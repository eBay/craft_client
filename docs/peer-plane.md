# The peer plane

CRAFT has **two planes**. The client plane carries UBD's IO to the members. The peer plane is replica to replica:
the leader polls the members, and a member that is behind fetches the slots it lacks from one that holds them.

|  | **Client plane** | **Peer plane** |
|---|---|---|
| Interface | `craft_replica` (`src/craft_replica.hpp`) | `craft_peer` (`include/craft/peer.hpp`) |
| Caller | `craft_client` -- the IO client | **a replica**: the leader's poll, a member's catch-up |
| Callee | a member | another member (a *holder*) |
| Trigger | user IO | login, committing `SyncRSCommitLSN`, catch-up |
| Verbs | `login` `logout` `write` `read` `keep_alive` `request_resolution` | `get_rs_commit_lsn` `fetch_data` |
| Wire opcodes | `wire::op` **1-14** | **17-20** (wire v2, see `docs/wire.md`) |
| Near half | `CraftTcpReplica` | `CraftTcpPeer` (reference) |
| Far half | `craft_tcp_server` (reference) / block_mgr2 `CraftSession` | `craft_tcp_server` (reference) / not built in block_mgr2 yet (S9) |

`craft_client` never calls a peer verb; ublkpp never links any of it. The peer plane lives in this repo because the
protocol is defined here: one opcode space and one framing for both planes, and the reference model exercises both.

## What wire v2 gives a peer transport

- **Bounded, resumable fetch.** Ranges instead of one i64 per dLSN, a byte bound per reply, and `next` to continue,
  so a member down for minutes can catch up (each reply fits `max_tx`). `peer::fetch_all` is the caller's loop.
- **Fences.** Partition id and RAFT term on every request; the responder's session term on every reply, and the
  session term each slot was written at.
- **Reclaimed is not absent.** `reclaimed_below` / status `reclaimed`, so a reclaimed slot is never miscounted as
  evidence that nobody holds it.
- **One codec.** `craft::peer::encode_*` / `decode_*` produce exactly the TCP payload, so a BM can carry the same
  messages over its own RPC channel.

## What is still missing

1. **The BM side (S9).** block_mgr2's `CraftSession` closes on peer ops, and nothing calls HomeBlocks'
   `set_peer_fetcher`. A peer server and an outbound peer client have to be built there, on this codec. Open:
   what credential one BM presents to another.
2. **`probe_slots`** (HomeBlocks resync.md §4.2's metadata probe) is not defined yet.
3. **The reference model** reports `journal_floor = -1` and accepts any `leader_raft_term`: it never reclaims from
   below and has no RAFT term. The fence and reclaim semantics are HomeBlocks'.

---

# Variant: server-side fan-out (parked, not built)

A recurring question: *can the replication fan-out move off the client and onto a fast server-side fabric?* It can,
and the client model survives almost intact. This section records how, and what it costs, so the idea can be picked
up (or answered) without re-deriving it.

**The shape.** The client keeps sessions with all N members and keeps assigning dLSNs, but it **unicasts** a write to
a single **ingress** member. The ingress appends it, acks, and forwards it to the other members over a fast
server-side fabric. The client learns that the other members have it from the watermark on their **keep_alive**
replies, and acks the write to the application once a quorum of members hold it. Reads are untouched: they are
already unicast to one eligible member and routed by the same map.

**The win.** The client sends the payload **once instead of N times**, so a 3-way set costs 1x client write
bandwidth instead of 3x. Reads already cost 1x, so the client link stops paying the replication tax entirely and the
fan-out moves to a backend fabric where bandwidth is cheap. On a bandwidth-bound client NIC this is roughly a 3x
write-throughput increase, and it is the whole reason to consider the variant.

## What does not change

- **dLSN assignment stays client-side.** The ingress orders nothing; it forwards a slot the client already numbered.
  CRAFT's core invariant is untouched.
- **Reads.** Unicast to one eligible member, routed by the two-tier map. Zero change.
- **The commit frontier, the piggybacked commit, and the reclaim floor** (`all_committed_lsn = min` across members).
- **The keep_alive channel already exists.** `drive_keepalives(exclude_idx)` already fires a keep_alive at every
  member that did NOT get the current IO. In this variant that is precisely the set whose watermark the client is
  waiting on. The polling machinery is already built.
- **`read_route_map`'s holder bitmask.** Already a bitmask; it just gets filled from a watermark rather than from N
  per-leg acks.

## The trap: last_append_lsn is NOT an ack

The tempting move is to let the client count member B as a holder of dLSN `d` once B's keep_alive reports
`last_append_lsn >= d`. **Do not.** `last_append_lsn` is the HIGHEST dLSN the replica has appended, not a promise
that it has everything below it. The model says so explicitly: `missing_count` counts Missing slots in
`(commit_lsn, last_append_lsn]`, so **holes live below last_append_lsn by construction**.

With a single ingress and an order-preserving forward channel, B's appends happen to be dense and the shortcut looks
correct. It breaks at **ingress failover**, which is the case the replica set exists for:

> A is the ingress. It has forwarded `d..d+4` to B, but dies before C receives `d+1..d+4`. The client fails over to
> B as ingress; B forwards from `d+5`. C appends `d+5`, so C's `last_append_lsn` jumps to `d+5` **while it is
> Missing `d+1..d+4`**. C's next keep_alive reports `d+5`, the client counts C as a holder of `d+2`, acks it at
> quorum, and sets C's holder bit. A later read of `d+2` is then routed to C, which serves the older block.

That is silent wrong data, from a watermark that was never a contiguity proof.

## The fix: a dense receive watermark

Report a third watermark: the highest dLSN with **no Missing slot at or below it** (first-Missing minus one). Call it
`appended_upto`.

- **It is free.** The replica already tracks its Missing set; that set is exactly what `apply_up_to()` stalls on.
- **It is not `commit_lsn`.** `commit_lsn` is the contiguous *applied* prefix, and it only advances when the client
  stamps a commit, which the client can only do once it has quorum. Circular: `commit_lsn` cannot be the ack,
  because the ack is what produces it. `appended_upto` is the contiguous *received* prefix and depends on nothing
  the client does.
- **It is self-certifying.** Correct however the writes arrived: across failover, reconnect, and retransmit gaps.
  It answers exactly the question the client is asking ("is it safe to read `d` from here?") unconditionally.
- **It is cumulative.** One keep_alive reply carrying `appended_upto = 5000` acks writes `1..5000` at that member in
  a single message. Today every write costs an ack from every member. This is a real amortization win, not just a
  workaround.

The write then completes like this, with the durability contract (ack at quorum) preserved:

```
client -> A       write(d)                   A appends, acks           holder #1 (direct)
A -> B, C         forward(client_hdr, d)     over the fabric
client -> B, C    keep_alive                 reply: appended_upto >= d  holder #2 (cumulative)
                                             -> quorum -> ack to the application
```

## What it costs

1. **The peer plane stops being a cold path and becomes THE data path.** Today it is resync-only. Here every write
   crosses it, so it must be as fast as the client wire, and the forward **must carry the client's `client_hdr`** --
   the `term` above all, because B and C still have to fence a deposed client's writes. A forward that skips
   term-fencing breaks the single-writer guarantee. This is the real cost of the variant, and it is why it is parked
   behind the rest of this document.
2. **The "provably Empty" fast path is lost.** Today the client sees each member's own answer and distinguishes ack
   / deterministic reject / timeout; when every member deterministically rejects, the slot is *provably Empty*, a
   resolved no-op. With only the ingress answering directly, the client cannot observe that, so a failed write must
   go through a resolution round instead. RESOLVE becomes more important in this variant, not less.
3. **Write latency grows by a keep_alive round** (ingress ack, then the keep_alive that carries `appended_upto` past
   `d`). At depth this is a latency tax, not a throughput one, since the evidence for `d` lands while `d+1..d+k` are
   in flight. If that tax is unacceptable, the alternative is for the **ingress to wait for the fabric quorum and
   return a holder bitmask in its reply**: one client round-trip, contract preserved, and the client's
   `record_completion(dlsn, idx, acked)` simply becomes `record_holders(dlsn, mask)` with the route map unchanged.
