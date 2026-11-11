# CRAFT resync

The resync design lives in HomeBlocks: [`docs/craft/resync.md`](https://github.com/eBay/HomeBlocks/blob/dev/v6.x/docs/craft/resync.md).
Resync is driven by the CRAFT BM side; this package (UBD's CRAFT client) does not drive it.

What the design asks of this repo (PR F there):

- **Failed writes are resolved at the next login, not during the session.** On a sub-quorum write the client
  reports the error, pins its frontier `F` below the slot, and keeps serving overlapping reads as of just before
  it. It no longer calls `request_resolution`, and the `resolve` op (13/14) is retired.
- **The transport must keep "never delivered" true.** `craft_async_conn` drops the connection on any send failure,
  so a half-sent frame can never be followed by the next message (D17 in the design's Appendix A).
- **Peer-plane codec v2** (`include/craft/peer.hpp`): range-based, byte-bounded `fetch_data` with continuation and
  a `reclaimed_below` status, plus term and partition fields on peer requests (PR E).
