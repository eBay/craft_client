/*********************************************************************************
 * Modifications Copyright 2026 eBay Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once

#include <chrono>
#include <cstdint>
#include <stdexcept>

#include <liburing.h>

#include <sisl/async/cqe_state.hpp> // is_managed / decode_managed_user_data + complete_cqe_state (the reap contract)

namespace craft::test {

// A driver-owned io_uring + the reap loop a ublk queue runs in production: submit the SQEs the transport queued,
// wait a slice for a CQE, then drain every ready one -- completing each managed sisl::async::cqe_state so its
// suspended leg resumes. This IS the "driver drives the reaping" contract the async verb overloads document;
// the transport only ever queues SQEs. Mirrors ublkpp::MockUblksrv::poll and io_uring_scheduler::poll_once.
struct ring_driver {
    ::io_uring ring{};

    explicit ring_driver(unsigned entries) {
        if (::io_uring_queue_init(entries, &ring, 0) < 0) throw std::runtime_error("io_uring_queue_init failed");
    }
    ~ring_driver() { ::io_uring_queue_exit(&ring); }
    ring_driver(ring_driver const&) = delete;
    ring_driver& operator=(ring_driver const&) = delete;

    // One reap slice: flush queued SQEs + wait up to `slice` for a CQE (one syscall), then drain all that are
    // ready. Consume each CQE BEFORE resuming its leg, so a resumed leg's own peek sees the next one, never this.
    void pump(std::chrono::milliseconds slice) {
        __kernel_timespec ts{.tv_sec = slice.count() / 1000, .tv_nsec = (slice.count() % 1000) * 1'000'000LL};
        ::io_uring_cqe* cqe = nullptr;
        int const r = ::io_uring_submit_and_wait_timeout(&ring, &cqe, 1, &ts, nullptr);
        if (r < 0 || nullptr == cqe) return; // -ETIME / -EINTR: no completion this slice
        do {
            uint64_t const ud = cqe->user_data;
            int const res = cqe->res;
            ::io_uring_cqe_seen(&ring, cqe);
            if (sisl::async::is_managed_user_data(ud)) {
                if (auto* s = static_cast< sisl::async::cqe_state* >(sisl::async::decode_managed_user_data(ud))) {
                    sisl::async::complete_cqe_state(*s, res);
                }
            }
        } while (0 == ::io_uring_peek_cqe(&ring, &cqe) && nullptr != cqe);
    }

    // Pump until `pred()` holds, bounded so a hung leg fails the assertion instead of spinning forever.
    template < class Pred >
    bool drive_until(Pred pred, int max_slices = 8000) {
        for (int i = 0; i < max_slices; ++i) {
            if (pred()) return true;
            pump(std::chrono::milliseconds{2});
        }
        return pred();
    }

    // Keep reaping for `wall`, to drain any still-detached straggler legs (e.g. a slow replica's keep_alive a
    // read left running) so no ring SQE points at a live coroutine frame when the cluster is torn down.
    void drain_for(std::chrono::milliseconds wall) {
        auto const deadline = std::chrono::steady_clock::now() + wall;
        while (std::chrono::steady_clock::now() < deadline) {
            pump(std::chrono::milliseconds{2});
        }
    }
};

} // namespace craft::test
