# A work-in-progress torrent library written in vanilla Rust


---

# uTP File-by-File Completion & Compliance Checklist (utp module)

## common.rs
- [x] Protocol constants and versions
- [x] Connection states and enums
- [x] Error types (`UtpError`)
- [x] Sequence number arithmetic, timestamp utilities
- [x] Global stats struct & helpers

**TODO:**
- [ ] Harden stats collection against SEU (triple redundancy in stats?).
- [ ] Integrate stack/heap usage macros for static analysis.
- [ ] Implement or document panic handler for `no_std` environments.
- [ ] Add documentation/comments for all public API/types.

---

## congestion.rs
- [x] LEDBAT-based congestion control
- [x] Triple-redundant (TMR) windowing logic
- [x] Window validation, slow start, and window reduction
- [x] All major window/RTT bookkeeping, base delay, and reset

**TODO:**
- [ ] Implement window scaling for high-BDP links.
- [ ] Reset base delay and RTT after major route/clock jumps.
- [ ] Add Nagle-like suppression (buffer small packets).
- [ ] Add property-based/unit testing for congestion edge cases.

---

## connection.rs
- [x] Connection ID, seq/ack management
- [x] Packet creation (SYN/ACK/DATA/FIN/RESET)
- [x] Incoming packet handler for state transitions and events

**TODO:**
- [ ] Fully implement four-way FIN handshake teardown logic.
- [ ] Ensure proper handling of simultaneous open/close.
- [ ] Enforce teardown timeouts and draining/final retransmits.
- [ ] Harden RESET packet handling and resource cleanup.
- [ ] Fuzz test all state transitions and error paths.

---

## packet.rs
- [x] uTP header struct, full packing/endianness
- [x] SACK extension encoding/decoding
- [x] Complete packet (header, SACK, payload)
- [x] Serialization and deserialization (with tests)

**TODO:**
- [ ] Add support for negotiating/handling additional uTP extensions (see BEP-29).
- [ ] Harden all extension parsing with AFL/libFuzzer coverage.
- [ ] Static assert all packing/size constraints.
- [ ] Tag all unsafe blocks (currently safe, but document for future modification).

---

## reliability.rs
- [x] RTT estimation, RTO, retransmit, max retransmits
- [x] Selective ACKs, duplicate ACK detection, loss recovery
- [x] OOO (out-of-order) buffering, cumulative ACK advancement
- [x] Triple redundancy for critical counters

**TODO:**
- [ ] Comprehensive test coverage for all edge cases.
- [ ] Ensure maximum retransmission and teardown triggers are robust.
- [ ] Add ECC/hamming for critical stored state if possible.
- [ ] Model check (e.g., with SEER) all loss and recovery state transitions.

---

## dispatcher.rs
- [x] Async dispatcher for UDP socket multiplexing
- [x] TMR notification events, connection mapping, event loop
- [x] Bounded execution for all tick/process loops
- [x] Notification/waker triple redundancy

**TODO:**
- [ ] Optimize notification/event dispatch for high-throughput environments.
- [ ] Harden all error paths & state transitions.
- [ ] Add async runtime integration tests (tokio/async-std).
- [ ] Document internal invariants (connection lifecycle).

---

## socket_manager.rs
- [x] Top-level API for dispatcher/socket management
- [x] Create/listen/shutdown logic, heartbeat, and TMR local addresses

**TODO:**
- [ ] Expose stack/heap usage bounds for certifiability.
- [ ] Validate panic/critical error handling in all methods.
- [ ] Add async cancellation/backpressure handling.
- [ ] Add support for mission/flight config hooks.

---

## socket.rs
- [x] UtpSocket main object, packet send/receive logic

**TODO:**
- [ ] Ensure full error propagation from lower layers.
- [ ] Harden all connection lifecycle stages (esp. close/abort).
- [ ] Integrate, as needed, with dispatcher for async readiness and event notification.
- [ ] Provide majority-voted control paths where state is critical.

---

## stream.rs
- [x] AsyncRead/AsyncWrite interface stubs

**TODO:**
- [ ] Fully implement `AsyncRead`/`AsyncWrite` (with proper waker use, backpressure, zero-copy).
- [ ] Integrate with dispatcher notifiers.
- [ ] Harden read/write close semantics.
- [ ] Property-based/interop test against reference (libutp).

---

## mod.rs
- [x] Module declarations, re-exports for crate API, placeholder `initialize`

**TODO:**
- [ ] Add global documentation for all public APIs.
- [ ] Expose logging/debug features for mission flight controls.
- [ ] Register/initialize with static analysis/cert toolchains (e.g., stack usage, memory bounds).
- [ ] Guard all initialization with stack/heap assertions as per JPL RLOC-4.

---

## New/Recommended Files

- **utp/fuzz.rs**  
  For property-based/fuzz testing of packet parsing, state transitions, etc.

- **utp/extensions.rs**  
  For optional protocol extension parsing/negotiation beyond SACK.

- **utp/no_std_panic.rs**  
  Custom panic handler for radiation-hardened `no_std` targets.

- **utp/verification.rs**  
  Proof artifacts, KLEE/Coq/SEER harnesses, and static analysis stubs.

- **utp/logger.rs**  
  Flight/safety-compliant logging and diagnostics.

---

## Testing & Verification (all modules)
- [ ] Add comprehensive integration tests (tokio/async-std, dispatcher/client/server).
- [ ] Add interop tests with a reference implementation (libutp, at least basic connect/send/close).
- [ ] Property-based/fuzz test: packet.rs, reliability.rs, connection.rs.
- [ ] Static analysis: all code (`-Z emit-stack-sizes`), generate/verify stack usage report.
- [ ] Add (or document) KLEE/SEER model checking state machine for critical path.

---

## Summary Table

| File/Module          | Core Features Complete | Major TODOs Remaining                                                                |
|----------------------|-----------------------|--------------------------------------------------------------------------------------|
| common.rs            | Yes                   | Cert docs, panic handling, stat hardening                                            |
| congestion.rs        | Yes                   | Window scaling, Nagle, reset on route drift                                          |
| connection.rs        | Mostly                | Four-way close, simultaneous open, teardown, RESET robustness                        |
| packet.rs            | Yes                   | More extensions, heavy parsing fuzzing                                               |
| reliability.rs       | Yes                   | More ECC, model-check edge cases                                                     |
| dispatcher.rs        | Yes                   | Async runtime interop, perf tuning, error path hardening                             |
| socket_manager.rs    | Yes                   | Stack/heap bounds, panic/critical error coverage                                     |
| socket.rs            | Yes                   | Error propagation, control path TMR                                                  |
| stream.rs            | Partial               | Full AsyncRead/Write, dispatcher notifier connection                                 |
| mod.rs               | Yes                   | Global docs, logging hooks, stack/heap usage guards                                  |
| **fuzz.rs**          | (add)                 | Proptest/afl harnesses for all serialization/mutation                                |
| **extensions.rs**    | (add)                 | Option/ext support                                                                   |
| **no_std_panic.rs**  | (add)                 | Custom panic for flight/no_std                                                       |
| **verification.rs**  | (add)                 | Model check artifacts, static/proof integration                                      |
| **logger.rs**        | (add)                 | Mission/safety logging, diagnostics                                                  |

---

## Next Actions

- **Triage TODOs per file above according to mission priorities.**
- **Add new files/modules as noted for full RLOC and JPL compliance.**
- **Request code templates or JPL-compliant patterns for any specific gap, and I’ll provide them.**

---