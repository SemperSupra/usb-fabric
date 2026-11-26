# Scoped first-A admission: executable safety requirements

Refs #11 and combined source #13. Actual source review: `blue.ScopedGenesisOwner` owns stable conflict locks, and `PrepareAdmission` writes scoped v2 intent at sequence 2. No current Manager constructor accepts v2; `heldledger.Store.Read` and legacy transition operations reject it. A direct swap for the old `blue.New` in the three-kernel broker would either remain denied or bypass the existing authority.

## Proposed next implementation (not implemented here)
1. Extend the original retained scoped owner, not a second broker or lock/grant service. Same live owner and exact current scope, operation, nonce, five independently observed domains and effective fences must authorize activation; persisted intent alone never reconstructs authority.
2. Preserve v2 scope and monotonic durable phase across attach, input and later release. No v1 conversion or clean admission window. Persist HELD before the physical input can occur.
3. Keep frontend fenced until activation succeeds; on loss of fences, failed or ambiguous write, crash, or identity mismatch, deny new access and keep journal. Retirement must exclude Manager operations before relinquishing retained OS locks.
4. Wire positive and negative real witness domains one at a time, preserving existing legacy three-kernel regression and B HELD/C refusal. Do not label synthetic observations as G4.

Run `python3 -B qualification/scoped_first_admission_model.py`. The model exhausts its finite reachable graph, verifies a nonvacuous first admission and four crash cutpoints, and rejects six unsafe transition mutations. It is a requirements oracle only; it does not prove actual Go concurrency, filesystem fsync, cryptographic witness truth, QEMU/USB/IP runtime, recovery or release. No workflow added. See exact evidence JSON.
