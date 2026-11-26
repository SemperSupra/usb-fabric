# CURRENT_TASK — combined Fabric source candidate

Read [migration #3](https://github.com/SemperSupra/usb-fabric/issues/3), AGENTS.md and [source convergence manifest](docs/migration/source-convergence.json). This branch composes the two prior qualified source stacks, not their verdicts. Native #9 and managed #12 are both exact parents. Existing separate workcells retain evidence and RED; no new authority.

First run `bash qualification/verify-combined-offline.sh` in a clean full Git checkout with Go 1.23+ and Python 3. Verify all parent-relative blobs and modes, original three-kernel source map, both modules race/vet and oracle parse. This candidate has no active workflow. Historical recipes in qualification/origin are inert references; do not launch them as-is (branch/parent guards and timeouts differ). After offline PASS, separately admit bounded public runs for native and managed oracles on the same candidate SHA. No private projection, release or HIL.

Next P0: #7 authenticated recovery and #11 scoped first admission and independent managed witnesses. G4 NO_GO. Public licensing unresolved. Do not merge without reviewed qualification and owner gate.
