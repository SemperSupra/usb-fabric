# CURRENT_TASK — combined P0 durable prerequisites

Read AGENTS.md, [migration #3](https://github.com/SemperSupra/usb-fabric/issues/3), [scoped first-A #11](https://github.com/SemperSupra/usb-fabric/issues/11), [native recovery #7](https://github.com/SemperSupra/usb-fabric/issues/7), and the [P0 convergence manifest](docs/migration/p0-prerequisite-convergence.json).

Combined source candidate stacks on the exact #13 qualified baseline and retains both independently source-qualified #16 and #18 heads. It contains the scoped same-owner first-input HELD seal and native identity-bound HELD journal plus recovery proof. No runtime activation or grant change; baseline oracles must not be interpreted as new v2/v3 runtime proof.

Qualification: in a full clean exact checkout run `python3 -B qualification/verify-p0-convergence.py`, `python3 -B qualification/verify-three-kernel-adoption.py`, the scoped finite model, both Go modules race/vet with offline env, and targeted new group reps. No active workflow; separately admit only bounded public workcells.

Next: protected live launch pin and actual guest evdev-neutral observation; original retained scoped Manager activation with fence-loss supervision; actual independent witness domains, VHCI crash/restart and G4. No grant or release pending all gates. Retain source parents and RED. Do not modify #13 baseline or duplicate authority.
