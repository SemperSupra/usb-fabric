# CURRENT_TASK

Read [bootstrap issue #1](https://github.com/SemperSupra/usb-fabric/issues/1), AGENTS.md and [source adoption plan](docs/migration/source-adoption.json). State: destination preparation, no source import or authority transfer. Inventory exact candidate module paths and transitive source dependencies; review license/provenance and source-only extraction, excluding all inherited workflow definitions. Do not import entire experimental trees. Prepare independent native and managed source adoption PRs from approved inventory.

Source adoption is profile-specific. Native first: protected QMP, actual guest HID and release, controller recovery and trusted guest enrollment. Managed: stable source identity, scoped journal, independently verified effective isolation and G4. Native does not depend on managed G4.

No release, private source publication, paid execution or HIL.
