# Scope and release boundaries

- One connection authority and durable transaction/lease journal
- Versioned topology, stable resource identity, operation and grant contracts
- Native QEMU and managed USB/IP backends with distinct release profiles

## Independent release qualification
Source adoption is profile-specific. Native first: protected QMP, actual guest HID and release, controller recovery and trusted guest enrollment. Managed: stable source identity, scoped journal, independently verified effective isolation and G4. Native does not depend on managed G4.

Support humans, automation and agents through stable CLI/API/schema, install/update/rollback instructions and typed errors. No new control plane or competing lease authority. Version contracts at the owning product.
