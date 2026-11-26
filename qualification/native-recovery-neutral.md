# Native recovery observation — narrow evidence primitive

Refs #7 and #13. Existing HELD recovery performs emergency QMP UP and returns before pin/receipt ingress. The v1 journal does not store original launch or lease scope and the normal DOWN/UP proof authority is volatile. Do not reconstruct its DOWN or accept a fresh enrollment as release.

The original runtimeproof package now has an independent-domain neutral observation envelope binding a fresh nonce, exact old lease scope, held journal byte digest and enrolled launch digest to the independently pinned key. Copies share one-shot consumption state. Success authenticates evidence only; it cannot clear HELD, make a Manager reclaimable or publish a frontend.

Next, persist a trusted exact launch/old-lease binding with the original durable write-ahead before input, qualify rollback and crash boundaries, and add an actual independently observed guest-neutral sensor. Under the retained owner, recheck protected peer and VM incarnation, current record hash and sequence, actual QMP release ACK and effective isolation immediately before the existing durable release transition. Old unbound records stay quarantined. No runtime changes in this PR. Targeted exact dependency subset race x10/vet PASS; full module and live recovery NOT_RUN.
