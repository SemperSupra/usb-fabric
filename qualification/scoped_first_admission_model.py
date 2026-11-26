#!/usr/bin/env python3
"""Finite abstraction of required scoped-v2 first-admission safety, not runtime code.

Existing v2 PrepareAdmission is an intent, not a grant. This model proposes a
same-owner activation contract. Each of the five witness bits represents a
positively observed independent, correctly scoped domain; signatures, actual
kernel/guest evidence, OS locks and fsync implementation are outside this model.
There is deliberately no recovery authorization or later A-to-B handoff here.
"""
from collections import deque
from dataclasses import dataclass, replace

MISSING, GENESIS, INTENT, HELD = range(4)
ALL = (1 << 5) - 1
DOMAINS = ("host-actuator", "usbip-exporter", "linux-vhci",
           "network-effective-deny", "guest-input-release")


@dataclass(frozen=True)
class State:
    journal: int = MISSING
    version: int = 2
    owner: bool = False
    fences: bool = False
    witnesses: int = 0
    prepared_here: bool = False
    proof_mask: int = 0
    visible: bool = False
    reserved: bool = False
    attached: bool = False
    physical_down: bool = False


def violations(s):
    if s.version != 2:
        return "NO_V1_DOWNGRADE"
    if s.journal in (INTENT, HELD) and s.proof_mask != ALL:
        return "ALL_FIVE_WITNESSES_BEFORE_INTENT"
    if s.visible and not (s.owner and s.fences and s.prepared_here
                          and s.journal in (INTENT, HELD)):
        return "NO_PUBLICATION_WITHOUT_SAME_LIVE_OWNER_AND_FENCES"
    if s.reserved and not s.visible:
        return "NO_LEASE_WITHOUT_PUBLICATION"
    if s.attached and not s.reserved:
        return "NO_ATTACHMENT_WITHOUT_LEASE"
    if s.physical_down and s.journal != HELD:
        return "DURABLE_HELD_BEFORE_PHYSICAL_INPUT"
    return None


def transitions(s, mutant=""):
    """All admitted steps; missing steps are denied, with state unchanged."""
    if not s.owner:
        yield "acquire-stable-locks", replace(s, owner=True)
    if s.owner and s.journal == MISSING:
        yield "fsync-v2-genesis-held", replace(s, journal=GENESIS)
    if s.owner and not s.fences:
        yield "establish-old-access-fences", replace(s, fences=True)
    if s.owner and s.fences and s.journal == GENESIS:
        for i, domain in enumerate(DOMAINS):
            if not (s.witnesses & (1 << i)):
                yield "observe:" + domain, replace(s, witnesses=s.witnesses | (1 << i))
        if s.witnesses == ALL or mutant == "skip-witness":
            # A failed/ambiguous write is never an activation. The crash
            # transition below covers either persistent pre/post-fsync cut.
            yield "fsync-v2-intent", replace(s, journal=INTENT,
                    prepared_here=True, proof_mask=s.witnesses)
    if (s.owner and s.fences and s.journal == INTENT and not s.visible
            and (s.prepared_here or mutant == "replay-intent")):
        yield "activate-same-owner", replace(s, visible=True,
                    version=1 if mutant == "downgrade" else s.version)
    if s.visible and not s.reserved:
        yield "reserve-first-lease", replace(s, reserved=True)
    if s.reserved and not s.attached:
        yield "attach-first-lease", replace(s, attached=True)
    if s.attached and s.journal == INTENT:
        yield "fsync-v2-held-before-input", replace(s, journal=HELD)
    if s.attached and (s.journal == HELD or mutant == "input-before-fsync"):
        yield "emit-physical-down", replace(s, physical_down=True)
    if s.owner and s.visible and not s.reserved:
        yield "retire-manager-before-unlock", replace(s, visible=False, prepared_here=False)
    if s.owner and (not s.visible and not s.reserved):
        yield "close-owner", replace(s, owner=False, fences=False,
                    prepared_here=False, witnesses=0)
    if mutant == "unlock-before-retire" and s.owner and s.visible:
        yield "unsafe-unlock", replace(s, owner=False)
    if s.fences:
        # Unexpected loss quarantines; re-establishing fences cannot replay
        # an already prepared operation or resurrect its earlier observations.
        yield "lose-effective-fence", replace(s, fences=False, witnesses=0,
                    prepared_here=False, visible=s.visible if mutant == "ignore-fence-loss" else False,
                    reserved=False, attached=False)
    if s.owner or s.visible or s.prepared_here or s.fences or s.witnesses:
        yield "crash-volatile-owner", replace(s, owner=False, fences=False, witnesses=0,
                    prepared_here=False, visible=False, reserved=False, attached=False)


def explore(mutant=""):
    initial = State()
    queue = deque([initial])
    parent = {initial: (None, "")}
    edges = 0
    while queue:
        s = queue.popleft()
        reason = violations(s)
        if reason:
            trace = []
            t = s
            while parent[t][0] is not None:
                prev, event = parent[t]
                trace.append(event)
                t = prev
            return len(parent), edges, reason, list(reversed(trace))
        for event, t in transitions(s, mutant):
            edges += 1
            if t not in parent:
                parent[t] = (s, event)
                queue.append(t)
    return len(parent), edges, None, []


def run_trace(events, s=State()):
    for event in events:
        choices = dict(transitions(s))
        if event not in choices:
            raise SystemExit(f"TRACE_RED unexpected denial: {event}")
        s = choices[event]
        if violations(s):
            raise SystemExit(f"TRACE_RED {violations(s)} after {event}")
    return s


def cutpoint_checks():
    prefix = ["acquire-stable-locks", "fsync-v2-genesis-held",
              "establish-old-access-fences"] + ["observe:" + d for d in DOMAINS]
    intent = run_trace(prefix + ["fsync-v2-intent"])
    admitted = run_trace(["activate-same-owner", "reserve-first-lease",
                          "attach-first-lease"], intent)
    held = run_trace(["fsync-v2-held-before-input"], admitted)
    down = run_trace(["emit-physical-down"], held)
    if not down.physical_down:
        raise SystemExit("TRACE_RED positive path vacuous")
    for state in (intent, admitted, held, down):
        reopened = run_trace(["crash-volatile-owner", "acquire-stable-locks",
                              "establish-old-access-fences"], state)
        if reopened.visible or reopened.reserved or reopened.journal != state.journal:
            raise SystemExit("TRACE_RED crash reopened authority or changed journal")
        if "activate-same-owner" in dict(transitions(reopened)):
            raise SystemExit("TRACE_RED persisted intent replay")
    print("POSITIVE_AND_CRASH_CUTPOINTS=PASS cuts=4")


def main():
    cutpoint_checks()
    states, edges, reason, trace = explore()
    if reason:
        raise SystemExit(f"MODEL_RED {reason} {trace}")
    print(f"SCOPED_FIRST_ADMISSION_MODEL=PASS states={states} edges={edges} fixpoint=true")
    expected = {
        "skip-witness": "ALL_FIVE_WITNESSES_BEFORE_INTENT",
        "replay-intent": "NO_PUBLICATION_WITHOUT_SAME_LIVE_OWNER_AND_FENCES",
        "downgrade": "NO_V1_DOWNGRADE",
        "input-before-fsync": "DURABLE_HELD_BEFORE_PHYSICAL_INPUT",
        "unlock-before-retire": "NO_PUBLICATION_WITHOUT_SAME_LIVE_OWNER_AND_FENCES",
        "ignore-fence-loss": "NO_PUBLICATION_WITHOUT_SAME_LIVE_OWNER_AND_FENCES",
    }
    for mutant, want in expected.items():
        _, _, got, trace = explore(mutant)
        if got != want:
            raise SystemExit(f"MUTANT_RED {mutant}: expected {want}, got {got}")
        print(f"MUTANT_REJECTED={mutant} invariant={got} trace={' -> '.join(trace)}")
    print("MUTATION_ORACLE=PASS mutants=6 actual_runtime=NOT_TESTED")


if __name__ == "__main__":
    main()
