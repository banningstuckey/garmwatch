# Suspicion scores, Ignore, and Quarantine

Every actor on the network carries a **suspicion score** from 0 to
100 — green for a good actor, sliding through yellow and orange to
red for a bad one. It appears in the Assets table and at the top of
every device's detail, colored by band: green under 25, yellow to
50, orange to 75, red above.

The score is a ranking heuristic, not a probability and never a
black box. Clicking the actor shows the **why**: the exact factors
and points behind the number, computed entirely from the stored
event log over the last 24 hours:

- **Alerts about the actor**, weighted by what fired — a write from
  a non-HMI counts 40, a new-device note counts 8 — discounted to a
  quarter during a maintenance window, and decaying with age
  (half-life about six hours after the first hour).
- **A canary touch pins the score at 100.** Nothing legitimate
  talks to the canary; there is nothing to weigh against it.
- **Being newly seen** adds 8. New is not bad, but new is worth a
  look.
- **Quarantine holds the score at 90 or above** while the actor is
  held.

## Ignore — a judgment, not a mute

The **Ignore** button in the why-panel records a human judgment:
"this actor is known and expected." It does **not** stop GarmWatch
watching or recording the actor, and it does not silence future
alerts. What it does is factor into the equation: everything the
actor did *before* the Ignore counts at half weight. Anything it
does *after* counts at full weight — an actor who misbehaves after
being vouched for climbs again. A canary touch is never softened.

Every Ignore is an audit-log entry with who made it
(`kind:operator`). That is deliberate: an insider could otherwise
use Ignore to blind the system to an accomplice. The why-panel
shows the credit openly — "Ignored by banning — earlier signals
halved (−20)" — so the vouch itself is always visible to whoever
looks next.

## Quarantine — a human act

The **Quarantine** button (two clicks: the button arms, the second
click confirms) is an operator's order, and the AI never makes it.
On confirm, GarmWatch:

- marks the actor quarantined (Assets badge, map detail, score
  held at 90+),
- writes the order to the audit log with who made it,
- and produces the **action sheet**: a one-page hand-off naming the
  device, the evidence, what GarmWatch has and has *not* done, and
  the exact isolation steps for the operator's switch or firewall.

GarmWatch is a passive monitor: it does not touch the network, so
the physical move — shutting the switch port, moving the actor to
the quarantine VLAN, blocking it at the firewall — is a human step
on the plant's gear, following the sheet. Where a quarantine
environment exists (the canary today, the twin later), the actor
is held there until a human releases them.

**Release** is in the same panel while an actor is held. It is
logged too. Nothing about an actor's standing is ever changed by
the software alone, and every change a human makes leaves
fingerprints.
