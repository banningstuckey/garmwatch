# Audit evidence — one click over the universal audit trail

The Audit evidence card (Events view) builds a printable report
from everything GarmWatch has recorded: the packet an auditor
(NERC CIP, IEC 62443), an insurer, or an investigator asks for
after something happens.

## The universal audit trail

GarmWatch records an **operator action** for every touch — and
every attempted touch that takes effect — in both directions:

- **Network actors:** alerts, writes, discoveries, connection
  attempts and malformed traffic are events in their own right;
  a canary touch is an alert by definition.
- **Operators:** simulation / replay / capture start and stop,
  canary start and stop, scenario runs (marked as drill traffic,
  so an investigator never mistakes a drill for an intrusion),
  maintenance windows, Ignore / Quarantine / Release, placement
  confirmations, analyst-model changes, and clearing the stored
  data.

Every operator record carries who did it (the OS user) and when.
Clearing the data is itself audited: the clear's record is
written *after* the wipe, as the first entry of the fresh
trail — a clear cannot erase its own record.

**Meta-audit:** pulling a report is recorded too, *before* the
report is built — so the report contains the record of its own
generation, and every view of the trail leaves fingerprints in
the trail. The logs are for investigation, and using them for
anything else is itself visible.

## The report

Pick a window (24 hours / 7 days / 30 days / all stored
history) and click **Generate report** to read it in the app —
it follows your theme, so it stays readable on screen. For
paper or a file, click **Open / save as file**: the report is
written as a standalone HTML page in your Downloads folder and
opened in your browser, where Print / Save-as-PDF works
properly. (The app's webview cannot print on macOS — that is
why the file route exists.) **Clear** empties the on-screen
report. Sections:

1. **Header** — when it was generated, by whom, the window, and
   the counts (events, alerts, operator actions, canary
   touches, new devices).
2. **Record integrity** — the hash chain's verdict over the
   whole stored log (see below), with the current chain head
   fingerprint. This section frames everything after it.
3. **Held in quarantine now** — who ordered each hold and when.
4. **Ignores (vouches) and what happened after** — every Ignore
   with its attribution, followed forward: an actor that stayed
   quiet is a clean vouch; one that alerted afterwards is
   flagged with the count and the heaviest signal. This is the
   section that answers "who vouched for the machine that later
   misbehaved?"
5. **Operator actions** — the audit trail itself, oldest first.
6. **Alerts** — every alert in the window.

## What it is for

- **Compliance evidence:** a dated, attributed record of
  monitoring and of every human decision taken on it.
- **Investigation:** one document that shows the alerts *and*
  the operator context around them — including the drills.
- **An out-of-band anchor:** saving the PDF somewhere other
  than the sensor bounds what even a compromised sensor could
  rewrite about the past (see the record-security design in
  the project plan).

## Record integrity — the hash chain

Every record in the event log is hash-chained (since v0.3.2):
each row carries the fingerprint of the record before it plus
its own, so editing, deleting, or reordering history breaks
the chain at exactly the point of tampering. Every report opens
with a **Record integrity** section stating the result of
walking the whole stored log — intact (with the current chain
head fingerprint), broken (with the record it broke at), or
unverifiable — before anything else in the report is read.

The chain is deliberately specified so anyone can check it
without GarmWatch:

- Algorithm: SHA-256, lowercase hex.
- A record's fingerprint is the SHA-256 of these fields joined
  by newlines, in this order: the predecessor's fingerprint,
  the record id, the Unix timestamp (seconds), the kind tag,
  the source IP (empty when none), the destination IP (empty
  when none), the summary text.
- The first chained record's predecessor is the fixed marker
  `garmwatch-audit-chain-v1:genesis`.
- Records written before the chain existed carry no
  fingerprint. Reports count them openly as pre-chain records;
  they are never silently treated as verified.
- Clearing stored data restarts the chain from the genesis
  marker, and — as before — the clear itself is the first
  record of the fresh trail. What a clear erases can still be
  bounded by any report filed before it: that is what the
  anchor is for.

File reports periodically. A report's chain head pins the
whole history up to that moment; a later report that verifies
over the same records proves none of them changed in between.

## Honest limits

- Identity is the OS user on the sensor — the app has no login
  system; if named accounts ever exist, they plug into the
  same stamp.
- The chain proves the log was not altered *after* a record
  was written. It cannot prove a record was true when written,
  and an attacker who owns the sensor machine outright can
  recompute a whole chain from scratch — the defence against
  that is the filed report: a recomputed chain cannot reproduce
  a head fingerprint that was already filed somewhere else.
