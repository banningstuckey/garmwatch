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
2. **Held in quarantine now** — who ordered each hold and when.
3. **Ignores (vouches) and what happened after** — every Ignore
   with its attribution, followed forward: an actor that stayed
   quiet is a clean vouch; one that alerted afterwards is
   flagged with the count and the heaviest signal. This is the
   section that answers "who vouched for the machine that later
   misbehaved?"
4. **Operator actions** — the audit trail itself, oldest first.
5. **Alerts** — every alert in the window.

## What it is for

- **Compliance evidence:** a dated, attributed record of
  monitoring and of every human decision taken on it.
- **Investigation:** one document that shows the alerts *and*
  the operator context around them — including the drills.
- **An out-of-band anchor:** saving the PDF somewhere other
  than the sensor bounds what even a compromised sensor could
  rewrite about the past (see the record-security design in
  the project plan).

## Honest limits

- Identity is the OS user on the sensor — the app has no login
  system; if named accounts ever exist, they plug into the
  same stamp.
- The store is plain SQLite today; the hash-chained,
  tamper-evident journal is designed (record-security rules)
  but not yet implemented. Until then, the exported report is
  the anchor — generate and file them periodically.
