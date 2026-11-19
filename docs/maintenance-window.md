# Maintenance window

Real plants have engineers. A controls engineer plugs a laptop into
the plant network, runs the programming software, and writes to
controllers — and every one of those actions looks exactly like the
opening moves of an attack. Without a maintenance window, the
operator's choice is bad either way: leave the alerts on and learn
to ignore them (alert fatigue — the real alerts drown), or let the
anomaly detector *learn* the engineer's laptop as normal (worse: a
real attacker using the same moves later looks normal too).

The maintenance window is the third option: say, in advance, "this
work is expected, for this long."

## What it does

Open one from the **Maintenance window** card in the Events view —
30 minutes, 1, 2, or 4 hours. While a window is open:

- **Learning stops.** Traffic during the window does not train the
  anomaly layer's baseline. The engineer's laptop never becomes
  "normal".
- **Anomaly alerts pause.** The layer does not score the window's
  traffic at all; the plant risk score stays where it was.
- **Rule alerts are marked, not hidden.** The hard rules still run
  and still record everything — an actual attack during a window is
  still in the log — but their alerts are stored with a
  "Maintenance window:" prefix, shown in the log in context, and
  kept out of the alert bell's badge count and the overview's
  latest-alert line.
- **It ends itself.** The window closes at its set time; ending it
  early is one click.

## The audit trail

Starting and ending a window are **operator actions**, and they are
recorded in the event log like everything else — with the OS user
account that did it:

- "Maintenance window started by banning — 60 minutes…"
- "Maintenance window ended early by banning."
- "Maintenance window ended — it ran its full 60 minutes (started
  by banning)."

They show under the log's **Important** filter and are searchable
with `kind:operator`. This is deliberate: a maintenance window is
exactly the cover a malicious insider would want ("of course the
PLC was written to at 2 a.m., we had a window open"), so the window
itself leaves fingerprints. Who opened it, when, and for how long
is always answerable from the log.

## What it is not

- It is not a mute button. Recording never stops; only the
  learning, the anomaly scoring, and the badge are window-aware.
- It does not whitelist the engineer's laptop permanently. When
  the window closes, the same actions alert again.
- It does not prove the work inside the window was legitimate. It
  proves someone *declared* it — and says who.
