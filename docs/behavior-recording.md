# Behavior recording

From the first packet it ever sees, GarmWatch records how each
device *behaves* — not just that it talked, but how it answers.
For every Modbus server on the wire, a **response profile** grows:

- **The values it returns.** For each register (or coil) the device
  answers for: the smallest and largest values ever returned, the
  most recent one, and how many samples fed the range.
- **Its function mix.** How many answers it has given per Modbus
  function — reads of holding registers, reads of coils, write
  echoes, and so on.
- **Who polls it.** Every client observed asking it anything.
- **Its polling rhythm.** The typical gap between requests it
  receives — the plant's heartbeat, per device.

Clicking a device on the map shows its profile under its details:
"Behavior profile — 1,204 answers recorded, polled about every
250 ms… Registers seen: addr 100: 990–1010, last 1005 · …"

## Why record from day one

The profile is the **twin's feedstock**. When a bad actor is
quarantined into the fake plant ("clone this system"), the fake
stack should not answer with generic made-up numbers — a halfway
careful intruder notices those. It should answer with the *real*
device's values, in the real device's ranges, at the real device's
rhythm. That is only possible if the real behavior was recorded
before anyone needed it — profiles need accumulated time, which is
why recording was built early in the feature program even though
the twin is built last.

The profiles are also useful on their own: a device whose answers
suddenly change range, or that starts answering functions it never
used to, is a device worth a second look.

## How it works

A Modbus response does not repeat the address it answers — it
carries only values. So the recorder pairs each read response with
its request by the MBAP **transaction id** (the field exists for
exactly this), and only then files the values under the request's
start address. A response whose request was never seen (the sensor
started mid-conversation) still counts toward the function mix; it
just teaches no register values, because nobody can honestly say
which addresses they belong to.

Recording is **aggregate, not raw**: ranges, counts, and rhythms —
never a packet archive. Storage is bounded (at most 512 register
addresses per device are ranged) and flushed to SQLite in batches,
so a busy plant cannot turn the recorder into a write flood.
Profiles survive restarts, and **Clear stored data** wipes them
with everything else.

Everything here is passive observation of traffic already flowing
past the sensor. Recording changes nothing on the wire.
