# Daily triage

An operator should not have to read hundreds of log lines to learn
what needs their eyes. The **Daily triage** card (Events view,
above the log) reads the last 24 hours and ranks it into a short
list, in plain English:

1. **Canary touches** — always first. There is no innocent version
   of this item.
2. **Whoever is in quarantine** — they are waiting on a human
   decision, and there is no clock on a quarantine.
3. **The highest suspicion scores** (25% and up, top three), each
   with its top reason attached.
4. **Ignores issued** — who vouched for whom. A vouch is
   investigation data, and the day it happens is the day to see it.
5. **Maintenance windows opened** and **new devices seen**, when
   there is room on the list.

Under the list, the raw counts: events, alerts, canary touches,
new devices, operator actions.

On a quiet day the list has exactly one item — "Nothing needs your
eyes" — because a triage that cries wolf on quiet days trains the
operator to skip it on loud ones.

## The list is deterministic

The triage is computed from the stored event log, the same source
the suspicion scores read. The same day always produces the same
list, and every item on it can be traced to the log entries behind
it. Nothing about the ranking is learned, guessed, or generated.

## "Explain today" — the analyst, pointed at the whole day

The optional local AI analyst (Ollama, on this machine only) can
narrate the triage: press **Explain today** and it writes a brief
in three sections — *The day in brief / Check first / Can probably
wait* — under the same house rules as its incident briefs: facts
only, plain English, never claim a confirmed attack, and never
instruct a response. It may mention that quarantining is the
operator's option; the decision stays human, as always.

The brief is recorded in the log as an analyst note, so the day's
narration is itself part of the record. GarmWatch works fully
without the analyst — the ranked list is the feature; the prose is
a convenience.
