# Luna runbook

Use one short objective prompt per session. Read the session's `INPUT DOCS` and
the current session report before acting. Do not start later work to compensate
for a partial result.

## Before a session

1. Confirm the requested session number and objective.
2. Read its complete entry in `EXECUTION_PLAN.md` and all `INPUT DOCS`.
3. Inspect current repository/runtime evidence; preserve unrelated changes.
4. State the implementation boundary and do-not-touch list.
5. Do only that session. Stop at its `STOP CONDITION`.

## During a session

- Prefer stable library/D-Bus APIs; never add shell execution as a shortcut.
- Keep the UI unprivileged and preserve product/security invariants.
- Validate incrementally, including real DMS/Labwc interaction where required.
- Record self-detected issues with root cause, correction, and validation.
- If evidence invalidates the plan, stop the affected work and record the full
  deviation format below. Do not silently redesign.

## Required end-of-session report

```text
SESSION OBJECTIVE REVIEW

THIS SESSION WAS SUPPOSED TO:
...

RESULT:
PASS / PARTIAL / FAIL

NOT COMPLETED:
...

V0 PROGRESS

V0 SESSIONS COMPLETED:
X/10

V0 SESSIONS REMAINING:
X

REMAINING V0 SESSIONS:
- Session N: ...
- Session N+1: ...

POST-V0 MILESTONES:
- V1 posture monitor and DMS widget: NOT STARTED / ACTIVE / COMPLETE / DEFERRED
- Application-network backend prototype: NOT STARTED / ACTIVE / COMPLETE / DEFERRED
- Application-network integration: BLOCKED BY PROTOTYPE / NOT STARTED / ACTIVE / COMPLETE / DEFERRED
- USBGuard active control: NOT STARTED / ACTIVE / COMPLETE / DEFERRED
- Richer security activity: NOT STARTED / ACTIVE / COMPLETE / DEFERRED
- Sensitive Files: NOT STARTED / ACTIVE / COMPLETE / DEFERRED
- High-Risk/Travel Mode: NOT STARTED / ACTIVE / COMPLETE / DEFERRED
- Advanced application policy: BLOCKED / NOT STARTED / ACTIVE / COMPLETE / DEFERRED
- AI-mediated security: NOT STARTED / ACTIVE / COMPLETE / DEFERRED

NEXT SESSION:
...

PLAN DEVIATION:
NONE
```

If the plan changed, replace `NONE` with:

```text
PLAN DEVIATION:

HISTORICAL IDEA:
...

EVIDENCE:
...

BETTER DIRECTION:
...

IMPACT:
...
```

Only sessions whose acceptance and stop condition pass count as complete.
Post-V0 milestones never increment the V0 count.

