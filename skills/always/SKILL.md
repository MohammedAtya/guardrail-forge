---
name: always
description: Make Claude always do something as part of its work, enforced by a hook instead of memory. Creates an always-rule from one sentence ("/always rebuild the app and copy it to my desktop after code changes", "/always commit after every update", "/always run the tests before you commit", "/always update the PDF after every change we decide"), and controls existing ones with /always skip, pause, resume, list, remove. Use when the user types /always, or asks Claude to do something every time, after every change, or before another step.
argument-hint: "[skip|pause|resume|list|remove] [rule]  or  <what Claude should always do>"
---

# Always

An **always-rule** makes Claude do a task every time something happens: Claude cannot finish its reply, or cannot take the next step, until the task is done. It runs on the same engine as `/forge` (never-rules): one hook program, tested examples, backtest on past sessions, and the tamper guard.

`<engine>` is `<skill-dir>/../forge/scripts/forge.py`, where `<skill-dir>` is the base directory shown when this skill loads. `<guardrails>` is the installed scope: `<project>/.claude/guardrails/` or `~/.claude/guardrails/`. The rule format is in [`../forge/reference/rules.md`](../forge/reference/rules.md) under **Always-rules**.

## Pick the branch from the arguments

| Arguments | Do |
|---|---|
| none, `help` | Show the menu below and stop |
| `skip [id]`, `pause [id]`, `resume [id]` | Nothing to run. The hook reads the user's own command from the conversation and announces it at the end of this reply. Say in one line what will happen, then stop. Never run anything to imitate it. |
| `list` | `python3 <guardrails>/forge.py list --always` for each installed scope |
| `remove <id>` | `python3 <guardrails>/forge.py remove <id>`. The tamper guard asks the user to confirm; that is by design. |
| anything else | **Create** (below) |

Menu:

```
/always <what Claude should always do>   create an always-rule
/always skip [rule]      skip the task for the current changes (it comes back with the next change)
/always pause [rule]     off for this session
/always resume [rule]    back on
/always list             your always-rules and their last state
/always remove <rule>    delete one (asks you to confirm)
Plain words work too: "skip it this time", "pause that", "resume".
```

## Create

The user writes one sentence. You work out everything else, and the user only confirms a plain preview. Ask the user only about what they want, never about facts you can look up.

### 1. Make sure the hook program is current

Run `python3 <guardrails>/forge.py doctor` if `<guardrails>/forge.py` exists. If it is missing or doctor says it is outdated, say so and get the user's OK first, then install:

```bash
python3 <engine> install --scope project --project-dir <repo root>   # or: --scope user
```

This step is required: a hook program from before 3.0 misreads always-rules, and an order rule would block every matching call.

### 2. Work out the rule yourself

From the sentence, find four things. Read the project to get them: build scripts (`package.json`, `Makefile`, `electron-builder.yml`, CI files), the layout, and how the task was done before in past sessions (`python3 <engine> backtest` lists past tool calls, and the transcripts are in `~/.claude/projects/<project>/`).

- **Do**: the task, as exact steps, e.g. "run `make app`, then copy `release/App.exe` to `~/Desktop/`". If past sessions show a working variant (a broken script that was worked around), use the working one.
- **When** (`after`): what makes the task due. **Prefer file changes**: "after every change we decide" almost always means "after the files the result is made from change". Watch the task's **inputs** (source dirs, the document a PDF is built from), never its outputs (build folders, the result file, logs), or the rule triggers itself. Leave out files that do not feed the result (tests, notes) unless the user wants them. Ask "which file is X made from?" only if the project does not tell you.
  Use conversation triggers only when no file changes, e.g. "write a summary after each decision". In that case, use any of these:
  - the user's short approval right after Claude proposes or asks (`@user` with `replying_to`);
  - a `Decision:` line Claude writes (`@claude`);
  - an explicit marker the user types (`decided:`).

  Tell the user this trigger is weaker: it reads wording.
- **Done when** (`done_when`): how the hook checks the result, independent of how Claude got there. Prefer `{"newer": "<result file>"}`: the result is newer than the last change. This works for an exe, a PDF, or a generated client. Otherwise use a check command that takes under 20 seconds, e.g. `{"command": "test -z \"$(git status --porcelain)\""}` for "committed". With neither, the rule trusts that the `ran` command ran; say that this is weaker.
- **By**:
  - "after X, do Y" → the end of the reply (`event: Stop`).
  - "before X, do Y" → an order gate on X (`event: PreToolUse`, `decision: deny`).
  - "just remind" → `PostToolUse` nudge.
  - A task that takes more than about a minute (a build) gets `slow_minutes`: about twice its usual duration, taken from past sessions' timestamps or a timed run. Ask if you cannot tell. Claude must start it before the reply ends, run it in the background, and the result is checked once it should be done.

Not an always-rule:
- **A time or schedule** ("every day at 9", "every 30 minutes"): hooks run only while Claude works. Point the user to `/schedule` or `/loop`.
- **A ban** ("never X"): that is `/forge`.

### 3. Write and test it

Write the rule JSON to a scratch file outside `.claude/`. Follow the always-rule example in [`rules.md`](../forge/reference/rules.md):
- `ran` matches the usual command (it is also what past sessions are checked against).
- The `message` gives the exact steps, plus what not to do. For example, "copy only after the build succeeds; never delete the old copy first".
- Fixtures:
  - `bad`: a change with nothing done (`"done": false`), and a run whose result is missing (`"done": false`);
  - `good`: the usual way, and a workaround command (`"done": true`);
  - `near_miss`: a change outside the inputs, and for a slow task, a run still inside `slow_minutes`.

```bash
python3 <guardrails>/forge.py add /tmp/always-rule.json --dry-run
```

Fix the rule until it prints `GREEN`:
- `CONFLICT`: another rule blocks the task, or a fixture fires the wrong rule. Show the user both rules.
- `LOOP`: this task and another always-rule's task would trigger each other forever. Ask the user which one to keep, or narrow a trigger.

Label every backtest hit with the user as for `/forge`.

### 4. Show the preview and wait

Show only this, in plain words, and write nothing before the user says yes:

```
I'll make this always-rule:

  When:       code under src/ or electron/ changes
  Do:         build the app (make app) and copy App.exe to your Desktop
  Done when:  ~/Desktop/App.exe is newer than your last change
  By:         before Claude finishes its reply. The build takes ~8 min, so it runs in the background
              and you get a ✓ when it lands.

  Example:  Claude fixes src/form.ts → it must start the build before it can say "done"
  Not:      Claude edits tests/ or notes.md → nothing due
  History:  in your past sessions this would have been due 11 times; you asked for it by hand each time

Say yes, or tell me what to change. ("details" shows the technical rule.)
```

On "details", show the rule JSON and the full backtest output.

### 5. Install and report

```bash
python3 <guardrails>/forge.py add /tmp/always-rule.json
```

Then tell the user, in two or three lines:
- the rule is on;
- they will see "✓ always-rule <id>: done" when the task is really done;
- `/always skip`, `pause` and `remove` exist.

On a first install, the hook registration may need `/hooks` or a restart in an already-running session.

## How it behaves (tell the user when it matters)

- **Two attempts, then you.** If the task is not done when Claude tries to finish, Claude is held back to do it. That happens at most twice per batch of changes. After that it stops blocking: Claude tells the user what failed, and a one-line ⚠ reminder shows at every reply's end until it is done or skipped.
- **Only the user can skip or pause.** The hook reads only the user's own messages for that, and announces every skip, pause and resume. Claude's own words never switch a rule off.
- **No loops.** A task never re-triggers its own rule. Two always-rules that would trigger each other are refused when added.
- **While working only.** The hook checks while Claude works: at each reply's end, and when a background task finishes and Claude is called back. It does nothing while the session is idle.
