---
name: forge
description: Forge a user's correction into an enforced never-rule (hook, permission deny, or stop gate) proven by fixtures, instead of a CLAUDE.md line. Use when the user types /forge, corrects a repeated mistake ("don't do that again", "never X", "stop doing Z"), or asks to audit, list, or remove guardrails. For "always do X after/before Y", use the /always skill.
argument-hint: "[harvest|audit|list|doctor|remove <id>]  or  <what Claude should never do>"
---

# Forge

Turn a **correction** into a **guardrail**: the strongest cheap enforcement that will not misfire, proven **red/green** by fixtures before it is installed, and logged to a **ledger** every time it fires.

A guardrail works in one of two directions:
- **Never-rule** (this skill): "never X", "stop doing X". Claude is blocked, asked about, or nudged when it tries X.
- **Always-rule** (the `/always` skill, `<skill-dir>/../always/SKILL.md`): "after X, always do Y", "before X, do Y". Claude cannot finish its reply, or take the next step, until Y is really done. When a correction is really a standing task ("you forgot to rebuild again"), follow that skill instead; it uses the same engine.

`<skill-dir>` below is the base directory shown when this skill loads. `<guardrails>` is the installed scope: `<project>/.claude/guardrails/` or `~/.claude/guardrails/`.

Pick the branch:
- A correction to enforce → **Forge** (below).
- "harvest" / "what do I keep correcting" → **Harvest**.
- "audit" / "which guardrails are useless" → **Audit**.
- "list" / "remove" / "undo" / "doctor" → **Manage**.

**The ratchet.** Tightening is free; loosening belongs to the user. Change guardrails only through `forge.py add` and `forge.py remove`. The dispatcher's built-in tamper guard **denies** direct edits, moves, or deletes of the guardrail files and anything that sets `disableAllHooks`, and **asks** the user before `forge.py remove`, before edits to any Claude Code `settings*.json`, and before git operations that would discard uncommitted guardrail files. To change a rule, remove it and add the new version. When the guard fires, it is working as designed: tell the user, and offer the `! python3 <guardrails>/forge.py remove <id>` command they can run themselves.

## Forge

### 1. Pin the rule

Turn the correction into one precise, testable rule: which tool call, which pattern, what Claude should do instead. When "that" in "don't do that" is unclear, ask what it refers to.

Then decide, using [`reference/ladder.md`](reference/ladder.md):
- **Class**: safety, convention, or style.
- **Rung**: the highest one whose detector will not fire on legitimate work.
- **Scope**: facts about this repo → project; the user's personal habits → user. Ask when it could be either.
- **Fixtures**: at least one bad call, one good call, and one **near-miss** (looks like the bad call, must pass).
- **Prompt budget**: an `ask` rung costs the user a prompt every time. Prefer deny-with-reason unless the user wants to decide case by case.
- **Sandbox lock** (path rules only): offer it when scripts or build tools could write the protected path. See **Sandbox lock** below.

Write the draft to a scratch file outside `.claude/` and **backtest** it against this project's real history:

```bash
python3 <skill-dir>/scripts/forge.py backtest /tmp/rule.json --project-dir <repo root>
```

It replays the draft over two sets and reports both:
- **Project history**: every tool call from past sessions, with an **evidence** label for how many of them were in the rule's area: `NONE`, `LOW` (< 20) or `OK`. With `NONE`/`LOW`, history cannot vouch for the rule; say so plainly and never call it "no false positives".
- **Day-one set**: the project's own `package.json` scripts, Makefile targets and recipes, CI `run:` steps, a sample of its tracked files, and common developer work in 8 domains. It works on a fresh clone and covers areas the history never touched.

**Label every hit with the user.** A real case of the mistake becomes a `bad` fixture; legitimate work means the rule is too broad, so narrow it (often with `unless`), add that call as a `near_miss` fixture, and backtest again. `backtest ... --fixtures` prints every hit as ready-to-paste fixture JSON. Present only a draft whose remaining hits are all labeled.

Present it in this shape and wait:

```
Rule:       Block Edit/Write on any file under src/generated/
Class:      convention      Rung: PreToolUse deny (Claude gets the reason and self-corrects)
Scope:      project (.claude/, committed, team inherits it)
Blocks:     Edit src/generated/api.ts
Allows:     Edit src/api/client.ts
Near-miss:  Edit src/generated_docs/README.md  (allowed)
Side doors: shell writes into src/generated/ (sed -i, >, tee, cp, mv, rm) also blocked
History:    evidence OK (212 past calls in src/); fired 2x, both real hand-edits of api.ts
Day one:    fires on `make clean` (rm -rf src/generated): legitimate? -> near_miss + unless
Lock:       optional sandbox lock also stops scripts writing there (sandbox is off; see below)
```

Done when the user says yes or edits it. Write nothing before that.

If the rung is **prose** or **repo test/lint**, do that instead as [`reference/ladder.md`](reference/ladder.md) describes, tell the user which rung and why, and stop here.

### 2. Install or refresh the dispatcher

If `<guardrails>/forge.py` exists, run `python3 <guardrails>/forge.py doctor` first. Install when it is missing, or when doctor reports it outdated (say so to the user: the dispatcher may be committed and shared):

```bash
python3 <skill-dir>/scripts/forge.py install --scope project --project-dir <repo root>
# or: --scope user
```

Idempotent: it copies the dispatcher and registers the hooks once. Show the user any settings diff it prints.

### 3. Add the rule red/green

Write the rule JSON to a scratch file **outside** `.claude/` (e.g. under `/tmp`) following [`reference/rules.md`](reference/rules.md). For Bash patterns, check normalisation first: `python3 <guardrails>/forge.py split "<command>"`.

```bash
python3 <guardrails>/forge.py add /path/to/rule.json
```

Read the verdict:
- `GREEN` then `Added` → done. It also prints the backtest summary, a `PROMPT BUDGET` note for ask rules, and a `SANDBOX LOCK` line for locked rules; relay any of these to the user.
- `MISSED` → the pattern is too narrow for a bad fixture. Widen it.
- `TOO-BROAD` → the rule fires on its own good/near-miss fixture. Narrow it or add `unless`.
- `CONFLICT` → the rule fires on another rule's good fixture, or blocks the call an always-rule needs ("never commit" next to "always commit after every update"). Show the user both rules and ask which wins. Always-rules that only hold the reply's end or remind never conflict with other rules' examples.
- `LOOP` → two always-rules would trigger each other forever. Ask the user which to keep.
- `INVALID RULE` → fix the listed fields.

A fixture encodes the user's intent, so fix the rule until green. Changing a fixture needs the user's say-so.

Done when `add` prints `Added <id>`.

### 4. Report

Tell the user: the rule in one line, its rung, the settings diff if any, and the undo command `python3 <guardrails>/forge.py remove <id>`. On a first install, add that hook registration may need `/hooks` or a restart before it takes effect in an already-running session.

## Sandbox lock

Hooks cannot see inside scripts (`npm run`, `make`, `python3 tool.py`). Claude Code's OS sandbox can: `sandbox.filesystem.denyWrite` blocks writes from every Bash command **and the programs it starts**. Put `"sandbox": true` on a path rule and `add` copies its glob into `denyWrite`; `remove` takes it out.

The glob does nothing until the sandbox is on, and turning it on changes all Bash commands in the project: writes outside the project are blocked, network access prompts per domain, and sandboxed commands stop asking for permission. So:

1. `python3 <guardrails>/forge.py sandbox status`: current settings, whether this machine can run the sandbox at all (Linux needs working `bwrap` and `socat`), and its **impact** on past work: how many past commands wrote outside the project or used the network. Show that impact to the user; it is what "on" will change.
2. If the machine cannot run it, show the user the fix it prints (it needs `sudo`; the user decides) and stop.
3. Explain the effects above and ask. Only on a yes: `forge.py sandbox on` (`--strict` also removes the per-command escape hatch).
4. The legitimate writer of the protected path (e.g. `make codegen`) must be exempted: `forge.py sandbox exclude "make codegen"`. Exempting loosens the lock, so the tamper guard asks the user.

## Harvest

`python3 <skill-dir>/scripts/forge.py harvest --project-dir <repo root>` clusters correction-like messages from this project's past session transcripts. Show the user the repeated clusters (count, sessions, quotes) and offer to forge the top ones; each accepted cluster goes through **Forge** from step 1.

## Audit

Run `python3 <guardrails>/forge.py audit` for each installed scope (`<repo>/.claude/guardrails/` and `~/.claude/guardrails/`, whichever exist). For each flagged rule, give a one-line recommendation:
- **SILENT**: offer removal. Safety rules are never flagged silent: a rule that never fires may be doing its job.
- **NOISY**: read the example inputs. Legitimate work → narrow the rule. Claude repeating the mistake → keep it.
- **OVERRIDDEN**: the user keeps approving the ask → demote to a nudge or narrow it.
- **ESCALATE?**: a nudge Claude keeps ignoring → offer a deny rule.

The audit also opens with **prompts in the last 7 days**. `PROMPT FATIGUE` means the user is asked so often that approvals stop being read: narrow the top asking rule or turn it into a deny with a corrective reason. `forge.py backtest --all` replays every installed rule over past sessions when a rule's reach is in doubt.

Change only what the user picks. Re-adding an edited rule = `remove`, then `add`.

## Manage

- `forge.py list`: every rule with kind (never/always), class, event, and decision. `list --always` adds each always-rule's last state.
- `forge.py doctor`: hooks registered, dispatcher current, no `disableAllHooks`, suite green, sandbox lock consistent and runnable, recent errors.
- `forge.py backtest <rule.json>|--all`: replay rules over every tool call in past sessions.
- `forge.py sandbox status|on|off|exclude "CMD"`: the OS-level lock (see **Sandbox lock**).
- `forge.py remove <id>`: archives the rule in `rules.archive.json` and drops its permission-deny entries. The tamper guard asks the user to confirm.
- `forge.py test`: re-runs every fixture. Run it after hand-editing `rules.json`.
- `forge.py explain '<hook event JSON>'`: shows which rules fire on one tool call.

## Limits to state honestly

Guardrails catch Claude's habits, not a determined adversary: a pattern can be routed around. Rules act only while Claude works; anything on a clock ("every day at 9") belongs to `/schedule` or `/loop`. That is why safety rules carry a `permission_deny` second layer. Hooks see tool calls only; a rule about how Claude talks or plans belongs on the prose rung. Scripts run from a file (`python3 tool.py`, `make x`) are opaque to hooks: the sandbox lock covers them for path rules where the machine supports it; otherwise opt a rule into `unknown_writes: "ask"`. A dispatcher bug fails open (logged); an unreadable `rules.json` fails toward the user (mutating calls ask until fixed).
