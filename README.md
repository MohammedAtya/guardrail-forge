# Guardrail Forge

**Correct Claude once. It stays corrected. Ask once. It keeps doing it.**

[![tests](https://github.com/MohammedAtya/guardrail-forge/actions/workflows/tests.yml/badge.svg)](https://github.com/MohammedAtya/guardrail-forge/actions/workflows/tests.yml)
![license](https://img.shields.io/badge/license-MIT-blue)
![version](https://img.shields.io/badge/version-3.0.0-informational)

A skill for [Claude Code](https://claude.com/claude-code). When you tell Claude "don't do that again", it usually writes a line in `CLAUDE.md`. In a long session that line gets forgotten and the mistake comes back.

Guardrail Forge turns the correction into a **rule that a small program checks before every action Claude takes**. It doesn't depend on Claude's memory, so it can't be forgotten.

It works both ways, with two commands:

| Command | Rule | Example |
|---|---|---|
| `/forge` | **never-rule**: stops Claude doing something | "never force-push", "don't edit generated files" |
| `/always` | **always-rule**: makes Claude do something, every time | "rebuild the app and put it on my desktop after every change", "commit after every update", "run the tests before you commit" |

```
You:     You hand-edited src/generated/api.ts again. It's generated. Never do that.

Claude:  Rule:      Block edits to anything in src/generated/
         Blocks:    Edit src/generated/api.ts, sed -i … src/generated/api.ts
         Allows:    Edit src/api/client.ts, make codegen
         Near-miss: Edit src/generated_docs/README.md  (allowed)
         History:   evidence OK (212 past actions in src/); fired 1x: the real hand-edit
         Install it?

You:     Yes.

Claude:  Done. Tested: it blocks the mistake and allows normal work.
```

From then on, if Claude tries to edit that folder, the action is stopped and Claude is told why ("change `schema/api.proto` and run `make codegen` instead"). It corrects itself without bothering you.

```
You:     /always rebuild the app and put it on my desktop after every change

Claude:  I'll make this always-rule:
           When:       code under src/ or electron/ changes
           Do:         build the app (make app) and copy App.exe to your Desktop
           Done when:  ~/Desktop/App.exe is newer than your last change
           By:         before Claude finishes its reply (the ~8 min build runs in the background)
           Example:    Claude fixes src/form.ts → it must start the build before it can say "done"
           Not:        Claude edits tests/ or notes → nothing due
         Say yes, or tell me what to change.

You:     yes
```

From then on you never ask "did you rebuild it?" again. When the new exe lands, you see `✓ always-rule desktop-build: done (App.exe updated 14:32)`.

## Install

**As a plugin (recommended)**, inside Claude Code:

```
/plugin marketplace add MohammedAtya/guardrail-forge
/plugin install guardrail-forge@guardrail-forge
```

The skills are then available as `/guardrail-forge:forge` and `/guardrail-forge:always`, and they also start on their own when you correct Claude or ask it to always do something.

**Or manually**, so they are available as `/forge` and `/always` (copy both folders: `/always` uses the engine in `forge`):

```bash
git clone https://github.com/MohammedAtya/guardrail-forge
cp -r guardrail-forge/skills/forge ~/.claude/skills/forge
cp -r guardrail-forge/skills/always ~/.claude/skills/always
```

**Upgrading from 2.x:** your rules keep working. Update the skill, then run `/forge doctor`; it offers to update each project's hook program. `/always` does this for you before it adds its first rule, because an older hook program misreads always-rules.

**Requirements:** Claude Code and Python 3.9+. Nothing to `pip install`; everything uses the standard library.

## How it works

```
Claude wants to act  ──►  forge.py checks your rules  ──►  allowed
(edit a file,             (.claude/guardrails/                blocked, with a reason Claude reads
 run a command)            rules.json)                        asks you first
```

- **One small dispatcher** (`forge.py`) is registered once as a Claude Code hook. It reads your rules on every tool call and answers in about 50 ms.
- **Rules are data**, not code. Each rule stores your original words and the date.
- **Every firing is logged**, so you can see later what your rules stopped.

### Never-rules (`/forge`)

| Kind | What it does | Example |
|---|---|---|
| Block | Stops the action and tells Claude what to do instead | "Don't edit generated files", "never force-push", "use pnpm, not npm" |
| Ask | Asks you before the action runs | "Ask me before anything touches the production database" |
| Remind or fix | Lets the action happen, then reminds Claude or fixes the file | "Run prettier after every .ts edit" |

### Always-rules (`/always`)

You write one sentence; the skill works out the rest from your project and shows you a plain preview (When / Do / Done when / By, with an example) before anything is installed.

| You say | When it's due | What happens |
|---|---|---|
| "Rebuild the app and put it on my desktop after every change" | The app's code changed | Claude can't finish its reply until the build has started; it runs in the background and you get a ✓ when the new exe lands |
| "Update the PDF after every change we decide" | The document the PDF is built from changed | Claude can't finish until the PDF is newer than the document |
| "Commit after every update" | Claude changed files | Claude can't finish until the changes are committed |
| "Always run the tests before you commit" | Code changed since the last test run | `git commit` is blocked until the tests run |
| "Write a summary after each decision" | You approved something Claude proposed | Claude can't finish until it writes to `DECISIONS.md` |

How it behaves:

- **It checks the result, not just the command.** "The exe on the Desktop is newer than your code" counts however Claude got there, and a failed build is caught instead of being reported as done.
- **Long tasks don't freeze the conversation.** A slow build must be *started* before the reply ends and runs in the background; its result is checked when it should be done.
- **Two attempts, then you.** If the task keeps failing, Claude is held back twice, then tells you what failed and what it tried. A one-line ⚠ reminder stays until it is fixed. It never loops.
- **You stay in control.** `/always skip` (just these changes), `/always pause` (this session), `/always resume`, `/always list`, `/always remove`. Plain words like "skip it this time" work too, but only *your* words count. Claude can't talk itself out of a rule.
- **No endless loops.** A task never re-triggers its own rule, and two rules that would trigger each other are refused when you add them.
- **It works while Claude works.** For things on a clock ("every morning at 9"), use Claude Code's `/schedule` or `/loop`.

Judgment calls that no program can check (like "explain trade-offs before a big refactor") go in `CLAUDE.md`, and the skill tells you plainly that this is the weakest kind.

### What it sees through

A rule about files covers the Edit and Write tools **and** shell commands that write: redirects, `tee`, `sed -i`, `cp`/`mv`/`rm`, `dd`, `git checkout`/`restore`, `curl -o`, archive extraction, in-place formatters, compiler output flags, and Python/Node one-liners and heredoc scripts. It follows `cd`, symlinks, `bash -c`, `sudo`, `$(...)`, `&&` chains and `$PWD`. It ignores reads, so `cat`, `grep` and copying *out* of a protected folder still work.

## Every rule is tested before you approve it

1. **Fixtures.** Each rule ships with three examples: the mistake (must be blocked), normal work (must pass), and a look-alike that is fine (must pass). A new rule is also run against every other rule's examples, so conflicts are caught before install.
2. **Backtest on your history.** The draft rule is replayed over every action Claude took in this project's past sessions. Each hit is either a real past mistake (the rule works) or legitimate work (the rule is too broad, so it gets narrowed).
3. **Evidence strength.** The backtest reports how many past actions were in the rule's area: `NONE`, `LOW` or `OK`. With thin history it says "not enough history to vouch for this rule" and never claims "no false positives".
4. **Day-one test.** The rule is also tried on your project's own `package.json` scripts, `Makefile` targets, CI steps and files, plus about 140 common developer tasks in 8 areas. This works on a fresh clone and covers areas your history never touched.
5. **You label the hits.** Real mistakes become "blocked" examples and legitimate work becomes "allowed" examples. The evidence is saved inside the rule, so teammates see what it was tested against.

## Claude can't switch it off

A rule built into the dispatcher (not stored in `rules.json`, so it can't be edited away) enforces a ratchet: **Claude can make the rules stricter, never looser, without you.**

| Action | Result |
|---|---|
| Adding a rule | Allowed |
| Removing a rule, editing Claude Code settings, exempting a command from the sandbox | Asks you |
| Editing the rules file or the dispatcher directly, deleting `.claude/`, setting `disableAllHooks` | Blocked |

In testing, a Claude session tried to disable the guardrails nine different ways and every attempt failed.

## Optional: the sandbox double lock

Hooks see the command Claude types, not what a script like `npm run build` does inside. For rules that protect files, you can add Claude Code's OS-level sandbox as a second lock: `sandbox.filesystem.denyWrite` blocks writes from every command and everything it starts.

It is off by default because turning the sandbox on changes all shell commands in a project (writes outside the project are blocked, and network access prompts per site). `/forge sandbox` shows what would change based on your past work, and Claude never turns it on without asking. On Linux it needs working `bubblewrap` and `socat`; `/forge doctor` checks that and tells you the fix if something is missing.

## Commands

| You type | What happens |
|---|---|
| `/forge` + a rule, or "don't do that again" | Claude proposes a never-rule, backtests it, and installs it after your yes |
| `/always` + a task, or "always do X after Y" | Claude proposes an always-rule, backtests it, and installs it after your yes |
| `/always skip` / `pause` / `resume` / `list` / `remove` | Control your always-rules |
| `/forge harvest` | Finds corrections you gave in more than one past session and suggests them as rules |
| `/forge audit` | Prompts you got this week, plus rules that never fire, fire too often, or that you always approve |
| `/forge list` | All rules |
| `/forge doctor` | Health check: installed, current, tests green, sandbox state |
| `/forge sandbox` | Sandbox lock status and impact |
| "remove rule X" | Claude asks you to confirm, then removes it (archived, restorable) |

With the plugin install, use `/guardrail-forge:forge` in place of `/forge`.

## Files it creates in your project

| File | What it is |
|---|---|
| `.claude/guardrails/rules.json` | Your rules, with your words, dates and test evidence. Commit it so your team gets the rules. |
| `.claude/guardrails/forge.py` | The dispatcher. |
| `.claude/guardrails/ledger.jsonl` | When each rule fired. Local only (gitignored), with secrets redacted. |
| `.claude/settings.json` | The one-time hook registration. |

Personal habits can go in `~/.claude/guardrails/` instead, so they apply to every project.

## Limits

- **It guards Claude's habits, not against an attacker.** It stops repeated mistakes. It is not a security boundary against someone deliberately trying to break in.
- **Scripts run from disk are opaque to hooks.** The sandbox lock covers them where your machine supports it; otherwise a rule can ask you before scripts run (`unknown_writes: "ask"`).
- **It sees actions, not words.** Rules about how Claude talks or plans belong in `CLAUDE.md`. An always-rule can be triggered by what you wrote (an approval), but that reads wording, so the skill prefers file changes and tells you when it can't.
- **Always-rules act while Claude works.** They are checked when Claude finishes a reply or acts, not on an idle session.

## Development

```bash
python3 -m unittest discover -s skills/forge/tests -v
```

74 tests: parsing, every rule type including always-rules, the tamper ratchet, the backtest and the sandbox lock. The design was stress-tested against 76 bypass attempts (0 got through, 0 false positives) and in live Claude Code sessions. It was reviewed along the way by DeepSeek R1, DeepSeek V4 and Gemma 4.

The skills' instructions are in [`skills/forge/SKILL.md`](skills/forge/SKILL.md) and [`skills/always/SKILL.md`](skills/always/SKILL.md); the rule format is in [`skills/forge/reference/rules.md`](skills/forge/reference/rules.md).

## License

[MIT](LICENSE) © 2026 Mohammed Atya
