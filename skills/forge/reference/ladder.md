# Picking the rung

Take the **highest** rung whose detector has near-zero false positives on legitimate work. If the honest detector would misfire, step down.

| Rung | Mechanism | Use when | Rule fields |
|---|---|---|---|
| 1. Permission deny | `settings.json` `permissions.deny` | The bad call has a fixed shape (a command prefix, a path glob) | `permission_deny` on a PreToolUse rule |
| 1b. Sandbox lock | `sandbox.filesystem.denyWrite` (OS level) | A protected path that scripts or build tools could write; add on top of rung 2 | `"sandbox": true` on a `path` rule |
| 2. Block with reason | PreToolUse `deny` | The call is always wrong; the message tells Claude the right move so it self-corrects | `event: PreToolUse`, `decision: deny` |
| 3. Ask the human | PreToolUse `ask` | Usually wrong, sometimes right (prod targets, big deletions) | `decision: ask` |
| 4. Nudge / auto-fix | PostToolUse `additionalContext`, optional `run` | Harmless to let happen, cheap to correct after (formatting, a reminder) | `event: PostToolUse`, `decision: nudge`, optional `run` |
| 5. Gate the finish | Stop `block` | "Before you say done, X must have happened" | An always-rule: see `/always` |
| 6. Repo test or lint | The repo's own tooling | The rule is about the code, and should bind humans too | Written in the repo, not in rules.json |
| 7. Prose | A line in `CLAUDE.md` | Pure judgment no pattern can detect | Written in CLAUDE.md |

## Always-rules: making Claude do something

A never-rule stops a call. An **always-rule** (`/always`, see `skills/always/SKILL.md`) holds Claude to a task: the rule carries a `require` block with a **trigger** (`after`), the usual way to do it (`ran`), an optional **result check** (`done_when`), and, for long tasks, `slow_minutes`. Pick the shape from what the user said:

| The user says | Shape | Rule fields |
|---|---|---|
| "after every X, do Y", "always Y when you X" | Hold the reply's end until Y is done | `event: Stop`, `decision: block`, `require: {after: X, ran: Y, done_when: ...}` |
| "before X, do Y", "Y first, then X" | Order gate: X is denied until Y is done | `event: PreToolUse`, `decision: deny`, `match: X`, `require: {after: <what makes Y stale>, ran: Y}`; without `after`, Y once per session |
| "remind me / yourself to Y after X" | Reminder, once per batch of changes | `event: PostToolUse`, `decision: nudge`, `require: {after: X, ran: Y}` (no `match` needed) |
| "after X, run `fmt`" (mechanical, no judgment) | The hook runs it itself | PostToolUse `nudge` with `run` (rung 4) |
| "every day at 9", "every 30 minutes" | Not a rule: hooks act only while Claude works | `/schedule` or `/loop` |

**Triggers.** Prefer file changes: "after every change we decide" almost always means "after the files the result is built from change". Watch the task's inputs, not its outputs. Conversation triggers (`@user` with `replying_to`, `@claude`, a typed marker) are for tasks with no file behind them, and are weaker because they read wording.

**Result over method.** `done_when` checks the outcome (`{"newer": "<file>"}` or a quick `{"command": ...}`), so a workaround command still counts and a failed run does not. Without it the rule trusts that `ran` ran.

**Strength.** The end-of-reply hold and the order gate keep Claude at it until the task is done; a reminder only informs. A held reply gets two attempts per batch of changes; then the task is handed to the user with a reminder at every reply's end.

## Class sets the default rung

- **safety**: irreversible or dangerous (force-push, `rm -rf`, prod data, secrets). Rung 2 **plus** rung 1 as a second layer: always fill `permission_deny` when the call has a fixed shape. The audit never flags safety rules as silent.
- **convention**: facts about this repo (package manager, generated dirs, migration command). Rung 2 with a message naming the correct alternative; rung 3 when real exceptions exist.
- **style**: preferences (commit format, naming). Rung 4. Blocking style is never worth the friction.

## Side doors

A block on one tool invites the same change through another. For any rule about **files**, list `Bash` in `tool` next to the edit tools and match on `path`: `path` also covers what a shell command writes (`sed -i`, `>`, `tee`, `cp`/`mv` onto, `rm`). Add a shell write to the bad fixtures and a shell read (`cat`, `grep`) to the near-misses. For rules about **commands**, the `cmd:` pattern already sees through `bash -c`, `sudo`, `env`, `&&` chains, and `git -C`. Interpreter one-liners, symlinks, and deleting a parent directory are covered too. What stays open: files written by a script run from disk (`python3 tool.py`) or by git operations that do not name paths; add `unknown_writes: "ask"` to close those at the cost of more prompts. The block message tells Claude to stop and ask rather than route around the rule.

## Rungs outside the dispatcher

- **Repo test/lint**: add the check in the repo's existing tool (eslint rule, ruff rule, a test). Run it once red on the bad case and once green on the fixed case, and show both outputs.
- **Prose**: append one line to the relevant `CLAUDE.md` with a trailing comment `<!-- forge: "<user's words>" YYYY-MM-DD -->`. Tell the user this is the weakest rung and why nothing stronger fits.

## Worked picks

- "Stop using npm, this repo is pnpm" → convention, rung 2: `cmd:^npm\b` deny, message "use pnpm <same args>". Near-miss: `pnpm install`, `echo npm`.
- "Never force-push" → safety, rung 2 + 1: `cmd:^git push\b.*\s(--force(?!-)|-f\b)`, `permission_deny: ["Bash(git push --force *)", "Bash(git push -f *)"]`. Near-miss: `git push --force-with-lease`.
- "Ask me before touching anything in prod" → safety, rung 3 ask on `cmd:\bprod\b` for deploy/migrate commands.
- "Run prettier after you edit TS files" → style, rung 4, `tool: "Edit|Write|MultiEdit|Bash"`, `match: {"path": "glob:**/*.ts"}`, `run: "npx prettier --write {path}"`.
- "Don't tell me it's done without running tests" → convention, rung 5: after an Edit|Write|Bash write to a .py file, require a Bash call matching the test command.
- "Explain trade-offs before big refactors" → prose. No tool call reveals it.
- "Rebuild the app and put it on my desktop after every change" → always-rule: `after` writes under the app's source dirs, `ran` the build-and-copy command, `done_when: {"newer": "~/Desktop/App.exe"}`, `slow_minutes` for an 8-minute build.
- "Do a commit after every update" → always-rule: `after` any write (`path: glob:**`, `unless` `/tmp/**`), `ran` `cmd:^git commit\b`, `done_when: {"command": "test -z \"$(git status --porcelain)\""}`. Ask whether "update" means each edit (then a reminder) or each finished task (the default).
- "Update the PDF after every change we decide" → always-rule on the document the PDF is built from: `after` writes to `plan.md`, `done_when: {"newer": "plan.pdf"}`.
- "Write a summary every time we decide something" → always-rule with a conversation trigger: the user's short approval `replying_to` a Claude proposal, or `AskUserQuestion`; `ran` a write to `DECISIONS.md`.
- "Always run the tests before you commit" → order gate: PreToolUse deny on `cmd:^git commit\b`, `require: {after: edits to *.py, ran: pytest}`.
