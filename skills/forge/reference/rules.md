# Rule format

One JSON object per rule; `forge.py add` validates it, runs every fixture in the suite, and appends it to `rules.json` only when green.

```json
{
  "id": "no-generated-edits",
  "class": "convention",
  "event": "PreToolUse",
  "tool": "Edit|Write|MultiEdit|NotebookEdit|Bash",
  "match": { "path": "glob:src/generated/**" },
  "unless": {},
  "decision": "deny",
  "message": "src/generated/ is rebuilt by `make codegen`. Edit schema/*.proto, then run make codegen.",
  "permission_deny": [],
  "provenance": { "said": "stop editing the generated client, it gets overwritten", "date": "2026-09-27" },
  "fixtures": {
    "bad":       [{ "tool_name": "Edit", "tool_input": { "file_path": "src/generated/api.ts" } },
                  { "tool_name": "Bash", "tool_input": { "command": "sed -i 's/a/b/' src/generated/api.ts" } }],
    "good":      [{ "tool_name": "Edit", "tool_input": { "file_path": "src/api/client.ts" } },
                  { "tool_name": "Bash", "tool_input": { "command": "make codegen" } }],
    "near_miss": [{ "tool_name": "Edit", "tool_input": { "file_path": "src/generated_docs/README.md" } },
                  { "tool_name": "Bash", "tool_input": { "command": "cat src/generated/api.ts" } }]
  }
}
```

## Fields

- `id`: lowercase, digits, dashes. Unique.
- `class`: `safety` | `convention` | `style`.
- `event` + `decision`: `PreToolUse` → `deny` | `ask`; `PostToolUse` → `nudge`; `Stop` → `block`.
- `tool`: regex, full match on the tool name (`Bash`, `Edit|Write|MultiEdit`, `mcp__.*`).
- `match`: `{field: pattern}`; **all** must hit. `field` is a `tool_input` key (`command`, `file_path`, `content`, `url`, ...) or `path`: the file a tool touches (file_path / path / notebook_path) **plus the paths a Bash command writes, moves onto, or deletes** (`>`, `>>`, `tee`, `sed -i`, `cp`/`mv` destination, `rm`, `touch`, `dd of=`). Also covered: paths inside interpreter one-liners and heredoc scripts that write or delete (`python3 -c "open('x','w')"`, `node -e "fs.writeFileSync('x')"`), symlinks (resolved to where the write lands), `~`/`$HOME`, and deleting or moving an **ancestor** (`rm -rf src` hits `src/generated/**`). A file rule with `tool: "Edit|Write|MultiEdit|NotebookEdit|Bash"` and a `path` glob therefore closes the shell side door in one rule; reads (`cat`, `grep`, `sed -n`, `cp` source) do not count.
- `unless`: `{field: pattern}`; **any** hit vetoes the rule. Use it to carve out legitimate cases.
- `message`: what Claude should do instead. Claude reads it on deny, ask, nudge, and block.
- `unknown_writes` (PreToolUse, optional): `"ask"` makes the rule ask on shell commands whose written files cannot be read off the command line: `git stash pop/apply`, `git apply`, `patch`, `git pull/merge/rebase/reset --hard/checkout <branch>/clean`, `tar`/`unzip`, running a script file with an interpreter, or a target that needs expansion (`src/$D/a.ts`). Use it on protected-path rules where a miss is costly; it is noisy on busy repos.
- `sandbox` (PreToolUse `path` glob rules, optional): `true` also writes the glob into Claude Code's `sandbox.filesystem.denyWrite`, which blocks writes at the OS level from every Bash command and its child processes (scripts included). Enforced only while the sandbox is on; see SKILL.md **Sandbox lock**. User-scope rules need an absolute or `~/` glob.
- `permission_deny`: permission-rule strings merged into `settings.json` `permissions.deny` (second layer for safety rules).
- `run` (PostToolUse only): auto-fix shell command. `{path}` becomes every touched path the rule's `path` pattern matches (Edit/Write file or shell write targets), so one rule covers both; other `{field}` placeholders come from `tool_input`. All shell-quoted. Its output is shown to Claude.
- `provenance`: the user's exact words and the date. `add` also records `provenance.backtest` (history calls, exposure, evidence label, hits), so teammates cloning the repo see what the rule was checked against.
- `require` (optional on PreToolUse and PostToolUse, required on Stop): makes the rule an **always-rule**, a task Claude must do. See **Always-rules** below.
- `fixtures`: `bad`, `good`, `near_miss`, each a non-empty list.

## Patterns

- `glob:` for paths. `*` stays within a segment, `**` crosses segments, `**/` also matches zero dirs, and a trailing `dir/**` also matches `dir` itself. Absolute paths are also tried relative to the project root.
- `cmd:` for Bash commands. Regex searched against each **normalised simple command**: chains (`&&`, `;`, `|`), `bash -c`, `eval`, `$(...)`, `sudo`/`env`/`timeout` wrappers, `VAR=x` prefixes and git global options (`-C dir`) are unwrapped, and quotes are removed. Heredoc bodies are dropped (text written to a file is data); to inspect heredoc text such as a commit message, use `re:` on `command` instead. Anchor with `^` so `echo "git push"` stays an echo. Preview with `forge.py split "<command>"`, which also prints the paths the command writes.
- `re:` raw regex search on the field value (content checks, URLs).

Watch word boundaries: `--force\b` also matches `--force-with-lease`; write `--force(?!-)`.

## Stop gate

```json
{
  "id": "tests-before-done",
  "class": "convention",
  "event": "Stop",
  "decision": "block",
  "require": {
    "after": { "tool": "Edit|Write|MultiEdit|Bash", "match": { "path": "glob:**/*.py" } },
    "ran":   { "tool": "Bash", "match": { "command": "cmd:^(python3? -m )?pytest\\b" } }
  },
  "message": "You edited Python files after the last test run. Run pytest and report the result before finishing.",
  "provenance": { "said": "don't say done without running the tests", "date": "2026-09-27" },
  "fixtures": {
    "bad":       [{ "transcript": [{ "tool_name": "Edit", "tool_input": { "file_path": "app.py" } }] }],
    "good":      [{ "transcript": [{ "tool_name": "Edit", "tool_input": { "file_path": "app.py" } },
                                   { "tool_name": "Bash", "tool_input": { "command": "pytest -q" } }] }],
    "near_miss": [{ "transcript": [{ "tool_name": "Edit", "tool_input": { "file_path": "README.md" } }] }]
  }
}
```

The gate fires when an `after` call happened and no `ran` call followed it. It reads the session transcript. It is the simplest always-rule; the next section has the full form.

## Always-rules

A `require` block makes any rule an always-rule: once the trigger happens, Claude owes the task.

```json
{
  "id": "desktop-build",
  "class": "convention",
  "event": "Stop",
  "decision": "block",
  "require": {
    "after": [{ "tool": "Edit|Write|MultiEdit|Bash", "match": { "path": "glob:src/**" } },
              { "tool": "Edit|Write|MultiEdit|Bash", "match": { "path": "glob:electron/**" } }],
    "ran":   { "tool": "Bash", "match": { "command": "cmd:^make app\\b" } },
    "done_when": { "newer": "~/Desktop/App.exe" },
    "slow_minutes": 15
  },
  "message": "The app's code changed. Run `make app`, then copy release/App.exe to ~/Desktop/. Copy only after the build succeeds; never delete the old copy first.",
  "provenance": { "said": "rebuild the exe and send it to the desktop after every change", "date": "2026-10-16" },
  "fixtures": {
    "bad":       [{ "transcript": [{ "tool_name": "Edit", "tool_input": { "file_path": "src/form.ts" } }], "done": false }],
    "good":      [{ "transcript": [{ "tool_name": "Edit", "tool_input": { "file_path": "src/form.ts" } },
                                   { "tool_name": "Bash", "tool_input": { "command": "make app && cp release/App.exe ~/Desktop/" } }],
                    "done": true }],
    "near_miss": [{ "transcript": [{ "tool_name": "Edit", "tool_input": { "file_path": "tests/form.test.ts" } }], "done": false }]
  }
}
```

### Fields

- `after` (required on Stop and PostToolUse): the trigger. `{tool, match, unless}`, or a list of them (any one counts). Changes after the task was handled open a new **batch**.
- `ran` (required): the usual way to do the task. It closes the batch, and it is what history backtests check.
- `done_when` (optional, recommended): how the hook checks the **result**, whatever command produced it:
  - `{"newer": "<file>"}`: the file exists and is newer than the batch's last change. `~` and project-relative paths work.
  - `{"command": "<shell>", "timeout": 10}`: exit 0 means done. It runs at the end of replies, so keep it under 20 seconds.

  With `done_when`, a workaround command still counts (the file is fresh) and a failed run does not.
- `slow_minutes` (optional, needs `done_when`): the task is long (a build). Claude must **start** it before the reply ends, and may run it in the background. The result is checked once this many minutes have passed since the start.

### What happens at the end of a reply (Stop)

| State | Hook does |
|---|---|
| Not due, or done earlier | Nothing |
| Just done (`done_when` passes) | Shows the user `✓ always-rule <id>: done (<detail>)`, once per batch |
| Due, attempt 1 or 2 | Holds the reply; Claude reads the message plus what made it due. Attempt 2 adds "if it fails again, stop and tell the user what failed and what you tried" |
| Due after 2 attempts | Stops holding; shows `⚠ always-rule <id> is still not done…` at every reply's end until it is done or skipped |
| Slow task started, within `slow_minutes` | Nothing (it is running) |
| Slow task past `slow_minutes`, result missing | Due again: "it ran but the result is missing: <detail>" |

On `PreToolUse` (order gate) the `match` call is denied while the task is due, judged on the calls before it. On `PostToolUse` (`nudge`, `match` optional) Claude is reminded once per batch.

### Conversation triggers

Besides tool names, `tool` can name two conversation events, matched on the field `text`:
- `@user`: a message the user typed. Harness markup is skipped; a typed slash command becomes `/name args`.
- `@claude`: text Claude wrote. Keep these patterns narrow (`re:(?m)^Decision:`).

`replying_to` (a `re:` pattern) on a `@user` spec requires the last thing Claude wrote before that message to match. A bare "yes" counts as approval only after a proposal:

```json
{ "tool": "@user", "match": { "text": "re:(?i)^\\W*(yes|ok|go ahead|do it|approved|نعم|تمام)\\b" },
  "replying_to": "re:(?i)\\?\\s*$|\\b(shall i|want me to|i propose|should we)\\b" }
```

### The user's controls

Only messages **the user** typed count; Claude's words never switch a rule off. Each action is announced once to the user.
- `/always skip [id]`, or a short message with "skip", "not now", "no need" (Arabic too): drops the current batch. The next change makes the task due again. Plain words skip only a batch that is due.
- `/always pause [id]` / "pause": off for the rest of the session.
- `/always resume [id]` / "resume": back on.

### No loops

- Calls that do the task (`ran`), and writes to the `done_when` file, never trigger the same rule.
- `add` and `test` refuse two always-rules whose tasks trigger each other (`LOOP`).

### Fixtures

- A `transcript` entry is a tool call, `{"user": "..."}` or `{"claude": "..."}`, with an optional `"at": "2026-10-16T10:00:00"` (local time).
- A fixture may set `"now"` (default: the last entry's time) and `"done": true|false` to pin the `done_when` result. Without `"done"`, fixtures trust `ran`.
- PreToolUse and PostToolUse fixtures put the transcript next to the call being judged: `{"transcript": [...], "tool_name": "Bash", "tool_input": {...}}`.

## Suite semantics

`add` and `test` run every fixture of every rule against the whole rule set:
- each `bad` fixture must fire its own rule (else `MISSED`);
- no `good` or `near_miss` fixture may fire its own rule (`TOO-BROAD`) or any other rule (`CONFLICT`), with this exception:
- an always-rule that only holds the reply's end (Stop) or only reminds (nudge) blocks no call, so it is not counted against other rules' fixtures;
- an always-rule's `ran` calls in its `good` fixtures must not be denied by any rule without `require` (`CONFLICT`: "commit after every update" next to "never commit"). Order rules only sequence a task, so they are not counted;
- no two always-rules may trigger each other (`LOOP`).
