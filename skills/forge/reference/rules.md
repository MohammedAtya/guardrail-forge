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

The gate fires when an `after` call happened and no `ran` call followed the last one. It reads the session transcript, and gives up after 3 blocks in one session so it can never trap Claude in a loop.

## Suite semantics

`add` and `test` run every fixture of every rule against the whole rule set:
- each `bad` fixture must fire its own rule (else `MISSED`);
- no `good` or `near_miss` fixture may fire its own rule (`TOO-BROAD`) or any other rule (`CONFLICT`).
