"""Tests for forge.py. Run: python3 -m unittest discover -s ~/.claude/skills/forge/tests -v"""
import datetime as dt
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest


def readj(path):
    with open(path) as f:
        return json.load(f)


def writej(path, data):
    with open(path, "w") as f:
        json.dump(data, f)

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "forge.py")
spec = importlib.util.spec_from_file_location("forge", SRC)
forge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forge)


def fx(tool, **inp):
    return {"tool_name": tool, "tool_input": inp}


def rule(**over):
    base = {
        "id": "no-generated-edits", "class": "convention", "event": "PreToolUse",
        "tool": "Edit|Write|MultiEdit|Bash", "match": {"path": "glob:src/generated/**"}, "decision": "deny",
        "message": "Edit schema/*.proto and run make codegen instead.",
        "provenance": {"said": "stop editing the generated client", "date": "2026-09-27"},
        "fixtures": {"bad": [fx("Edit", file_path="src/generated/api.ts"),
                             fx("Bash", command="sed -i 's/a/b/' src/generated/api.ts"),
                             fx("Bash", command="cat > src/generated/api.ts <<'EOF'\nx\nEOF"),
                             fx("Bash", command="rm -rf src/generated")],
                     "good": [fx("Edit", file_path="src/api/client.ts"), fx("Bash", command="make codegen")],
                     "near_miss": [fx("Edit", file_path="src/generated_docs/README.md"),
                                   fx("Bash", command="cat src/generated/api.ts"),
                                   fx("Bash", command="cp src/generated/api.ts /tmp/x.ts")]},
    }
    base.update(over)
    return base


NO_NPM = rule(id="no-npm", tool="Bash", match={"command": "cmd:^npm\\b"}, message="Use pnpm.",
              fixtures={"bad": [fx("Bash", command="cd web && npm install")],
                        "good": [fx("Bash", command="pnpm install")],
                        "near_miss": [fx("Bash", command="echo npm is not used here")]})

NO_FORCE = rule(id="no-force-push", **{"class": "safety"}, tool="Bash",
                match={"command": "cmd:^git push\\b.*\\s(--force(?!-)|-f\\b)"},
                message="Never force-push. Push normally or ask the user.",
                permission_deny=["Bash(git push --force *)", "Bash(git push -f *)"],
                fixtures={"bad": [fx("Bash", command="git push --force origin main"),
                                  fx("Bash", command='bash -c "git -C repo push -f"')],
                          "good": [fx("Bash", command="git push origin feature")],
                          "near_miss": [fx("Bash", command="git push --force-with-lease"),
                                        fx("Bash", command="echo 'git push --force'")]})

PROD_ASK = rule(id="ask-prod-migrate", **{"class": "safety"}, tool="Bash", decision="ask",
                match={"command": "cmd:^(make )?migrate\\b.*\\bprod\\b"}, message="Confirm prod migration.",
                fixtures={"bad": [fx("Bash", command="make migrate ENV=prod")],
                          "good": [fx("Bash", command="make migrate ENV=dev")],
                          "near_miss": [fx("Bash", command="grep prod migrate.log")]})

FMT = rule(id="fmt-after-edit", **{"class": "style"}, event="PostToolUse", decision="nudge",
           tool="Edit|Write", match={"path": "glob:**/*.ts"}, message="File was formatted.",
           run="echo formatted {file_path}",
           fixtures={"bad": [fx("Edit", file_path="src/a.ts")], "good": [fx("Edit", file_path="src/a.py")],
                     "near_miss": [fx("Edit", file_path="src/a.tsx")]})

TESTS_GATE = {
    "id": "tests-before-done", "class": "convention", "event": "Stop", "decision": "block",
    "require": {"after": {"tool": "Edit|Write|Bash", "match": {"path": "glob:**/*.py"}},
                "ran": {"tool": "Bash", "match": {"command": "cmd:^(python3? -m )?pytest\\b"}}},
    "message": "Run pytest before finishing.",
    "provenance": {"said": "don't say done without tests", "date": "2026-09-27"},
    "fixtures": {"bad": [{"transcript": [fx("Edit", file_path="app.py")]},
                         {"transcript": [fx("Bash", command="cat > app.py <<'EOF'\npass\nEOF")]}],
                 "good": [{"transcript": [fx("Edit", file_path="app.py"), fx("Bash", command="pytest -q")]}],
                 "near_miss": [{"transcript": [fx("Edit", file_path="README.md")]}]},
}


class Split(unittest.TestCase):
    cases = {
        "git push --force origin main": ["git push --force origin main"],
        "cd repo && git push -f": ["cd repo", "git push -f"],
        "git -C ../x push --force": ["git push --force"],
        "git -c user.name=x --no-pager push": ["git push"],
        'bash -c "git push --force"': ["git push --force"],
        "sh -lc 'npm i'": ["npm i"],
        "FOO=1 sudo -E git push -f": ["git push -f"],
        "echo 'git push --force'": ["echo git push --force"],
        "ls\ngit push -f": ["ls", "git push -f"],
        "timeout 10s npm install": ["npm install"],
        'eval "rm -rf /tmp/x"': ["rm -rf /tmp/x"],
        "cat a | xargs -0 rm": ["cat a", "rm"],
        "/usr/bin/git push": ["git push"],
    }

    def test_normalisation(self):
        for cmd, want in self.cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(forge.split_command(cmd), want)

    def test_newline_inside_quotes_is_text(self):
        cmd = 'git commit -m "Fix push logic\n\ngit push -f was used before"\ngit status'
        self.assertEqual(forge.split_command(cmd)[1], "git status")
        self.assertEqual(len(forge.split_command(cmd)), 2)
        self.assertFalse(forge.pattern_matches("cmd:^git push", [cmd], "/p"))

    def test_substitution_is_seen(self):
        self.assertIn("git push -f", forge.split_command("echo $(git push -f)"))
        self.assertIn("npm i", forge.split_command("x=`npm i`"))

    def test_heredoc_body_is_data(self):
        cmd = "cat > README.md <<'EOF'\nRun npm install then git push --force\nEOF\ngit status"
        self.assertEqual(forge.split_command(cmd), ["cat > README.md <<EOF", "git status"])
        self.assertFalse(forge.pattern_matches("cmd:^npm\\b", [cmd], "/p"))

    def test_write_targets(self):
        cases = {
            "sed -i 's/a/b/' x.ts": ["x.ts"], "sed -n 1p x.ts": [], "echo a >> x 2>/dev/null": ["x"],
            "cat n | tee -a y": ["y"], "cp a b": ["b"], "mv a dir/": ["a", "dir/"], "rm -rf d": ["d"],
            "dd if=/dev/zero of=z": ["z"], 'bash -c "echo 1 > q"': ["q"], "cat x": [], "ls && touch t": ["t"],
            "cat > app.py <<'EOF'\nprint(1) > nope\nEOF": ["app.py"],
            "cd src/generated && sed -i s/a/b/ api.ts": ["src/generated/api.ts"],
            "cd src && echo x > ../src/generated/a.ts": ["src/generated/a.ts"],
            "cd a; cd b && touch c": ["a/b/c"], "cd /abs && touch c": ["/abs/c"],
            "G=.claude/x.py\nfor c in \"echo 'x' > src/g/a.ts\" \"rm src/g/b\"; do echo $c; done": [],
            "OUT=src/g/a.ts ./build.sh": ["src/g/a.ts"], "echo 'a > b' | wc": [], "ls 2>/dev/null >out.txt": ["out.txt"],
            "find . -type f -exec ls -l {} \\\\;": [], "find build -name '*.o' -exec rm {} +": ["build"],
            "python3 - <<'EOF'\nsrc = open('forge.py').read()\ncases = ['src/generated/api.ts']\nopen('forge.py','w').write(src)\nEOF": ["forge.py"],
            "python3 - <<'EOF'\np = Path('src/g/a.ts')\ns = p.read_text()\np.write_text(s + 'x')\nEOF": ["src/g/a.ts"],
            "python3 -c \"import shutil; shutil.copy('a.txt', 'src/g/b.txt')\"": ["src/g/b.txt"],
            "python3 -c \"from pathlib import Path; Path('my report.md').write_text('x')\"": ["my report.md"],
            "python3 -c \"s = 'a,b'.replace(',', ';'); print(s)\"": [],
            "git checkout HEAD~3 -- src/g/a.ts": ["src/g/a.ts"], "git restore src/g/a.ts": ["src/g/a.ts"],
            "git checkout main": [], "git -C . restore --staged x": [],
        }
        for cmd, want in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(forge.bash_write_targets(cmd), want)

    def test_unbalanced_quotes_do_not_crash(self):
        self.assertTrue(forge.split_command('echo "unterminated'))


class Glob(unittest.TestCase):
    def test_globs(self):
        m = lambda pat, path, cwd="/p": forge.pattern_matches("glob:" + pat, [path], cwd)
        self.assertTrue(m("src/generated/**", "src/generated/a/b.ts"))
        self.assertTrue(m("src/generated/**", "src/generated"))
        self.assertFalse(m("src/generated/**", "src/generated_docs/x.md"))
        self.assertTrue(m("src/generated/**", "/p/src/generated/a.ts"))
        self.assertTrue(m("src/generated/**", "./src/generated/a.ts"))
        self.assertFalse(m("src/generated/**", "/elsewhere/src/generated/a.ts"))
        # the shell cd'd into the dir in an earlier call; hook cwd follows it
        self.assertTrue(forge.pattern_matches("glob:src/generated/**", ["api.ts"], "/p/src/generated")
                        if os.environ.setdefault("CLAUDE_PROJECT_DIR", "/p") else False)
        os.environ.pop("CLAUDE_PROJECT_DIR")
        self.assertTrue(m("src/generated/**", "../src/generated/a.ts", "/p/src") is False)
        self.assertTrue(m("**/*.env", ".env"))
        self.assertTrue(m("**/*.env", "a/b/prod.env"))
        self.assertFalse(m("*.ts", "src/a.ts"))
        self.assertFalse(m("**/*.ts", "src/a.tsx"))


class Validate(unittest.TestCase):
    def test_all_sample_rules_valid(self):
        for r in (rule(), NO_NPM, NO_FORCE, PROD_ASK, FMT, TESTS_GATE):
            self.assertEqual(forge.validate(r), [], r["id"])

    def test_rejections(self):
        bad = {
            "class": rule(**{"class": "urgent"}),
            "decision": rule(decision="nudge"),
            "id": rule(id="Bad ID"),
            "message": rule(message=" "),
            "provenance": rule(provenance={}),
            "kind": rule(match={"path": "src/**"}),
            "regex": rule(tool="Bash", match={"command": "cmd:(unclosed"}),
            "fixtures": rule(fixtures={"bad": [fx("Edit", file_path="x")], "good": [], "near_miss": []}),
            "run": rule(run="echo x"),
            "stop": {**TESTS_GATE, "require": {}},
            "perm": rule(permission_deny=["rm -rf"]),
        }
        for name, r in bad.items():
            with self.subTest(name=name):
                self.assertTrue(forge.validate(r))
        self.assertTrue(forge.validate(rule(), existing_ids={"no-generated-edits"}))


class Suite(unittest.TestCase):
    def test_green(self):
        checks, fails = forge.run_suite([rule(), NO_NPM, NO_FORCE, PROD_ASK, FMT, TESTS_GATE])
        self.assertEqual(fails, [])
        self.assertGreaterEqual(checks, 20)

    def test_missed(self):
        r = rule(match={"path": "glob:src/gen/**"})
        self.assertTrue(any(f.startswith("MISSED") for f in forge.run_suite([r])[1]))

    def test_too_broad(self):
        r = rule(match={"path": "glob:src/generated*/**"})
        self.assertTrue(any(f.startswith("TOO-BROAD") for f in forge.run_suite([r])[1]))

    def test_conflict(self):
        no_pnpm = rule(id="no-pnpm", tool="Bash", match={"command": "cmd:^pnpm\\b"}, message="use npm",
                       fixtures={"bad": [fx("Bash", command="pnpm i")], "good": [fx("Bash", command="npm i")],
                                 "near_miss": [fx("Bash", command="echo pnpm")]})
        fails = forge.run_suite([NO_NPM, no_pnpm])[1]
        self.assertTrue(any(f.startswith("CONFLICT") for f in fails), fails)


class Sandbox(unittest.TestCase):
    """A temp project with the dispatcher installed, driven the way Claude Code drives it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.tmp.name, "home")
        self.proj = os.path.join(self.tmp.name, "proj")
        os.makedirs(os.path.join(self.proj, ".claude"))
        os.makedirs(self.home)
        with open(os.path.join(self.proj, ".claude", "settings.json"), "w") as f:
            json.dump({"model": "keep-me", "hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]}]}}, f)
        self.env = {**os.environ, "HOME": self.home, "CLAUDE_PROJECT_DIR": self.proj}
        out = self.cli(SRC, "install", "--scope", "project", "--project-dir", self.proj)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.g = os.path.join(self.proj, ".claude", "guardrails")
        self.forge = os.path.join(self.g, "forge.py")

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, script, *args, stdin=None):
        return subprocess.run([sys.executable, script, *args], input=stdin, capture_output=True,
                              text=True, env=self.env, cwd=self.proj)

    def add(self, r, *extra):
        return self.cli(self.forge, "add", "-", *extra, stdin=json.dumps(r))

    def hook(self, mode, payload):
        payload = {"session_id": "s1", "cwd": self.proj, **payload}
        res = subprocess.run([sys.executable, "-c", forge.LAUNCHER, self.g, mode], input=json.dumps(payload),
                             capture_output=True, text=True, env=self.env, cwd=self.proj)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout) if res.stdout.strip() else None

    def settings(self):
        return readj(os.path.join(self.proj, ".claude", "settings.json"))

    def ledger(self):
        path = os.path.join(self.g, "ledger.jsonl")
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(l) for l in f]

    def rules_on_disk(self):
        return readj(os.path.join(self.g, "rules.json"))

    def write_transcript(self, calls):
        path = os.path.join(self.tmp.name, "t.jsonl")
        with open(path, "w") as f:
            f.write(json.dumps({"type": "user", "message": {"role": "user", "content": "hi"}}) + "\n")
            f.write("not json\n")
            for name, inp in calls:
                f.write(json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
                    {"type": "text", "text": "..."}, {"type": "tool_use", "id": "x", "name": name, "input": inp}]}}) + "\n")
        return path


class Project(Sandbox):
    # install
    def test_install_registers_and_preserves(self):
        s = self.settings()
        self.assertEqual(s["model"], "keep-me")
        cmds = [h["command"] for g in s["hooks"]["PreToolUse"] for h in g["hooks"]]
        self.assertIn("echo mine", cmds)
        self.assertTrue(any('"$CLAUDE_PROJECT_DIR/.claude/guardrails" pre' in c and "import forge" in c for c in cmds))
        self.assertIn("PostToolUse", s["hooks"])
        self.assertIn("Stop", s["hooks"])
        self.assertTrue(os.path.exists(os.path.join(self.g, ".gitignore")))

    def test_install_idempotent(self):
        before = self.settings()
        out = self.cli(SRC, "install", "--scope", "project", "--project-dir", self.proj)
        self.assertIn("Already installed", out.stdout)
        self.assertEqual(before, self.settings())

    def test_user_scope_uses_absolute_path(self):
        out = self.cli(SRC, "install", "--scope", "user")
        self.assertEqual(out.returncode, 0, out.stderr)
        s = readj(os.path.join(self.home, ".claude", "settings.json"))
        cmd = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn(os.path.join(self.home, ".claude", "guardrails"), cmd)

    # add
    def test_add_merges_permission_deny(self):
        out = self.add(NO_FORCE)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn("Bash(git push --force *)", self.settings()["permissions"]["deny"])
        self.assertEqual([r["id"] for r in self.rules_on_disk()], ["no-force-push"])

    def test_add_red_writes_nothing(self):
        out = self.add(rule(match={"path": "glob:src/**"}))
        self.assertEqual(out.returncode, 3)
        self.assertIn("TOO-BROAD", out.stdout)
        self.assertEqual(self.rules_on_disk(), [])

    def test_add_conflict_blocked(self):
        self.assertEqual(self.add(NO_NPM).returncode, 0)
        no_pnpm = rule(id="no-pnpm", tool="Bash", match={"command": "cmd:^pnpm\\b"}, message="use npm",
                       fixtures={"bad": [fx("Bash", command="pnpm i")], "good": [fx("Bash", command="yarn")],
                                 "near_miss": [fx("Bash", command="echo pnpm")]})
        out = self.add(no_pnpm)
        self.assertEqual(out.returncode, 3)
        self.assertIn("CONFLICT", out.stdout)
        self.assertIn("fired by no-pnpm", out.stdout)

    def test_add_invalid_and_duplicate(self):
        self.assertEqual(self.add(rule(**{"class": "x"})).returncode, 2)
        self.assertEqual(self.add(rule()).returncode, 0)
        out = self.add(rule())
        self.assertEqual(out.returncode, 2)
        self.assertIn("already exists", out.stdout)

    def test_dry_run(self):
        out = self.add(NO_FORCE, "--dry-run")
        self.assertIn("DRY RUN", out.stdout)
        self.assertEqual(self.rules_on_disk(), [])
        self.assertNotIn("permissions", self.settings())

    # hooks
    def test_pre_deny_shape_and_ledger(self):
        self.add(rule())
        out = self.hook("pre", {"hook_event_name": "PreToolUse", "tool_name": "Edit",
                                "tool_input": {"file_path": os.path.join(self.proj, "src/generated/a.ts")}})
        h = out["hookSpecificOutput"]
        self.assertEqual(h["hookEventName"], "PreToolUse")
        self.assertEqual(h["permissionDecision"], "deny")
        self.assertIn("[guardrail no-generated-edits]", h["permissionDecisionReason"])
        self.assertIn("do not route around it", h["permissionDecisionReason"])
        fires = [e for e in self.ledger() if e["kind"] == "fire"]
        self.assertEqual(fires[0]["rule"], "no-generated-edits")

    def test_pre_no_match_is_silent(self):
        self.add(rule())
        self.assertIsNone(self.hook("pre", {"tool_name": "Edit", "tool_input": {"file_path": "src/ok.ts"}}))
        self.assertIsNone(self.hook("pre", {"tool_name": "Read", "tool_input": {"file_path": "src/generated/a"}}))

    def test_deny_beats_ask(self):
        self.add(PROD_ASK)
        wipe = rule(id="no-prod-wipe", **{"class": "safety"}, tool="Bash", match={"command": "cmd:--wipe\\b"},
                    message="Never wipe.",
                    fixtures={"bad": [fx("Bash", command="make migrate ENV=prod --wipe")],
                              "good": [fx("Bash", command="make migrate ENV=dev")],
                              "near_miss": [fx("Bash", command="echo wipe")]})
        self.assertEqual(self.add(wipe).returncode, 0)
        out = self.hook("pre", {"tool_name": "Bash", "tool_input": {"command": "make migrate ENV=prod --wipe"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("Never wipe", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertEqual(len([e for e in self.ledger() if e["kind"] == "fire"]), 2)

    def test_ask_then_approval_is_logged(self):
        self.add(PROD_ASK)
        call = {"tool_name": "Bash", "tool_input": {"command": "make migrate ENV=prod"}}
        out = self.hook("pre", call)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        self.hook("post", call)
        self.hook("post", call)  # a second PostToolUse must not double count
        self.assertEqual(len([e for e in self.ledger() if e["kind"] == "approved"]), 1)

    def test_post_nudge_runs_fixer(self):
        self.add(FMT)
        out = self.hook("post", {"tool_name": "Edit", "tool_input": {"file_path": "src/a b.ts"}})
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("formatted src/a b.ts", ctx)
        self.assertIn("exit 0", ctx)

    def test_post_fixer_path_placeholder_covers_shell_writes(self):
        r = {**FMT, "id": "fmt-any", "tool": "Edit|Write|Bash", "run": "echo formatted {path}"}
        r["fixtures"] = {**FMT["fixtures"], "bad": FMT["fixtures"]["bad"] + [fx("Bash", command="sed -i s/a/b/ src/c.ts")]}
        self.assertEqual(self.add(r).returncode, 0)
        out = self.hook("post", {"tool_name": "Bash", "tool_input": {"command": "sed -i s/a/b/ src/c.ts notes.md"}})
        self.assertIn("formatted src/c.ts", out["hookSpecificOutput"]["additionalContext"])
        self.assertNotIn("notes.md", out["hookSpecificOutput"]["additionalContext"].split("ran")[1])

    def test_stop_gate(self):
        self.assertEqual(self.add(TESTS_GATE).returncode, 0)
        t = self.write_transcript([("Edit", {"file_path": "app.py"})])
        out = self.hook("stop", {"hook_event_name": "Stop", "transcript_path": t, "stop_hook_active": False})
        self.assertEqual(out["decision"], "block")
        t2 = self.write_transcript([("Edit", {"file_path": "app.py"}), ("Bash", {"command": "cd x && pytest -q"})])
        self.assertIsNone(self.hook("stop", {"transcript_path": t2}))

    def test_stop_gate_gives_up_after_three(self):
        self.add(TESTS_GATE)
        t = self.write_transcript([("Edit", {"file_path": "app.py"})])
        results = [self.hook("stop", {"transcript_path": t, "stop_hook_active": i > 0}) for i in range(5)]
        self.assertEqual([r is not None for r in results], [True, True, True, False, False])

    def test_bad_stdin_fails_open_broken_rules_fail_to_human(self):
        res = self.cli(self.forge, "pre", stdin="{not json")
        self.assertEqual((res.returncode, res.stdout), (0, ""))
        with open(os.path.join(self.g, "rules.json"), "w") as f:
            f.write("[{broken")
        out = self.hook("pre", {"tool_name": "Bash", "tool_input": {"command": "ls"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertIn("forge-broken", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertIsNone(self.hook("pre", {"tool_name": "Read", "tool_input": {"file_path": "x"}}))
        self.assertIsNone(self.hook("post", {"tool_name": "Bash", "tool_input": {"command": "ls"}}))
        self.assertEqual(self.ledger()[-1]["kind"], "error")

    # remove / audit / test
    def test_remove_archives_and_drops_deny(self):
        self.add(NO_FORCE)
        out = self.cli(self.forge, "remove", "no-force-push")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.rules_on_disk(), [])
        self.assertEqual(self.settings().get("permissions", {}).get("deny"), [])
        archive = readj(os.path.join(self.g, "rules.archive.json"))
        self.assertEqual(archive[0]["id"], "no-force-push")

    def test_test_command_detects_hand_edit(self):
        self.add(rule())
        rules = self.rules_on_disk()
        rules[0]["match"] = {"path": "glob:src/**"}
        writej(os.path.join(self.g, "rules.json"), rules)
        out = self.cli(self.forge, "test")
        self.assertEqual(out.returncode, 1)
        self.assertIn("TOO-BROAD", out.stdout)

    def test_audit_flags(self):
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=40)).isoformat()
        for r in (rule(), NO_FORCE, PROD_ASK, FMT):
            self.add(r)
        rules = self.rules_on_disk()
        for r in rules:
            r["created"] = old
        writej(os.path.join(self.g, "rules.json"), rules)
        for i in range(6):
            call = {"tool_name": "Bash", "tool_input": {"command": f"make migrate ENV=prod v{i}"}}
            self.hook("pre", call)
            if i < 5:
                self.hook("post", call)
        for i in range(12):
            self.hook("post", {"tool_name": "Edit", "tool_input": {"file_path": f"src/f{i}.ts"}})
        out = self.cli(self.forge, "audit", "--days", "30", "--noisy-per-day", "0.3").stdout
        block = lambda rid: out.split(rid + " [")[1].split("\n\n")[0]
        self.assertIn("SILENT", block("no-generated-edits"))
        self.assertNotIn("SILENT", block("no-force-push"))  # safety is never flagged silent
        self.assertIn("OVERRIDDEN", block("ask-prod-migrate"))
        self.assertIn("ESCALATE?", block("fmt-after-edit"))
        self.assertIn("NOISY", block("fmt-after-edit"))
        self.assertIn("e.g. Edit:", block("fmt-after-edit"))

    def test_latency(self):
        for r in (rule(), NO_NPM, NO_FORCE, PROD_ASK, FMT, TESTS_GATE):
            self.add(r)
        payload = json.dumps({"session_id": "s", "cwd": self.proj, "tool_name": "Read",
                              "tool_input": {"file_path": "x"}})
        start = time.perf_counter()
        for _ in range(20):
            self.cli(self.forge, "pre", stdin=payload)
        avg_ms = (time.perf_counter() - start) / 20 * 1000
        print(f"\n  dispatcher avg latency: {avg_ms:.1f} ms")
        self.assertLess(avg_ms, float(os.environ.get("FORGE_MAX_HOOK_MS", "400")))  # CI runners are slower


class Hardening(Sandbox):
    """Round-2 security fixes: tamper ratchet, interpreters, symlinks, ancestors, unknown writes,
    redaction, ledger rotation, ReDoS, doctor, harvest."""

    def decision(self, tool, **inp):
        out = self.hook("pre", {"tool_name": tool, "tool_input": inp})
        return out["hookSpecificOutput"]["permissionDecision"] if out else "pass"

    def test_tamper_ratchet(self):
        self.add(rule())
        g = os.path.join(self.proj, ".claude")
        cases = {
            ("Edit", os.path.join(g, "guardrails", "rules.json")): "deny",
            ("Write", ".claude/guardrails/forge.py"): "deny",
            ("Write", ".claude/settings.local.json"): "ask",
            ("Edit", os.path.join(self.home, ".claude", "settings.json")): "ask",
            ("Read", ".claude/guardrails/rules.json"): "pass",
        }
        for (tool, path), want in cases.items():
            with self.subTest(tool=tool, path=path):
                self.assertEqual(self.decision(tool, file_path=path), want)
        self.assertEqual(self.decision("Write", file_path=".claude/settings.local.json",
                                       content='{"disableAllHooks": true}'), "deny")
        bash = {
            "rm -rf .claude": "deny", "rm -rf .claude/guardrails": "deny", "mv .claude /tmp/x": "deny",
            "echo '{\"disableAllHooks\": true}' > .claude/settings.local.json": "deny",
            "jq '.disableAllHooks=true' s.json": "deny",
            "sed -i s/deny/allow/ .claude/guardrails/rules.json": "deny",
            "python3 -c \"open('.claude/guardrails/rules.json','w').write('[]')\"": "deny",
            "cp /tmp/evil.pyc .claude/guardrails/__pycache__/forge.cpython-312.pyc": "deny",
            "git checkout -- .claude/guardrails/rules.json": "deny",
            "python3 .claude/guardrails/forge.py remove no-generated-edits": "ask",
            "echo {} > ~/.claude/settings.json": "ask",
            "jq '.permissions.allow += [\"Bash(ls:*)\"]' .claude/settings.json > /tmp/s && mv /tmp/s .claude/settings.json": "ask",
            "python3 .claude/guardrails/forge.py add /tmp/r.json": "pass",
            "python3 .claude/guardrails/forge.py test": "pass",
            "cat .claude/guardrails/rules.json": "pass",
            "rm -rf build": "pass",
        }
        for cmd, want in bash.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(self.decision("Bash", command=cmd), want)
        # deny on a user rule and ask from the tamper guard: deny wins
        self.assertEqual(self.decision("Bash", command="rm -rf src/generated ~/.claude/settings.json"), "deny")

    def test_symlinks_and_restores(self):
        self.add(rule())
        os.makedirs(os.path.join(self.proj, "src", "generated"))
        cases = {
            "ln -s src/generated innocent && echo x >> innocent/api.ts": "deny",
            "ln -sf src/generated innocent; cd innocent && touch api.ts": "deny",
            "ln -s src/api pointer && echo x >> pointer/a.ts": "pass",
            "git checkout -- src/generated/api.ts": "pass",
            "git checkout HEAD -- src/generated": "pass",
            "git restore src/generated/api.ts": "pass",
            "git restore --staged src/generated/api.ts": "pass",
            "git checkout HEAD~2 -- src/generated/api.ts": "deny",
            "git restore --source=main~1 src/generated/api.ts": "deny",
        }
        for cmd, want in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(self.decision("Bash", command=cmd), want)
        os.symlink(os.path.join(self.proj, "src", "generated"), os.path.join(self.proj, "innocent"))
        self.assertEqual(self.decision("Bash", command="rm innocent"), "pass")  # removes the link only
        self.assertEqual(self.decision("Bash", command="rm innocent/api.ts"), "deny")

    def test_malformed_rule_does_not_disable_others(self):
        self.add(rule())
        rules = self.rules_on_disk() + [{"id": "half-written"}]
        writej(os.path.join(self.g, "rules.json"), rules)
        self.assertEqual(self.decision("Edit", file_path="src/generated/a.ts"), "deny")
        self.assertIn("malformed", self.ledger()[-2]["error"])

    def test_interpreter_writes(self):
        self.add(rule())
        cases = {
            "python3 -c \"open('src/generated/api.ts','a').write('x')\"": "deny",
            "python3 -c \"import pathlib; pathlib.Path('src/generated/api.ts').write_text('x')\"": "deny",
            "node -e \"require('fs').writeFileSync('src/generated/api.ts', 'x')\"": "deny",
            "python3 - <<'EOF'\nimport os\nos.remove('src/generated/api.ts')\nEOF": "deny",
            "python3 -c \"print(open('src/generated/api.ts').read())\"": "pass",
            "node -e \"console.log(require('fs').readFileSync('src/generated/api.ts','utf8'))\"": "pass",
            "python3 tools/codegen.py": "pass",
        }
        for cmd, want in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(self.decision("Bash", command=cmd), want)

    def test_symlink_into_protected_dir(self):
        self.add(rule())
        os.makedirs(os.path.join(self.proj, "src", "generated"))
        os.symlink(os.path.join(self.proj, "src", "generated"), os.path.join(self.proj, "innocent"))
        self.assertEqual(self.decision("Write", file_path="innocent/api.ts"), "deny")
        self.assertEqual(self.decision("Bash", command="echo x >> innocent/api.ts"), "deny")
        self.assertEqual(self.decision("Bash", command="cat innocent/api.ts"), "pass")

    def test_destructive_ancestors(self):
        self.add(rule())
        cases = {"rm -rf src": "deny", "rm -rf ./src/": "deny", "mv src /tmp/old": "deny", "rm -rf .": "deny",
                 "cd src && rm -rf generated": "deny", "rm -rf src/other": "pass", "cp x.ts src": "pass",
                 "touch src": "pass", "rm -rf srcs": "pass"}
        for cmd, want in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(self.decision("Bash", command=cmd), want)

    def test_unknown_writes_opt_in(self):
        r = rule(unknown_writes="ask")
        self.assertEqual(self.add(r).returncode, 0, self.add(r).stdout)
        cases = {"git stash pop": "ask", "git apply fix.patch": "ask", "patch -p1 < fix.diff": "ask",
                 "D=generated; echo x > src/$D/a.ts": "ask", "git pull": "ask", "git checkout main": "ask",
                 "git stash list": "pass", "git status": "pass", "make codegen": "pass",
                 "git checkout -b feature": "pass", "sed -i s/a/b/ src/generated/a.ts": "deny"}
        for cmd, want in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(self.decision("Bash", command=cmd), want)
        self.assertTrue(forge.validate(rule(unknown_writes="deny")))

    def test_secrets_redacted_in_ledger(self):
        self.add(NO_NPM)
        self.hook("pre", {"tool_name": "Bash", "tool_input": {
            "command": "npm publish --token=npm_abcdef123456 && curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc' x"}})
        logged = self.ledger()[-1]["input"]
        self.assertNotIn("npm_abcdef123456", logged)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", logged)
        self.assertIn("[REDACTED]", logged)
        for s in ("key sk-proj-abcdefghijklmnop", "ghp_" + "a" * 30, "AKIAABCDEFGHIJKLMNOP", "password=hunter2"):
            with self.subTest(s=s):
                self.assertIn("[REDACTED]", forge.redact(s))
        self.assertEqual(forge.redact("git push origin main"), "git push origin main")

    def test_ledger_rotation_and_tail(self):
        p = forge.paths(self.g)
        with open(p["ledger"], "w") as f:
            f.write(("x" * 1000 + "\n") * (forge.LEDGER_ROTATE_BYTES // 1000 + 10))
        forge.ledger_append(p, {"kind": "fire", "rule": "r"})
        self.assertTrue(os.path.exists(p["ledger"].replace(".jsonl", ".1.jsonl")))
        self.assertEqual([e["rule"] for e in forge.ledger_read(p)], ["r"])

    def test_redos_rejected(self):
        errs = forge.validate(rule(tool="Bash", match={"command": "re:^(a+)+$"}))
        self.assertTrue(any("too slow" in e for e in errs), errs)
        self.assertFalse(forge.regex_is_slow(r"^git push\b.*\s(--force(?!-)|-f\b)"))

    def test_doctor(self):
        self.add(rule())
        out = self.cli(self.forge, "doctor")
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn("HEALTHY", out.stdout)
        s = self.settings()
        s["disableAllHooks"] = True
        writej(os.path.join(self.proj, ".claude", "settings.json"), s)
        out = self.cli(self.forge, "doctor")
        self.assertEqual(out.returncode, 1)
        self.assertIn("disableAllHooks", out.stdout)

    def test_harvest(self):
        tdir = os.path.join(self.tmp.name, "transcripts")
        os.makedirs(tdir)
        msgs = [("s1", "don't edit src/generated/api.ts by hand, use make codegen"),
                ("s2", "you edited src/generated/api.ts again! use make codegen"),
                ("s3", "never hand edit the generated api.ts file, run make codegen"),
                ("s3", "please add a login page"),
                ("s4", "stop using npm here")]
        for sid, text in msgs:
            with open(os.path.join(tdir, sid + ".jsonl"), "a") as f:
                f.write(json.dumps({"type": "user", "timestamp": "2026-09-20T10:00:00Z",
                                    "message": {"role": "user", "content": text}}) + "\n")
                f.write(json.dumps({"type": "user", "message": {"role": "user", "content": [
                    {"type": "tool_result", "content": "never mind"}]}}) + "\n")
        out = self.cli(self.forge, "harvest", "--transcripts", tdir).stdout
        self.assertIn("3x across 3 session(s); likely path rule", out)
        self.assertIn("make codegen", out)
        self.assertNotIn("login page", out)


class V21(Sandbox):
    """Backtest against past sessions, prompt budget, sandbox double lock."""

    def transcripts(self, sessions):
        tdir = os.path.join(self.tmp.name, "history")
        os.makedirs(tdir, exist_ok=True)
        n = 0
        for sid, calls in sessions.items():
            with open(os.path.join(tdir, sid + ".jsonl"), "w") as f:
                for name, inp in calls:
                    n += 1
                    f.write(json.dumps({"type": "assistant", "sessionId": sid, "cwd": self.proj,
                                        "timestamp": "2026-09-20T10:00:00Z", "message": {"content": [
                                            {"type": "tool_use", "id": f"t{n}", "name": name, "input": inp}]}}) + "\n")
        return tdir

    def test_backtest_replays_history(self):
        tdir = self.transcripts({
            "s1": [("Edit", {"file_path": "src/generated/api.ts"}), ("Bash", {"command": "cat src/generated/api.ts"})],
            "s2": [("Bash", {"command": "make codegen && sed -i s/a/b/ src/generated/api.ts"}),
                   ("Bash", {"command": "ls"})],
        })
        out = self.cli(self.forge, "backtest", "-", "--transcripts", tdir, stdin=json.dumps(rule())).stdout
        self.assertIn("4 past tool calls in 2 session(s)", out)
        self.assertIn("would have fired 2 time(s)", out)
        self.assertIn("writes src/generated/api.ts", out)
        self.assertIn("evidence LOW", out)  # 3 calls in the rule's area is not enough to vouch for it
        clean = self.cli(self.forge, "backtest", "-", "--transcripts", tdir, stdin=json.dumps(NO_FORCE)).stdout
        self.assertIn("evidence NONE", clean)       # no git calls at all in this history
        self.assertIn("NOT ENOUGH HISTORY", clean)
        self.assertNotIn("no false positives", clean)

    def test_backtest_dedupes_resumed_sessions_and_judges_stop_gates(self):
        calls = [("Edit", {"file_path": "app.py"})]
        tdir = self.transcripts({"s1": calls})
        with open(os.path.join(tdir, "s1.jsonl")) as f:
            copy = f.read()
        with open(os.path.join(tdir, "s1-resumed.jsonl"), "w") as f:
            f.write(copy)
        out = self.cli(self.forge, "backtest", "-", "--transcripts", tdir, stdin=json.dumps(TESTS_GATE)).stdout
        self.assertIn("1 past tool calls", out)
        self.assertIn("would have fired 1 time(s)", out)

    def test_evidence_ok_with_enough_history(self):
        tdir = self.transcripts({"s1": [("Bash", {"command": f"git push origin feature-{i}"}) for i in range(25)]})
        out = self.cli(self.forge, "backtest", "-", "--transcripts", tdir, stdin=json.dumps(NO_FORCE)).stdout
        self.assertIn("25 in this rule's area -> evidence OK", out)
        self.assertIn("no false positives in real use so far", out)

    def test_day_one_set_uses_project_config_files_and_common_work(self):
        with open(os.path.join(self.proj, "package.json"), "w") as f:
            json.dump({"scripts": {"build": "tsc && vite build", "gen": "buf generate && cp out/*.ts src/generated/"}}, f)
        with open(os.path.join(self.proj, "Makefile"), "w") as f:
            f.write("codegen:\n\tpython3 tools/codegen.py\nclean:\n\trm -rf src/generated dist\n")
        os.makedirs(os.path.join(self.proj, ".github", "workflows"))
        with open(os.path.join(self.proj, ".github", "workflows", "ci.yml"), "w") as f:
            f.write("jobs:\n  t:\n    steps:\n      - run: npm ci\n      - run: npm test\n")
        empty = os.path.join(self.tmp.name, "none")
        out = self.cli(self.forge, "backtest", "-", "--transcripts", empty, "--project-dir", self.proj,
                       stdin=json.dumps(rule())).stdout
        self.assertIn("config:package.json", out)   # cp into src/generated/ inside an npm script
        self.assertIn("config:Makefile", out)       # make clean deletes src/generated
        npm = self.cli(self.forge, "backtest", "-", "--transcripts", empty, "--project-dir", self.proj,
                       stdin=json.dumps(NO_NPM)).stdout
        self.assertIn("config:ci/ci.yml", npm)
        self.assertIn("common:frontend", npm)
        fx_out = self.cli(self.forge, "backtest", "-", "--transcripts", empty, "--project-dir", self.proj,
                          "--fixtures", stdin=json.dumps(NO_NPM)).stdout
        self.assertTrue(json.loads(fx_out)["hits_as_fixtures"][0]["tool_input"]["command"])

    def test_add_stores_evidence_in_the_rule(self):
        tdir = self.transcripts({"s1": [("Edit", {"file_path": "src/generated/api.ts"})]})
        self.assertEqual(self.cli(self.forge, "add", "-", "--transcripts", tdir, stdin=json.dumps(rule())).returncode, 0)
        ev = self.rules_on_disk()[0]["provenance"]["backtest"]
        self.assertEqual((ev["history_calls"], ev["history_hits"], ev["evidence"]), (1, 1, "LOW"))

    def test_add_reports_backtest_and_prompt_budget(self):
        tdir = self.transcripts({"s1": [("Bash", {"command": "make migrate ENV=prod"})]})
        self.assertEqual(self.add(PROD_ASK).returncode, 0)
        for i in range(3):
            self.hook("pre", {"tool_name": "Bash", "tool_input": {"command": f"make migrate ENV=prod v{i}"}})
        second = rule(id="ask-prod-deploy", **{"class": "safety"}, tool="Bash", decision="ask",
                      match={"command": "cmd:^deploy\\b.*\\bprod\\b"}, message="Confirm prod deploy.",
                      fixtures={"bad": [fx("Bash", command="deploy prod")], "good": [fx("Bash", command="deploy dev")],
                                "near_miss": [fx("Bash", command="echo deploy prod")]})
        out = self.cli(self.forge, "add", "-", "--transcripts", tdir, stdin=json.dumps(second)).stdout
        self.assertIn("Backtest of ask-prod-deploy", out)
        self.assertIn("PROMPT BUDGET: 1 other rule(s) already ask the user (3 prompts", out)
        self.assertNotIn("Backtest", self.cli(self.forge, "add", "-", "--no-backtest",
                                              stdin=json.dumps(NO_NPM)).stdout)
        audit = self.cli(self.forge, "audit", "--prompts-per-day", "0.1").stdout
        self.assertIn("Prompts in the last 7 days: 3", audit)
        self.assertIn("PROMPT FATIGUE", audit)

    def test_sandbox_lock_lifecycle(self):
        self.assertTrue(forge.validate(rule(tool="Bash", match={"command": "cmd:^x"}, sandbox=True)))
        out = self.add(rule(sandbox=True))
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn("SANDBOX LOCK", out.stdout)
        self.assertEqual(self.settings()["sandbox"]["filesystem"]["denyWrite"], ["src/generated/**"])
        doc = self.cli(self.forge, "doctor").stdout
        self.assertIn("sandbox is off", doc)
        self.cli(self.forge, "sandbox", "on")
        self.cli(self.forge, "sandbox", "exclude", "make codegen")
        sb = self.settings()["sandbox"]
        self.assertTrue(sb["enabled"])
        self.assertEqual(sb["excludedCommands"], ["make codegen"])
        self.assertIn("this machine:", self.cli(self.forge, "sandbox", "status").stdout)
        self.cli(self.forge, "remove", "no-generated-edits")
        self.assertNotIn("filesystem", self.settings()["sandbox"])
        self.assertIsInstance(forge.sandbox_capability(), tuple)

    def test_sandbox_tamper(self):
        self.add(rule(sandbox=True))
        d = lambda **inp: (self.hook("pre", {"tool_name": "Bash", "tool_input": inp}) or {}).get(
            "hookSpecificOutput", {}).get("permissionDecision", "pass")
        self.assertEqual(d(command="python3 .claude/guardrails/forge.py sandbox off"), "ask")
        self.assertEqual(d(command="python3 .claude/guardrails/forge.py sandbox exclude 'npm run build'"), "ask")
        self.assertEqual(d(command="python3 .claude/guardrails/forge.py sandbox on"), "pass")
        self.assertEqual(d(command="npm run build", dangerouslyDisableSandbox=True), "ask")
        self.assertEqual(d(command="npm run build"), "pass")


if __name__ == "__main__":
    unittest.main()
