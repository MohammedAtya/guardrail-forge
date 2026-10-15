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

    def test_stop_gate_hands_over_after_two_attempts(self):
        self.add(TESTS_GATE)
        t = self.write_transcript([("Edit", {"file_path": "app.py"})])
        results = [self.hook("stop", {"transcript_path": t, "stop_hook_active": i > 0}) for i in range(4)]
        self.assertEqual([r.get("decision") for r in results], ["block", "block", None, None])
        self.assertIn("still not done after 2 attempts", results[3]["systemMessage"])

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


# ---------------------------------------------------------------- always-rules: rules that make Claude DO something

WRITES = {"tool": "Edit|Write|MultiEdit|NotebookEdit|Bash", "match": {"path": "glob:**"}}
COMMIT = {"tool": "Bash", "match": {"command": "cmd:^git commit\\b"}}
SRC_WRITES = {"tool": "Edit|Write|MultiEdit|Bash", "match": {"path": "glob:src/**"}}
BUILD = {"tool": "Bash", "match": {"command": "cmd:^(npm run build|make app)\\b"}}


def duty(**over):
    base = {"class": "convention", "event": "Stop", "decision": "block",
            "provenance": {"said": "do a commit after every update", "date": "2026-10-14"}}
    base.update(over)
    return base


def at(entry, when):
    return {**entry, "at": f"2026-10-16T{when}:00"}


COMMIT_DUTY = duty(
    id="commit-after-update", require={"after": WRITES, "ran": COMMIT},
    message="You changed files and have not committed. Commit them with a message that says what changed.",
    fixtures={"bad": [{"transcript": [fx("Edit", file_path="app.py")]},
                      {"transcript": [fx("Edit", file_path="a.py"), fx("Bash", command="git commit -m a"),
                                      fx("Bash", command="echo x > b.txt")]}],
              "good": [{"transcript": [fx("Edit", file_path="app.py"), fx("Bash", command="git add -A && git commit -m x")]}],
              "near_miss": [{"transcript": [fx("Read", file_path="app.py"), fx("Bash", command="git status")]},
                            {"transcript": [{"user": "what does this repo do?"}]}]})

DECISION_LOG = duty(
    id="summary-after-decision",
    require={"after": [{"tool": "@user", "match": {"text": "re:(?i)\\b(let'?s go with|go with|decided|approved)\\b"}},
                       {"tool": "AskUserQuestion"}],
             "ran": {"tool": "Edit|Write|Bash", "match": {"path": "glob:**/DECISIONS.md"}}},
    message="A decision was made. Append a short summary (what, why, alternatives dropped) to DECISIONS.md.",
    provenance={"said": "write a summary every time after deciding a thing", "date": "2026-10-14"},
    fixtures={"bad": [{"transcript": [{"user": "ok, let's go with option B"}, fx("Edit", file_path="app.py")]},
                      {"transcript": [fx("AskUserQuestion", questions=[{"question": "Which DB?"}])]}],
              "good": [{"transcript": [{"user": "approved"}, fx("Bash", command="cat >> DECISIONS.md <<'EOF'\nB\nEOF")]}],
              "near_miss": [{"transcript": [{"user": "what options do we have?"}]},
                            {"transcript": [{"claude": "I decided nothing yet"}]}]})

DESKTOP_BUILD = duty(
    id="desktop-build", require={"after": SRC_WRITES, "ran": BUILD, "done_when": {"newer": "~/Desktop/app.exe"},
                                 "slow_minutes": 15},
    message="The app's code changed. Rebuild it (make app) and copy the exe to ~/Desktop/app.exe.",
    provenance={"said": "rebuild the exe and send it to the desktop after every change", "date": "2026-10-16"},
    fixtures={"bad": [{"transcript": [fx("Edit", file_path="src/a.ts")], "done": False},
                      {"transcript": [at(fx("Edit", file_path="src/a.ts"), "10:00"),
                                      at(fx("Bash", command="make app && cp out/app.exe ~/Desktop/"), "10:01")],
                       "now": "2026-10-16T10:30:00", "done": False}],
              "good": [{"transcript": [fx("Edit", file_path="src/a.ts"), fx("Bash", command="make app")], "done": True},
                       {"transcript": [fx("Edit", file_path="src/a.ts"),
                                       fx("Bash", command="node node_modules/x/cli.js && cp out/app.exe ~/Desktop/")],
                        "done": True}],
              "near_miss": [{"transcript": [fx("Edit", file_path="tests/a.test.ts")], "done": False},
                            {"transcript": [at(fx("Edit", file_path="src/a.ts"), "10:00"),
                                            at(fx("Bash", command="make app"), "10:01")],
                             "now": "2026-10-16T10:05:00", "done": False}]})

COMMIT_REMINDER = duty(
    id="commit-reminder", event="PostToolUse", decision="nudge", tool="Edit|Write|MultiEdit|NotebookEdit|Bash",
    require={"after": WRITES, "ran": COMMIT},
    message="You have uncommitted changes. Commit them when this step works.",
    fixtures={"bad": [fx("Edit", file_path="b.py")],
              "good": [{"transcript": [fx("Edit", file_path="a.py")], **fx("Bash", command="git commit -am a")}],
              "near_miss": [{"transcript": [fx("Edit", file_path="a.py")], **fx("Read", file_path="a.py")}]})

TESTS_BEFORE_COMMIT = duty(
    id="tests-before-commit", event="PreToolUse", decision="deny", tool="Bash", match={"command": "cmd:^git commit\\b"},
    require={"after": {"tool": "Edit|Write|Bash", "match": {"path": "glob:**/*.py"}},
             "ran": {"tool": "Bash", "match": {"command": "cmd:^(python3? -m )?pytest\\b"}}},
    message="Python changed since the last test run. Run pytest first, then commit.",
    provenance={"said": "always run the tests before you commit", "date": "2026-10-14"},
    fixtures={"bad": [{"transcript": [fx("Edit", file_path="app.py")], **fx("Bash", command="git commit -m x")}],
              "good": [{"transcript": [fx("Edit", file_path="app.py"), fx("Bash", command="pytest -q")],
                        **fx("Bash", command="git commit -m x")}],
              "near_miss": [{"transcript": [fx("Edit", file_path="README.md")], **fx("Bash", command="git commit -m d")},
                            fx("Bash", command="git commit -m first")]})

DUTIES = [COMMIT_DUTY, DECISION_LOG, DESKTOP_BUILD, COMMIT_REMINDER, TESTS_BEFORE_COMMIT]


def ev(name, when=None, **inp):
    return (name, inp, dt.datetime(2026, 10, 16, *when) if when else None)


def said(text, when=None):
    return ("@user", {"text": text}, dt.datetime(2026, 10, 16, *when) if when else None)


class Duties(unittest.TestCase):
    def test_valid_and_green_together(self):
        for r in DUTIES:
            self.assertEqual(forge.validate(r), [], r["id"])
        checks, fails = forge.run_suite([rule(), NO_NPM, NO_FORCE, PROD_ASK, FMT, TESTS_GATE] + DUTIES)
        self.assertEqual(fails, [])  # end-of-reply always-rules (tests, commit, build) do not conflict
        self.assertGreaterEqual(checks, 40)

    def test_rejections(self):
        req = DESKTOP_BUILD["require"]
        bad = {
            "no-ran": duty(id="x1", require={"after": WRITES}, message="m", fixtures=COMMIT_DUTY["fixtures"]),
            "no-trigger": duty(id="x2", require={"ran": COMMIT}, message="m", fixtures=COMMIT_DUTY["fixtures"]),
            "time-at": {**COMMIT_DUTY, "require": {**COMMIT_DUTY["require"], "at": "18:00"}},
            "time-within": {**COMMIT_DUTY, "require": {**COMMIT_DUTY["require"], "within_minutes": 30}},
            "unknown-field": {**COMMIT_DUTY, "require": {**COMMIT_DUTY["require"], "every": 3}},
            "after-type": {**COMMIT_DUTY, "require": {"after": "Edit", "ran": COMMIT}},
            "done-both": {**DESKTOP_BUILD, "require": {**req, "done_when": {"newer": "a", "command": "true"}}},
            "done-none": {**DESKTOP_BUILD, "require": {**req, "done_when": {}}},
            "done-timeout": {**DESKTOP_BUILD, "require": {**req, "done_when": {"command": "true", "timeout": 60}}},
            "slow-without-result": {**COMMIT_DUTY, "require": {**COMMIT_DUTY["require"], "slow_minutes": 5}},
            "slow-type": {**DESKTOP_BUILD, "require": {**req, "slow_minutes": "15"}},
            "post-needs-after": {**COMMIT_REMINDER, "require": {"ran": COMMIT}},
            "unknown-writes": {**TESTS_BEFORE_COMMIT, "unknown_writes": "ask"},
            "pre-needs-match": {**TESTS_BEFORE_COMMIT, "match": {}},
        }
        for name, r in bad.items():
            with self.subTest(name=name):
                self.assertTrue(forge.validate(r))
        self.assertIn("/schedule", " ".join(forge.validate(bad["time-at"])))

    def test_message_names_the_trigger(self):
        _, out = forge.evaluate([DECISION_LOG], "Stop", forge.fixture_payload(DECISION_LOG,
                                                                               DECISION_LOG["fixtures"]["bad"][0]))
        self.assertIn("Due since: @user: ok, let's go with option B", out["reason"])

    def test_result_check_accepts_any_way_and_catches_failures(self):
        st = lambda events, ok, now=None: forge.duty_state(DESKTOP_BUILD, events, "/p", now, forge.fixed_check(ok))
        edit = ev("Edit", (10, 0), file_path="src/a.ts")
        workaround = ev("Bash", (10, 1), command="node cli.js && cp out/app.exe ~/Desktop/")
        self.assertEqual(st([edit, workaround], True)["status"], "done")   # not the usual command, still done
        self.assertEqual(st([edit, workaround], False)["status"], "due")
        build = ev("Bash", (10, 1), command="make app && cp out/app.exe ~/Desktop/")
        early, late = dt.datetime(2026, 10, 16, 10, 5), dt.datetime(2026, 10, 16, 10, 30)
        self.assertEqual(st([edit, build], False, early)["status"], "pending")  # slow: still building
        failed = st([edit, build], False, late)
        self.assertEqual((failed["status"], failed["failed"]), ("due", True))
        retry = ev("Bash", (10, 29), command="make app")
        self.assertEqual(st([edit, build, retry], False, late)["status"], "pending")  # the retry restarts the clock
        self.assertEqual(st([], False)["status"], "idle")

    def test_the_task_never_retriggers_itself(self):
        r = duty(id="docs-after-change", require={"after": WRITES, "ran": {"tool": "Edit", "match": {"path": "glob:README.md"}},
                                                  "done_when": {"newer": "site/index.html"}},
                 message="m", fixtures={})
        events = [ev("Edit", file_path="app.py"), ev("Edit", file_path="README.md"),
                  ev("Bash", command="mkdocs build -o site/index.html")]  # writing its own result
        self.assertEqual(forge.duty_state(r, events, "/p")["status"], "done")

    def test_user_controls(self):
        st = lambda *events: forge.duty_state(COMMIT_DUTY, list(events), "/p")
        edit = ev("Edit", file_path="a.py")
        self.assertEqual(st(edit, said("/always skip commit-after-update"))["status"], "idle")
        self.assertEqual(st(edit, said("/guardrail-forge:always skip"))["notes"], [("skip", 1)])
        self.assertEqual(st(edit, said("/always skip another-rule"))["status"], "due")
        self.assertEqual(st(edit, said("not now"))["status"], "idle")                    # plain words
        self.assertEqual(st(edit, said("skip it this time, thanks"))["status"], "idle")
        self.assertEqual(st(edit, ("@claude", {"text": "let's skip the commit"}, None))["status"], "due")
        self.assertEqual(st(edit, said("we should skip the header row when parsing the csv file, "
                                       "and also handle empty lines properly"))["status"], "due")  # long: not a command
        self.assertEqual(st(said("skip"), edit)["status"], "due")   # a skip before the change skips nothing
        paused = st(said("/always pause"), edit)
        self.assertEqual((paused["status"], paused["notes"]), ("paused", [("pause", 0)]))
        self.assertEqual(st(said("pause"), edit, said("resume"))["status"], "due")
        self.assertEqual(st(said("unpause"), edit)["notes"], [])     # nothing was paused

    def test_attempts_then_handoff_and_confirmation(self):
        payload = {"_calls": [("Edit", {"file_path": "src/a.ts"}, None)], "_result": False, "cwd": "/p"}
        memo = lambda **kw: {**{k: (dict() if k == "attempts" else set()) for k in forge.NO_MEMO}, **kw}
        key = forge.due_key(("Edit", {"file_path": "src/a.ts"}, None))
        fired, out = forge.evaluate([DESKTOP_BUILD], "Stop", payload, memo=memo())
        self.assertEqual(out["decision"], "block")
        self.assertIn("background", out["reason"])
        self.assertNotIn("last attempt", out["reason"])
        _, out = forge.evaluate([DESKTOP_BUILD], "Stop", payload, memo=memo(attempts={("desktop-build", key): 1}))
        self.assertIn("last attempt", out["reason"])
        _, out = forge.evaluate([DESKTOP_BUILD], "Stop", payload, memo=memo(attempts={("desktop-build", key): 2}))
        self.assertNotIn("decision", out)                       # handed over: no more blocking
        self.assertIn("still not done after 2 attempts", out["systemMessage"])
        done = {**payload, "_result": True}
        _, out = forge.evaluate([DESKTOP_BUILD], "Stop", done, memo=memo())
        self.assertTrue(out["systemMessage"].startswith("✓ always-rule desktop-build: done"))
        self.assertEqual(out["_log"][0]["kind"], "done")
        self.assertIsNone(forge.evaluate([DESKTOP_BUILD], "Stop", done,
                                         memo=memo(confirmed={("desktop-build", key)}))[1])  # confirmed once
        memo2 = forge.duty_memo([{"kind": "fire", "event": "Stop", "rule": "r", "due": "k", "session": "s"},
                                 {"kind": "fire", "event": "Stop", "rule": "r", "due": "k", "session": "s"},
                                 {"kind": "done", "rule": "r", "key": "k", "session": "s"},
                                 {"kind": "fire", "event": "Stop", "rule": "r", "due": "k", "session": "other"}], "s")
        self.assertEqual(memo2["attempts"][("r", "k")], 0)    # a confirmed batch starts its attempts afresh

    def test_short_yes_counts_only_as_a_reply_to_a_proposal(self):
        approve = {"tool": "@user", "match": {"text": "re:(?i)^\\W*(yes|ok|go ahead|do it|نعم|تمام)\\b"},
                   "replying_to": "re:(?i)\\?\\s*$|\\b(shall i|want me to|i propose)\\b"}
        r = duty(id="pdf-after-decision", require={"after": approve, "ran": {"tool": "Bash", "match": {"command": "cmd:^pandoc\\b"}}},
                 message="Rebuild plan.pdf.", fixtures={})
        self.assertEqual(forge.validate({**r, "fixtures": COMMIT_DUTY["fixtures"]}), [])
        claude = lambda t: ("@claude", {"text": t}, None)
        st = lambda *events: forge.duty_state(r, list(events), "/p")["status"]
        self.assertEqual(st(claude("Shall I switch the report to A4?"), said("yes")), "due")
        self.assertEqual(st(claude("Want me to add a chart? I can."), said("تمام")), "due")
        self.assertEqual(st(claude("Done, the tests pass."), said("ok")), "idle")      # not a proposal
        self.assertEqual(st(said("yes")), "idle")                                       # nothing proposed
        self.assertTrue(forge.validate({**r, "require": {**r["require"], "after": {**approve, "replying_to": "\\?"}}}))

    def test_duty_conflicts_with_a_rule_that_blocks_its_action(self):
        no_commit = rule(id="no-commit", tool="Bash", match={"command": "cmd:^git commit\\b"}, message="never commit",
                         fixtures={"bad": [fx("Bash", command="git commit -m x")], "good": [fx("Bash", command="git status")],
                                   "near_miss": [fx("Bash", command="echo git commit")]})
        fails = forge.run_suite([COMMIT_DUTY, no_commit])[1]
        self.assertTrue(any("which no-commit blocks" in f for f in fails), fails)

    def test_two_rules_that_trigger_each_other_are_refused(self):
        api, docs = {"tool": "Edit|Write", "match": {"path": "glob:api/**"}}, {"tool": "Edit|Write", "match": {"path": "glob:docs/**"}}
        docs_rule = duty(id="docs-after-api", require={"after": api, "ran": docs}, message="update docs",
                         fixtures={"bad": [{"transcript": [fx("Edit", file_path="api/a.py")]}],
                                   "good": [{"transcript": [fx("Edit", file_path="api/a.py"), fx("Edit", file_path="docs/a.md")]}],
                                   "near_miss": [{"transcript": [fx("Edit", file_path="x.py")]}]})
        api_rule = duty(id="api-after-docs", require={"after": docs, "ran": api}, message="regenerate api",
                        fixtures={"bad": [{"transcript": [fx("Edit", file_path="docs/a.md")]}],
                                  "good": [{"transcript": [fx("Edit", file_path="docs/a.md"), fx("Edit", file_path="api/a.py")]}],
                                  "near_miss": [{"transcript": [fx("Edit", file_path="x.py")]}]})
        fails = forge.run_suite([docs_rule, api_rule])[1]
        self.assertTrue(any(f.startswith("LOOP") for f in fails), fails)
        self.assertEqual(forge.run_suite([docs_rule, COMMIT_DUTY])[1], [])  # a one-way chain ends

    def test_order_rule_without_after_needs_ran_once(self):
        r = duty(id="read-contributing-first", event="PreToolUse", decision="deny", tool="Bash",
                 match={"command": "cmd:^git commit\\b"}, message="Read CONTRIBUTING.md before the first commit.",
                 require={"ran": {"tool": "Read", "match": {"file_path": "glob:**/CONTRIBUTING.md"}}},
                 fixtures={"bad": [fx("Bash", command="git commit -m x")],
                           "good": [{"transcript": [fx("Read", file_path="CONTRIBUTING.md")], **fx("Bash", command="git commit -m x")}],
                           "near_miss": [fx("Bash", command="git status")]})
        self.assertEqual(forge.validate(r), [])
        self.assertEqual(forge.run_suite([r])[1], [])

    def test_order_gate_does_not_count_the_call_itself(self):
        r = duty(id="commit-before-next-edit", event="PreToolUse", decision="deny", tool="Edit|Write",
                 match={"path": "glob:**"}, require={"after": {"tool": "Edit|Write", "match": {"path": "glob:**"}},
                                                     "ran": COMMIT},
                 message="Commit your last change before the next edit.",
                 fixtures={"bad": [{"transcript": [fx("Edit", file_path="a.py")], **fx("Edit", file_path="b.py")}],
                           "good": [{"transcript": [fx("Edit", file_path="a.py"), fx("Bash", command="git commit -am a")],
                                     **fx("Edit", file_path="b.py")}],
                           "near_miss": [fx("Edit", file_path="first.py")]})
        self.assertEqual(forge.validate(r), [])
        self.assertEqual(forge.run_suite([r])[1], [])

    def test_transcript_parsing(self):
        cmd = ("<command-message>always</command-message>\n<command-name>/always</command-name>\n"
               "<command-args>skip desktop-build</command-args>")
        self.assertEqual(forge.entry_events({"type": "user", "message": {"content": cmd}})[0][:2],
                         ("@user", {"text": "/always skip desktop-build"}))
        self.assertEqual(forge.entry_events({"type": "user", "message": {"content": "<local-command-stdout>x"}}), [])
        self.assertEqual(forge.entry_events({"type": "attachment", "attachment": {"type": "queued_command"}}), [])
        self.assertEqual(forge.local_time("2026-10-14T18:05:00"), dt.datetime(2026, 10, 14, 18, 5))
        self.assertIsNone(forge.local_time("2026-10-14T18:05:00.123Z").tzinfo)
        self.assertIsNone(forge.local_time("nope"))


class DutyHooks(Sandbox):
    def transcript(self, entries):
        path = os.path.join(self.tmp.name, "t.jsonl")
        with open(path, "w") as f:
            for e in entries:
                e = dict(e)
                ts = e.pop("at", None)
                if "user" in e:
                    line = {"type": "user", "message": {"role": "user", "content": e["user"]}}
                else:
                    line = {"type": "assistant", "message": {"role": "assistant", "content": [
                        {"type": "tool_use", "id": "x", "name": e["tool_name"], "input": e["tool_input"]}]}}
                if ts:
                    line["timestamp"] = ts
                f.write(json.dumps(line) + "\n")
        return path

    def ago(self, minutes):
        return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)).isoformat()

    def stop(self, t, again=False):
        return self.hook("stop", {"transcript_path": t, "stop_hook_active": again})

    def test_decision_summary_gate_reads_user_text(self):
        self.assertEqual(self.add(DECISION_LOG).returncode, 0)
        t = self.transcript([{"user": "great, let's go with Postgres"}, fx("Edit", file_path="db.py")])
        out = self.stop(t)
        self.assertEqual(out["decision"], "block")
        self.assertIn("DECISIONS.md", out["reason"])
        t = self.transcript([{"user": "great, let's go with Postgres"}, fx("Write", file_path="DECISIONS.md")])
        self.assertIsNone(self.stop(t))
        t = self.transcript([{"user": "<local-command-stdout>go with it</local-command-stdout>"}])  # harness markup
        self.assertIsNone(self.stop(t))

    def test_desktop_build_lifecycle(self):
        self.assertEqual(self.add(DESKTOP_BUILD).returncode, 0)
        t = self.transcript([{**fx("Edit", file_path="src/a.ts"), "at": self.ago(3)}])
        first = self.stop(t)
        self.assertEqual(first["decision"], "block")
        self.assertNotIn("last attempt", first["reason"])
        self.assertIn("last attempt", self.stop(t, again=True)["reason"])  # attempts are counted per batch
        handed = self.stop(t, again=True)
        self.assertNotIn("decision", handed)
        self.assertIn("still not done after 2 attempts (~/Desktop/app.exe does not exist)", handed["systemMessage"])
        exe = os.path.join(self.home, "Desktop", "app.exe")
        os.makedirs(os.path.dirname(exe))
        with open(exe, "w") as f:
            f.write("build")
        done = self.stop(t)
        self.assertNotIn("decision", done)
        self.assertIn("✓ always-rule desktop-build: done (app.exe updated", done["systemMessage"])
        self.assertIsNone(self.stop(t))  # confirmed once, not at every reply
        kinds = [e["kind"] for e in self.ledger() if e.get("rule") == "desktop-build"]
        self.assertEqual(kinds, ["added", "fire", "fire", "handoff", "done"])
        listing = self.cli(self.forge, "list", "--always").stdout
        self.assertIn("desktop-build", listing)
        self.assertIn("last done", listing)
        self.assertNotIn("no-generated-edits", listing)

    def test_slow_task_running_in_background_is_not_blocked(self):
        self.add(DESKTOP_BUILD)
        t = self.transcript([{**fx("Edit", file_path="src/a.ts"), "at": self.ago(3)},
                             {**fx("Bash", command="make app && cp out/app.exe ~/Desktop/"), "at": self.ago(2)}])
        self.assertIsNone(self.stop(t))  # started 2 minutes ago, allowed 15
        t = self.transcript([{**fx("Edit", file_path="src/a.ts"), "at": self.ago(40)},
                             {**fx("Bash", command="make app && cp out/app.exe ~/Desktop/"), "at": self.ago(39)}])
        out = self.stop(t)
        self.assertIn("but the result is missing", out["reason"])  # it finished long ago and produced nothing

    def test_skip_by_slash_command_is_announced_once(self):
        self.add(COMMIT_DUTY)
        cmd = ("<command-message>always</command-message>\n<command-name>/always</command-name>\n"
               "<command-args>skip</command-args>")
        t = self.transcript([fx("Edit", file_path="a.py"), {"user": cmd}])
        out = self.stop(t)
        self.assertNotIn("decision", out)
        self.assertIn("Skipped always-rule commit-after-update", out["systemMessage"])
        self.assertIsNone(self.stop(t))

    def test_order_rule_through_the_hook(self):
        self.assertEqual(self.add(TESTS_BEFORE_COMMIT).returncode, 0)
        t = self.transcript([fx("Edit", file_path="app.py"), fx("Bash", command="git commit -m x")])
        out = self.hook("pre", {"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}, "transcript_path": t})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        t = self.transcript([fx("Edit", file_path="app.py"), fx("Bash", command="pytest")])
        self.assertIsNone(self.hook("pre", {"tool_name": "Bash", "tool_input": {"command": "git commit -m x"},
                                            "transcript_path": t}))

    def test_reminder_once_per_batch(self):
        self.assertEqual(self.add(COMMIT_REMINDER).returncode, 0)
        t = self.transcript([fx("Edit", file_path="a.py")])
        call = {"tool_name": "Edit", "tool_input": {"file_path": "b.py"}, "transcript_path": t}
        self.assertIn("uncommitted", self.hook("post", call)["hookSpecificOutput"]["additionalContext"])
        self.assertIsNone(self.hook("post", call))  # already reminded about this batch

    def test_backtest_judges_each_turn(self):
        tdir = os.path.join(self.tmp.name, "history")
        os.makedirs(tdir)
        lines = [{"type": "user", "uuid": "u1", "message": {"role": "user", "content": "ok let's go with B"}},
                 {"type": "assistant", "uuid": "a1", "message": {"content": [
                     {"type": "tool_use", "id": "t1", "name": "Edit", "input": {"file_path": "b.py"}}]}},
                 {"type": "user", "uuid": "u2", "message": {"role": "user", "content": "thanks, next task"}},
                 {"type": "assistant", "uuid": "a2", "message": {"content": [
                     {"type": "tool_use", "id": "t2", "name": "Edit", "input": {"file_path": "c.py"}}]}}]
        with open(os.path.join(tdir, "s1.jsonl"), "w") as f:
            for line in lines:
                f.write(json.dumps({"sessionId": "s1", "cwd": self.proj, "timestamp": "2026-10-01T10:00:00Z", **line}) + "\n")
        out = self.cli(self.forge, "backtest", "-", "--transcripts", tdir, stdin=json.dumps(DECISION_LOG)).stdout
        self.assertIn("2 past tool calls in 1 session(s)", out)
        self.assertIn("would have fired 1 time(s)", out)
        self.assertIn("due since @user: ok let's go with B", out)
        fixtures = self.cli(self.forge, "backtest", "-", "--transcripts", tdir, "--fixtures",
                            stdin=json.dumps(DECISION_LOG)).stdout
        self.assertIn('"transcript"', fixtures)


if __name__ == "__main__":
    unittest.main()
