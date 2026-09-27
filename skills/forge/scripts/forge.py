#!/usr/bin/env python3
"""Guardrail Forge: one dispatcher for every guardrail, plus the CLI that manages them.

Stdlib only. The installed copy lives in <scope>/.claude/guardrails/forge.py (project) or
~/.claude/guardrails/forge.py (user); rules.json and ledger.jsonl sit beside it, and the
settings.json it registers in is the one in the parent directory.

Hook modes (Claude Code pipes the event JSON on stdin):
  forge.py pre | post | stop

CLI:
  forge.py install --scope project|user [--project-dir DIR]
  forge.py doctor                        installed? hooks registered? dispatcher current? suite green?
  forge.py add RULE.json|- [--dry-run]
  forge.py remove RULE_ID                loosening: the tamper guard asks the human first
  forge.py list
  forge.py test
  forge.py explain EVENT_JSON|-          which rules fire on one tool call
  forge.py split "COMMAND"               how a Bash command is normalised (cmd:) and which paths it writes (path)
  forge.py audit [--days N] [--noisy-per-day X] [--min-asks N]
  forge.py backtest RULE.json|-|--all  replay a rule over every tool call from past sessions
  forge.py sandbox status|on [--strict]|off|exclude CMD   OS-level double lock for path rules
  forge.py harvest [--project-dir DIR] [--transcripts DIR] [--min N]
                                         repeated corrections in past sessions, as rule candidates

Built in, not editable through rules.json: the tamper guard. Any change to the guardrail files
or to a Claude Code settings file asks the human, so Claude can tighten guardrails but never
quietly loosen them.
"""
import datetime as _dt
import hashlib
import json
import os
import re
import shlex
import sys

# difflib, shutil, subprocess and tempfile are imported where used: every tool call pays the
# dispatcher's startup cost, and the common path needs none of them.

HERE = os.path.dirname(os.path.abspath(__file__))
CLASSES = ("safety", "convention", "style")
DECISIONS = {"PreToolUse": ("deny", "ask"), "PostToolUse": ("nudge",), "Stop": ("block",)}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
HOOK_MARK = "guardrails/forge.py"
MAX_STOP_BLOCKS = 3
VERSION = "2.2.0"
LEDGER_TAIL_BYTES = 256 * 1024
LEDGER_ROTATE_BYTES = 5 * 1024 * 1024
MUTATING_TOOLS = re.compile(r"Edit|Write|MultiEdit|NotebookEdit|Bash")
GUARDRAIL_FILES = ("forge.py", "rules.json", "rules.archive.json", "ledger.jsonl", "ledger.1.jsonl", "corpus.json")
SETTINGS_FILES = ("settings.json", "settings.local.json")


# ---------------------------------------------------------------- storage

def paths(base=None):
    base = base or HERE
    return {
        "dir": base,
        "rules": os.path.join(base, "rules.json"),
        "archive": os.path.join(base, "rules.archive.json"),
        "ledger": os.path.join(base, "ledger.jsonl"),
        "settings": os.path.join(os.path.dirname(base), "settings.json"),
    }


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def write_json(path, data):
    import tempfile
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".forge-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def now():
    return _dt.datetime.now(_dt.timezone.utc)


def iso(t=None):
    return (t or now()).isoformat(timespec="seconds")


def ledger_append(p, entry):
    entry = {"ts": iso(), **entry}
    try:
        if os.path.getsize(p["ledger"]) > LEDGER_ROTATE_BYTES:
            os.replace(p["ledger"], p["ledger"].replace(".jsonl", ".1.jsonl"))
    except OSError:
        pass
    try:
        with open(p["ledger"], "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def ledger_read(p, tail=True):
    """Hooks read only the recent tail (fast); the audit reads everything, rotated file included."""
    files = [p["ledger"]] if tail else [p["ledger"].replace(".jsonl", ".1.jsonl"), p["ledger"]]
    out = []
    for path in files:
        try:
            with open(path, "rb") as f:
                if tail:
                    f.seek(max(0, os.path.getsize(path) - LEDGER_TAIL_BYTES))
                    f.readline() if f.tell() else None  # drop the partial first line
                for line in f:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
        except FileNotFoundError:
            pass
    return out


SECRET_RES = [
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)\S+"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password|passwd|pwd|access[_-]?key)[\"']?\s*[:=]\s*[\"']?)[^\s\"'&]+"),
    re.compile(r"\b(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}"
               r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)"),
]


def redact(text):
    for rx in SECRET_RES:
        text = rx.sub(lambda m: (m.group(1) if m.lastindex and m.group(0) != m.group(1) else "") + "[REDACTED]", text)
    return text


# ---------------------------------------------------------------- matching

def glob_to_re(pattern):
    tail = ""
    if pattern.endswith("/**"):  # "dir/**" also covers "dir" itself (rm -rf dir)
        pattern, tail = pattern[:-3], "(?:/.*)?"
    i, out = 0, []
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    flags = re.I if sys.platform in ("darwin", "win32") else 0  # case-insensitive filesystems
    return re.compile("^" + "".join(out) + tail + "$", flags)


WRAPPERS = {"sudo", "env", "command", "exec", "nohup", "time", "nice", "builtin", "doas"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "|&", ";;", "\n"}
GIT_OPTS_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}


def unquoted_newlines_to_semicolons(cmd):
    """A newline ends a command only outside quotes: a multi-line commit message is one argument."""
    out, quote, i = [], None, 0
    while i < len(cmd):
        c = cmd[i]
        if c == "\\" and quote != "'" and i + 1 < len(cmd):
            out.append(cmd[i:i + 2])
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "\n":
            c = " ; "
        out.append(c)
        i += 1
    return "".join(out)


def split_command(cmd, depth=0):
    """Normalise a shell command into its simple commands, one string each (see command_segments)."""
    return [" ".join(words) for words in command_segments(cmd, depth)]


def command_segments(cmd, depth=0):
    """Normalise a shell command into its simple commands, each a list of words.

    Handles && || ; | & and newlines, subshells, $(..) and backticks, `bash -c "..."`,
    `eval`, leading VAR=value assignments, wrappers like sudo/env/timeout, and git's
    global options (`git -C dir push` -> `git push`). Quotes are removed, so a pattern
    anchored with ^ sees `echo "git push"` as an echo, not a push.
    """
    if depth > 4 or not cmd:
        return []
    cmd = strip_heredocs(cmd)
    cmd = re.sub(r"&>(>?)", r">\1", cmd).replace(">|", ">")  # &> &>> >| are redirects, not & or |
    cmd = re.sub(r"\$\(\s*pwd\s*\)|`\s*pwd\s*`", "$PWD", cmd)  # keep $(pwd)/x as one word
    found = []
    for inner in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", cmd):
        found += command_segments(inner[0] or inner[1], depth + 1)
    try:
        lex = shlex.shlex(unquoted_newlines_to_semicolons(cmd), posix=True, punctuation_chars=";&|()")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        tokens = re.split(r"\s+", cmd.strip())
    segment = []
    for tok in tokens + [";"]:
        if tok in SEPARATORS:
            if segment:
                found += normalise_segment(segment, depth)
            segment = []
        else:
            segment.append(tok)
    return found


HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?\n[ \t]*\2[ \t]*(?=\n|$)", re.S)


def strip_heredocs(cmd):
    """Drop heredoc bodies: text written to a file is data, not commands."""
    return HEREDOC_RE.sub(lambda m: "<<" + m.group(2), cmd)


WRITE_ALL_ARGS = {"tee", "touch", "truncate", "mkdir"}
DESTROY_ALL_ARGS = {"rm", "unlink", "shred", "rmdir"}
WRITE_LAST_ARG = {"cp", "install", "ln", "rsync"}
INTERPRETERS = re.compile(r"^(python[0-9.]*|node|nodejs|deno|bun|ruby|perl|php|Rscript|osascript)$")
CODE_FLAGS = {"-c", "-e", "-E", "-r", "--eval", "-p", "--print", "eval", "-"}
WRITE_VERBS = re.compile(
    r"open\s*\([^,)]*,\s*(mode\s*=\s*)?['\"][rbt]*[wax+][rwxabt+]*['\"]|mode\s*=\s*['\"][rbt]*[wax+]"
    r"|\.write(_text|_bytes)?\s*\(|writeFile|appendFile|createWriteStream"
    r"|\b(os|fs|shutil|FileUtils|File)\.(remove|unlink|rename|replace|rm|rmSync|rmdir|move|copy\w*|write\w*|delete)"
    r"|rmtree|\.unlink\s*\(|\.rename\s*\(|\bunlink\s*\(|\brename\s*\(|file_put_contents|open\s*\(\s*\w+\s*,\s*['\"]\+?[>|]"
    r"|IO\.write|system\s*\(|subprocess|child_process|exec(Sync)?\s*\(")
LITERALS = [re.compile(r"'([^'\n]{1,300})'"), re.compile(r'"([^"\n]{1,300})"')]


FORMATTERS = {  # tool -> flags that make it rewrite its path arguments in place (None = always)
    "prettier": {"--write", "-w"}, "eslint": {"--fix"}, "stylelint": {"--fix"}, "biome": {"--write", "--apply"},
    "black": None, "isort": None, "autopep8": {"-i", "--in-place"}, "yapf": {"-i", "--in-place"},
    "ruff": {"format", "--fix"}, "gofmt": {"-w"}, "goimports": {"-w"}, "rustfmt": None,
    "clang-format": {"-i"}, "shfmt": {"-w"}, "dprint": {"fmt"}, "standard": {"--fix"}, "rubocop": {"-a", "-A"},
}
OUTPUT_FLAG = re.compile(r"(?i)^--?(out(put)?([-_]?(file|dir|path|document|directory))?|outdir|dest(ination)?(-dir)?"
                         r"|target(-dir)?|build-dir|prefix)$")
SHORT_O_IS_BOOLEAN = {"grep", "egrep", "fgrep", "rg", "ag", "ls", "ps", "set", "shopt", "bash", "sh", "zsh",
                      "sed", "awk", "find", "test", "[", "mount", "git", "tr", "cut", "uniq", "wc", "ssh", "scp"}


class PathValue(str):
    """A path a tool call touches; `destructive` marks rm/mv-source style removal."""
    destructive = False


Q = r"(?P<q>['\"])(?P<p>[^'\"\n]{1,300}?)(?P=q)"   # a quoted literal; the path is group "p"
WRITE_CALLS = [  # regexes whose group "p" is a path the call writes, moves onto, or deletes
    r"open\s*\(\s*" + Q + r"\s*,\s*(?:mode\s*=\s*)?['\"][rbt]*[wax+]",                       # python open(p, 'w')
    r"Path\s*\(\s*" + Q + r"\s*\)\s*\.\s*(?:write_text|write_bytes|unlink|touch|rename|replace|rmdir|mkdir|open\s*\(\s*['\"][rbt]*[wax+])",
    r"\b(?:os|fs|FileUtils|File|IO)\.\w*(?:write|append|remove|unlink|rm|rmdir|rename|replace|copy|move|delete|truncate)\w*\s*\(\s*" + Q,
    r"\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|unlinkSync|rmSync|truncateSync"
    r"|file_put_contents|unlink|rmtree|remove)\s*\(\s*" + Q,
    r"\bshutil\.(?:copy\w*|move)\s*\(\s*[^,]+,\s*" + Q,                                     # destination argument
    r"\b(?:renameSync|copyFile|copyFileSync)\s*\(\s*[^,]+,\s*" + Q,                               # node fs (str.replace is not a write)
    r"open\s*\(\s*\$?\w+\s*,\s*['\"]\+?(?:>>?|\|)\s*(?P<p>[^'\"\n]{1,300}?)['\"]",                # perl 2-arg open(F, ">p")
    r"open\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*['\"]\+?>>?['\"]\s*,\s*" + Q,                           # perl 3-arg
]
WRITE_CALLS = [re.compile(x) for x in WRITE_CALLS]
VAR_ASSIGN = re.compile(r"\b(?P<v>[A-Za-z_]\w*)\s*=\s*(?:Path\s*\(\s*)?" + Q)
VAR_WRITE = (r"(?:\b{v}\s*\.\s*(?:write_text|write_bytes|unlink|touch|rename|replace|rmdir|open\s*\(\s*['\"][rbt]*[wax+])"
             r"|open\s*\(\s*{v}\s*,\s*(?:mode\s*=\s*)?['\"][rbt]*[wax+]"
             r"|\b(?:writeFileSync|writeFile|appendFileSync|appendFile|unlinkSync|rmSync|file_put_contents|unlink|rmtree|remove"
             r"|os\.\w*(?:remove|unlink|rename|replace)\w*|fs\.\w*(?:write|append|unlink|rm|rename)\w*)\s*\(\s*{v}\b"
             r"|\bshutil\.(?:copy\w*|move)\s*\([^,]+,\s*{v}\b)")


def interpreter_targets(code):
    """Paths inline code writes: literals passed to a write/delete call, directly or via a variable
    (p = Path('x'); p.write_text(...)). Paths it merely mentions or reads are not counted."""
    if not WRITE_VERBS.search(code):
        return []
    found = [m.group("p").lstrip("<>+|& ") for rx in WRITE_CALLS for m in rx.finditer(code)]
    for m in VAR_ASSIGN.finditer(code):
        if re.search(VAR_WRITE.format(v=re.escape(m.group("v"))), code):
            found.append(m.group("p"))
    return [p for p in dict.fromkeys(found) if p.strip()]


def interpreter_computes_paths(code):
    """Writes happen but no written path could be read off the code: the target is computed."""
    return bool(WRITE_VERBS.search(code)) and not interpreter_targets(code)


def bash_writes(cmd):
    """Best-effort [(path, destructive)] a shell command writes, moves, or deletes."""
    out = []
    for m in HEREDOC_RE.finditer(cmd):  # `python3 - <<EOF ... EOF`: the body is code
        line = cmd[cmd.rfind("\n", 0, m.start()) + 1:m.start()]
        if any(INTERPRETERS.match(os.path.basename(w)) for w in line.split()):
            out += [(t, False) for t in interpreter_targets(m.group(0))]
    for segment in re.split(r"[;&|(\n]", strip_heredocs(cmd)):  # leading VAR=path assignments only
        words = segment.split()
        while words and words[0] in ("env", "export"):
            words = words[1:]
        assigned = []
        for i, w in enumerate(words):
            m = re.match(r"^[A-Za-z_]\w*=(['\"]?)(\S*/\S*?)\1$", w)
            if not m:
                if not re.match(r"^[A-Za-z_]\w*=", w):  # a command follows: VAR=x cmd (a bare G=x sets nothing up)
                    out += [(a, False) for a in assigned]
                break
            assigned.append(m.group(2))
    vdir, links = "", {}
    for words in command_segments(cmd):
        sub = " ".join(words)
        found = []
        if words[0] in ("cd", "pushd") and len(words) == 2:
            vdir = os.path.normpath(os.path.join(vdir, words[1]))
            continue
        for i, w in enumerate(words):  # a quoted "a > b" stays one word, so it is never taken for a redirect
            if re.fullmatch(r"(\d|&)?>>?", w) and i + 1 < len(words):
                found.append((words[i + 1], False))
            elif re.match(r"^(\d|&)?>>?[^>&]", w):
                found.append((re.sub(r"^(\d|&)?>>?", "", w), False))
            elif w.startswith("of=") and words[0] == "dd":
                found.append((w[3:], False))
        if words:
            while words and words[0] in ("npx", "bunx", "pnpx"):  # package runners: look at the tool they run
                words = [w for w in words[1:] if w not in ("--yes", "-y", "--no-install")]
            if len(words) > 2 and words[0] in ("pnpm", "yarn", "npm") and words[1] in ("dlx", "exec"):
                words = words[2:] if words[2] != "--" else words[3:]
            if not words:
                continue
            head, args = words[0], [w for w in words[1:] if not w.startswith("-") and ">" not in w]
            if head in WRITE_ALL_ARGS:
                found += [(a, False) for a in args]
            elif head in DESTROY_ALL_ARGS:
                found += [(a, True) for a in args]
            elif head == "mv" and len(args) >= 2:  # sources vanish, destination is written
                found += [(a, True) for a in args[:-1]] + [(args[-1], False)]
            elif head in WRITE_LAST_ARG and len(args) >= 2:
                found.append((args[-1], False))
            elif head == "git" and len(words) > 1 and words[1] in ("checkout", "restore"):
                # restoring a directory rewrites everything under it: mark as covering descendants.
                # Back to HEAD/index ("restore") is an undo, not an edit: path rules allow it, tamper does not.
                if words[1] == "checkout":
                    split = words.index("--") if "--" in words else None
                    revs = [w for w in words[2:split] if not w.startswith("-")] if split else []
                    kind = "restore" if revs in ([], ["HEAD"]) else True
                    found += [(w, kind) for w in words[split + 1:]] if split else []
                else:
                    src = [w.split("=", 1)[1] for w in words if w.startswith("--source=")]
                    src += [words[i + 1] for i, w in enumerate(words[:-1]) if w in ("-s", "--source")]
                    kind = "restore" if src in ([], ["HEAD"]) else True
                    staged_only = ("--staged" in words or "-S" in words) and not ({"--worktree", "-W"} & set(words))
                    if not staged_only:
                        found += [(w, kind) for w in args[1:] if w not in src]
            elif head == "git" and len(words) > 2 and words[1] == "rm":
                found += [(a, True) for a in args[1:]]
            elif head == "git" and len(words) > 2 and words[1] == "mv" and len(args) >= 3:
                found += [(a, True) for a in args[1:-1]] + [(args[-1], False)]
            elif head == "find" and find_writes(words):
                roots = []
                for w in words[1:]:
                    if w.startswith("-") or w in ("(", "!"):
                        break
                    roots.append(w)
                found += [(r, True) for r in roots or ["."]]
            elif head in ("curl", "wget"):
                for i, w in enumerate(words[:-1]):
                    if w in ("-o", "--output", "-O", "--output-document"):
                        if not (head == "curl" and w == "-O"):
                            found.append((words[i + 1], False))
                found += [(w.split("=", 1)[1], False) for w in words if re.match(r"^--output(-document)?=", w)]
            elif head == "tar" and re.search(r"(^|\s)(-\w*x|--extract|x\w*\s)", " ".join(words[1:]) + " "):
                for i, w in enumerate(words[:-1]):
                    if w in ("-C", "--directory"):
                        found.append((words[i + 1], True))
                found += [(w.split("=", 1)[1], True) for w in words if w.startswith("--directory=")]
            elif head == "unzip" and "-d" in words[:-1]:
                found.append((words[words.index("-d") + 1], True))
            elif head in ("sed", "perl") and any(re.match(r"^-\w*i", w) or w.startswith("--in-place")
                                                 for w in words[1:]):
                explicit_script = any(w in ("-e", "-f") for w in words[1:])
                found += [(a, False) for a in (args if explicit_script else args[1:])]
            if head in FORMATTERS and (FORMATTERS[head] is None or FORMATTERS[head] & set(words[1:])):
                paths_ = [a for a in args if a not in (FORMATTERS[head] or ())]
                found += [(a, True) for a in paths_]  # a dir or glob argument rewrites everything under it
            if head == "sqlite3":
                found += [(words[i + 1], False) for i, w in enumerate(words[:-1]) if w in (".output", ".once")]
                found += [(m, False) for w in words for m in re.findall(r"^\.(?:output|once)\s+(\S+)", w)]
            if head in ("docker", "podman"):
                for i, w in enumerate(words[:-1]):
                    if w in ("-v", "--volume"):
                        spec = words[i + 1].split(":")
                        if len(spec) >= 2 and "ro" not in spec[2:]:
                            found.append((spec[0], True))
                    if w == "--mount" and "readonly" not in words[i + 1]:
                        found += [(m, True) for m in re.findall(r"(?:source|src)=([^,]+)", words[i + 1])]
            for i, w in enumerate(words[1:], 1):  # generic output flags: tsc --outFile, webpack --output-path, -o
                flag, eq, val = w.partition("=")
                if OUTPUT_FLAG.match(flag) or (flag == "-o" and head not in SHORT_O_IS_BOOLEAN):
                    val = val if eq else (words[i + 1] if i + 1 < len(words) else "")
                    if val and not val.startswith("-") and ("/" in val or "." in val or flag != "--target"):
                        found.append((val, bool(re.search(r"dir|path|prefix", flag, re.I))))
            if INTERPRETERS.match(head) and any(w in CODE_FLAGS for w in words[1:]):
                # the normalised form lost the inner quotes; read the literals from the raw command
                found += [(t, False) for t in interpreter_targets(strip_heredocs(cmd))]
        for t, destructive in found:
            if destructive and re.search(r"[*?\[]", t):  # `prettier --write "**/*.ts"` covers its base dir
                t = glob_prefix(t) or "."
            if t and not t.startswith("&") and t != "/dev/null":
                path = t if os.path.isabs(t) or not vdir else os.path.normpath(os.path.join(vdir, t))
                for link, dest in links.items():  # a link made earlier in this command, not on disk yet
                    if path == link or path.startswith(link + "/"):
                        path = os.path.normpath(dest + path[len(link):])
                out.append((path, destructive))
        if words and words[0] == "ln" and any(re.match(r"^-\w*s", w) or w == "--symbolic" for w in words[1:]):
            largs = [w for w in words[1:] if not w.startswith("-")]
            if len(largs) >= 2:
                link = os.path.normpath(os.path.join(vdir, largs[-1]))
                dest = largs[0] if os.path.isabs(largs[0]) else os.path.join(os.path.dirname(link), largs[0])
                links[link] = os.path.normpath(dest)
    return out


FIND_WRITERS = WRITE_ALL_ARGS | DESTROY_ALL_ARGS | set(WRITE_LAST_ARG) | {"mv", "sed", "perl", "chmod", "chown", "dd",
                                                                        "truncate", "git"} | SHELLS


def find_writes(words):
    """find deletes (-delete), writes a list file (-fprint), or -exec/-ok's a command that writes."""
    for i, w in enumerate(words):
        if w == "-delete" or w.startswith("-fprint") or w.startswith("-fls"):
            return True
        if w in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(words):
            run = os.path.basename(words[i + 1])
            if run in FIND_WRITERS or INTERPRETERS.match(run) or run in FORMATTERS:
                return True
    return False


def bash_write_targets(cmd):
    return [t for t, _ in bash_writes(cmd)]


UNKNOWN_GIT = {"stash", "apply", "am", "merge", "pull", "rebase", "cherry-pick", "revert", "switch", "clean"}


def bash_unknown_writes(cmd):
    """Reasons this command may write files whose names cannot be read off the command line."""
    reasons = []
    for sub in split_command(cmd):
        words = sub.split()
        if not words:
            continue
        if words[0] == "git" and len(words) > 1:
            verb = words[1]
            if (verb in UNKNOWN_GIT and not (verb == "stash" and (len(words) == 2 or words[2] in ("list", "show")))) \
                    or (verb == "reset" and "--hard" in words) \
                    or (verb == "checkout" and "--" not in words and not {"-b", "-B"} & set(words)):
                reasons.append(f"`{sub[:60]}` rewrites working-tree files it does not name")
        elif words[0] in ("patch", "tar", "unzip"):
            reasons.append(f"`{sub[:60]}` writes files it does not name")
        elif words[0] in ("npm", "pnpm", "yarn", "bun", "npx") and len(words) > 1 and \
                words[1] in ("run", "run-script", "exec", "dlx", "x") or words[0] in ("npx",):
            reasons.append(f"`{sub[:60]}` runs a package script whose writes cannot be seen")
        elif re.search(r"\.(sh|bash|zsh|py|rb|pl|js|mjs|cjs|ts|php)$", words[0]) \
                or (words[0] in SHELLS and len(words) > 1 and not words[1].startswith("-")):
            reasons.append(f"`{sub[:60]}` runs a script file whose writes cannot be seen")
        elif INTERPRETERS.match(words[0]) and len(words) > 1 and not words[1].startswith("-") \
                and not re.search(r"\b(unittest|pytest|--version)\b", sub):
            reasons.append(f"`{sub[:60]}` runs a script whose writes cannot be seen")
    code = strip_heredocs(cmd)
    if any(INTERPRETERS.match(w.split()[0]) for w in split_command(cmd) if w.split()) \
            and interpreter_computes_paths(code):
        reasons.append("inline code writes to a path it computes at runtime")
    for t in bash_write_targets(cmd):
        if re.search(r"[$`*?{]", re.sub(r"\$\{?(PWD|HOME|CLAUDE_PROJECT_DIR)\}?", "", t)):
            reasons.append(f"write target `{t}` is only known after shell expansion")
    return reasons


def normalise_segment(tokens, depth):
    t = list(tokens)
    while t:
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t[0]):
            t.pop(0)
        elif t[0] in WRAPPERS:
            t.pop(0)
            while t and (t[0].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t[0])):
                t.pop(0)
        elif t[0] == "timeout":
            t.pop(0)
            while t and (t[0].startswith("-") or re.match(r"^[0-9.]+[smhd]?$", t[0])):
                t.pop(0)
        elif t[0] == "xargs":
            t.pop(0)
            while t and t[0].startswith("-"):
                t.pop(0)
        else:
            break
    if not t:
        return []
    head = os.path.basename(t[0])
    if head in SHELLS:
        for i, tok in enumerate(t[1:], 1):
            if re.match(r"^-[a-z]*c[a-z]*$", tok) and i + 1 < len(t):
                return command_segments(t[i + 1], depth + 1)
    if head == "eval" and len(t) > 1:
        return command_segments(" ".join(t[1:]), depth + 1)
    if head == "git":
        rest, i = ["git"], 1
        while i < len(t) and t[i].startswith("-"):
            opt = t[i].split("=", 1)[0]
            i += 2 if (opt in GIT_OPTS_WITH_ARG and "=" not in t[i]) else 1
        t = rest + t[i:]
    else:
        t = [head] + t[1:]
    return [t]


def field_values(tool_input, field):
    if field == "path":
        keys = ("file_path", "path", "notebook_path")
        vals = [PathValue(tool_input[k]) for k in keys if isinstance(tool_input.get(k), str)]
        if isinstance(tool_input.get("command"), str):
            for t, destructive in bash_writes(tool_input["command"]):
                v = PathValue(t)
                v.destructive = bool(destructive)
                v.head_restore = destructive == "restore"
                vals.append(v)
        return vals
    v = tool_input.get(field)
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):  # e.g. MultiEdit edits -> match any new_string
        vals = []
        for item in v:
            if isinstance(item, dict):
                vals += [s for s in item.values() if isinstance(s, str)]
            elif isinstance(item, str):
                vals.append(item)
        return vals
    return []


def expand(value, cwd=None):
    """~, $PWD, $CLAUDE_PROJECT_DIR and $HOME-style variables as the shell would expand them."""
    if cwd:
        value = re.sub(r"\$\{?PWD\}?", lambda m: cwd, value)
    root = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    if root:
        value = re.sub(r"\$\{?CLAUDE_PROJECT_DIR\}?", lambda m: root, value)
    return os.path.expanduser(os.path.expandvars(value))


def path_candidates(value, cwd):
    """The path as written, normalised, and relative to the project root.

    Relative paths are resolved against the hook's cwd, which follows the shell after a
    `cd` in an earlier command, so `cd src/generated` then `echo x >> api.ts` still resolves.
    """
    cands = [value, os.path.normpath(value)]
    removes_link = getattr(value, "destructive", False) and not getattr(value, "head_restore", False)
    value = expand(value, cwd)
    root = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    if cwd:
        absolute = os.path.normpath(value if os.path.isabs(value) else os.path.join(cwd, value))
        real = (os.path.join(os.path.realpath(os.path.dirname(absolute)), os.path.basename(absolute))
                if removes_link else os.path.realpath(absolute))  # rm on a symlink removes only the link
        for base, target in ((root, absolute), (os.path.realpath(root), real)):
            rel = os.path.relpath(target, base)  # second pass follows symlinks to where the write lands
            if not rel.startswith(".."):
                cands.append(rel)
            elif target != absolute:
                cands.append(target)
    return list(dict.fromkeys(cands))


def glob_prefix(body):
    """Literal directory prefix of a glob: `src/generated/**` -> `src/generated`, `**/*.env` -> ``."""
    if not re.search(r"[*?\[]", body):
        return body.rstrip("/")
    literal = re.split(r"[*?\[]", body, maxsplit=1)[0]
    return literal.rsplit("/", 1)[0] if "/" in literal else ""


def is_ancestor(candidate, prefix):
    c = candidate.rstrip("/")
    if not prefix or os.path.isabs(c) != os.path.isabs(prefix):
        return False
    return c in (".", "") or prefix == c or prefix.startswith(c + "/")


def pattern_matches(pattern, values, cwd):
    kind, _, body = pattern.partition(":")
    if kind == "glob":
        rx = glob_to_re(body)
        for v in values:
            if getattr(v, "head_restore", False):  # `git checkout -- f` undoes edits back to the committed file
                continue
            cands = path_candidates(v, cwd)
            if any(rx.match(c) for c in cands):
                return True
            # rm -rf src / mv src elsewhere destroys src/generated/** without naming it
            if getattr(v, "destructive", False) and any(is_ancestor(c, glob_prefix(body)) for c in cands):
                return True
        return False
    if kind == "re":
        rx = re.compile(body)
        return any(rx.search(v) for v in values)
    if kind == "cmd":
        rx = re.compile(body)
        return any(rx.search(sub) for v in values for sub in split_command(v))
    raise ValueError(f"unknown pattern kind in {pattern!r} (use glob:, re:, or cmd:)")


def call_matches(spec, tool_name, tool_input, cwd):
    """spec = {tool, match, unless}. All `match` fields must hit; any `unless` field hit vetoes."""
    if not re.fullmatch(spec.get("tool", ".*"), tool_name or ""):
        return False
    for field, pat in (spec.get("match") or {}).items():
        if not pattern_matches(pat, field_values(tool_input, field), cwd):
            return False
    for field, pat in (spec.get("unless") or {}).items():
        if pattern_matches(pat, field_values(tool_input, field), cwd):
            return False
    return True


def summarise(tool_name, tool_input):
    for k in ("command", "file_path", "path", "notebook_path", "url", "pattern"):
        if isinstance(tool_input.get(k), str):
            return redact(f"{tool_name}: {tool_input[k]}")[:200]
    return redact(f"{tool_name}: {json.dumps(tool_input, ensure_ascii=False)}")[:200]


def fingerprint(tool_name, tool_input):
    raw = json.dumps([tool_name, tool_input], sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------- transcript (Stop gate)

def transcript_calls(path):
    calls = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                msg = entry.get("message") if isinstance(entry, dict) else None
                content = msg.get("content") if isinstance(msg, dict) else None
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            calls.append((block.get("name", ""), block.get("input") or {}))
    except (FileNotFoundError, TypeError):
        pass
    return calls


def stop_gate_unmet(rule, calls, cwd):
    """True when an `after` call happened and no `ran` call followed the last one."""
    req = rule["require"]
    last_after = -1
    for i, (name, inp) in enumerate(calls):
        if call_matches(req["after"], name, inp, cwd):
            last_after = i
    if last_after < 0:
        return False
    return not any(call_matches(req["ran"], n, i, cwd) for n, i in calls[last_after + 1:])


# ---------------------------------------------------------------- evaluation

def protected_files(cwd):
    """Files whose change would loosen guardrails: this scope's guardrail files and every
    Claude Code settings file that could deregister the hooks or set disableAllHooks."""
    root = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    dirs = {os.path.dirname(HERE), os.path.join(root, ".claude"), os.path.join(os.path.expanduser("~"), ".claude")}
    files = [os.path.join(HERE, f) for f in GUARDRAIL_FILES]
    files += [os.path.join(d, f) for d in dirs for f in SETTINGS_FILES]
    return {os.path.realpath(f) for f in files}


def tamper_reason(tool_name, tool_input, cwd):
    """Built-in ratchet: tightening is free, loosening asks the human. Not stored in rules.json."""
    if not MUTATING_TOOLS.fullmatch(tool_name or ""):
        return None
    guarded = protected_files(cwd)
    own = {os.path.realpath(os.path.join(HERE, f)) for f in GUARDRAIL_FILES}
    cmd = tool_input.get("command") if isinstance(tool_input.get("command"), str) else ""
    if "disableAllHooks" in cmd or "disableAllHooks" in str(tool_input.get("content", "")) \
            or "disableAllHooks" in str(tool_input.get("new_string", "")):
        return "it would set disableAllHooks, switching every guardrail off", "deny"
    for v in field_values(tool_input, "path"):
        x = expand(v, cwd)
        target = os.path.realpath(x if os.path.isabs(x) else os.path.join(cwd, x))
        if target in own or target.startswith(os.path.realpath(os.path.join(HERE, "__pycache__")) + os.sep):
            return f"it changes the guardrail file {target} directly", "deny"
        under = [g for g in guarded if g.startswith(target.rstrip("/") + "/")]
        if getattr(v, "destructive", False) and under:
            return (f"it deletes or moves {target}, which holds guardrail files", "deny") if set(under) & own \
                else (f"it deletes or moves {target}, which holds Claude Code settings", "ask")
        if target in guarded:
            return f"it changes the settings file {target}", "ask"
    if tool_input.get("dangerouslyDisableSandbox") and any(r.get("sandbox") for r in sandbox_rules_cache()):
        return "it runs outside the sandbox that locks protected paths", "ask"
    for sub in split_command(cmd):
        if re.search(r"(^|/)forge\.py\s+remove\b", sub):
            return "it removes a guardrail rule", "ask"
        if re.search(r"(^|/)forge\.py\s+sandbox\s+(off|exclude)\b", sub):
            return "it switches the sandbox lock off or exempts a command from it", "ask"
        w = sub.split()
        reverts = len(w) > 1 and w[0] == "git" and (
            (w[1] == "stash" and not (len(w) > 2 and w[2] in ("list", "show", "pop", "apply")))
            or w[1] == "clean" or (w[1] == "reset" and "--hard" in w)
            or (w[1] in ("checkout", "switch") and "--" not in w and not {"-b", "-B", "-c"} & set(w)))
        if reverts:
            dirty = uncommitted(cwd, sorted(guarded))
            if dirty:
                return f"`{sub[:50]}` would discard uncommitted guardrail/settings changes ({dirty[0]})", "ask"
    return None


def sandbox_rules_cache():
    try:
        return [r for r in load_rules(paths(), log=False) if r.get("sandbox")]
    except RulesUnreadable:
        return []


def uncommitted(cwd, files):
    """Guardrail or settings files git would lose on stash/clean/reset/checkout (modified or untracked)."""
    import subprocess
    root = os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or cwd)
    files = [f for f in files if f.startswith(root + os.sep) and os.path.exists(f)]  # git rejects outside paths
    if not files:
        return []
    try:
        out = subprocess.run(["git", "status", "--porcelain", "--"] + files,
                             cwd=cwd, capture_output=True, text=True, timeout=5)
        return [line[3:] for line in out.stdout.splitlines() if line.strip()] if out.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired):
        return []


TAMPER_RULE = {"id": "forge-tamper", "class": "safety", "decision": "ask"}


def evaluate(rules, event, payload, builtin=True):
    """Pure decision: returns (fired_rules, output_dict_or_None). No side effects."""
    cwd = payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    active = [r for r in rules if r.get("event") == event and not r.get("disabled")]
    if event == "Stop":
        calls = payload.get("_calls")
        if calls is None:
            calls = transcript_calls(payload.get("transcript_path", ""))
        fired = [r for r in active if stop_gate_unmet(r, calls, cwd)]
        if not fired:
            return [], None
        return fired, {"decision": "block", "reason": join_messages(fired)}
    fired = [r for r in active if call_matches(r, tool_name, tool_input, cwd)]
    if event == "PreToolUse":
        cmd = tool_input.get("command") if isinstance(tool_input.get("command"), str) else ""
        unknown = bash_unknown_writes(cmd) if cmd else []
        for r in active:
            if (unknown and r.get("unknown_writes") == "ask" and r not in fired
                    and re.fullmatch(r.get("tool", ".*"), tool_name or "")):
                fired.append({**r, "decision": "ask", "message": f"{r['message']} This command's writes cannot "
                              f"be checked ({unknown[0]}); confirm with the user."})
        tamper = tamper_reason(tool_name, tool_input, cwd) if builtin else None
        if tamper:
            reason, decision = tamper
            how = ("To drop a rule run `forge.py remove <id>` (the user confirms); to change one, remove and "
                   "re-add it; or the user edits the file themselves." if decision == "deny"
                   else "Confirm with the user.")
            fired.append({**TAMPER_RULE, "decision": decision, "message": f"This would loosen the guardrails: "
                          f"{reason}. Only the user may do that. {how} Tightening (forge.py add) needs no approval."})
    if not fired:
        return [], None
    if event == "PreToolUse":
        decision = "deny" if any(r["decision"] == "deny" for r in fired) else "ask"
        shown = [r for r in fired if r["decision"] == decision]
        return fired, {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": join_messages(shown),
        }}
    return fired, {"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": join_messages(fired),
    }}


SUFFIX = ("(Guardrail set by the user. Follow it; do not route around it with another tool or command. "
          "If it looks wrong for this case, stop and ask the user.)")


def join_messages(rules):
    return "\n".join(f"[guardrail {r['id']}] {r['message']}" for r in rules) + "\n" + SUFFIX


def rule_paths(rule, tool_input, cwd):
    """Paths this call touched that the rule's own `path` pattern matches (all of them if none)."""
    pat = (rule.get("match") or {}).get("path")
    vals = field_values(tool_input, "path")
    return [v for v in vals if not pat or pattern_matches(pat, [v], cwd)]


def run_fixers(rules, tool_input, cwd):
    import subprocess
    notes = []
    for r in rules:
        tmpl = r.get("run")
        if not tmpl:
            continue

        def fill(m):
            if m.group(1) == "path":  # every matched path, edit tools and shell writes alike
                return " ".join(shlex.quote(p) for p in rule_paths(r, tool_input, cwd))
            return shlex.quote(str(tool_input.get(m.group(1), "")))
        cmd = re.sub(r"\{(\w+)\}", fill, tmpl)
        try:
            res = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=30)
            out = (res.stdout + res.stderr).strip()[-600:]
            notes.append(f"[guardrail {r['id']}] ran `{cmd}` (exit {res.returncode}){': ' + out if out else ''}")
        except subprocess.TimeoutExpired:
            notes.append(f"[guardrail {r['id']}] `{cmd}` timed out")
    return notes


class RulesUnreadable(Exception):
    pass


RULE_KEYS = ("id", "class", "event", "decision", "message")


def load_rules(p, log=True):
    """Parse rules.json. Unparseable -> RulesUnreadable. A malformed single rule is skipped
    (and logged) so one bad entry cannot switch the others off."""
    try:
        rules = load_json(p["rules"], [])
    except ValueError as exc:
        raise RulesUnreadable(f"rules.json is not valid JSON ({exc})")
    if not isinstance(rules, list):
        raise RulesUnreadable("rules.json must be a JSON list")
    good = []
    for r in rules:
        if isinstance(r, dict) and all(isinstance(r.get(k), str) for k in RULE_KEYS):
            good.append(r)
        elif log:
            ledger_append(p, {"kind": "error", "error": f"skipped malformed rule {str(r)[:120]}"})
    return good


def hook(event):
    p = paths()
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0
    try:
        try:
            rules = load_rules(p)
        except RulesUnreadable as exc:
            ledger_append(p, {"kind": "error", "event": event, "error": str(exc)[:300]})
            # fail toward the human, not open: mutations wait for approval until rules.json is fixed
            if event == "PreToolUse" and MUTATING_TOOLS.fullmatch(payload.get("tool_name", "")):
                print(json.dumps({"hookSpecificOutput": {
                    "hookEventName": "PreToolUse", "permissionDecision": "ask",
                    "permissionDecisionReason": f"[guardrail forge-broken] {exc}. Guardrails are not being "
                    f"enforced until it is fixed (run forge.py doctor). Ask the user before changing anything."}}))
            return 0
        session = payload.get("session_id", "")
        tool_name = payload.get("tool_name", "")
        tool_input = payload.get("tool_input") or {}
        fp = fingerprint(tool_name, tool_input) if event != "Stop" else ""
        if event == "PostToolUse":
            mark_approvals(p, session, fp)
        fired, out = evaluate(rules, event, payload)
        if event == "Stop" and fired:
            blocks = sum(1 for e in ledger_read(p, tail=True) if e.get("session") == session and e.get("event") == "Stop"
                         and e.get("kind") == "fire")
            if payload.get("stop_hook_active") and blocks >= MAX_STOP_BLOCKS:
                for r in fired:
                    ledger_append(p, {"kind": "gave_up", "rule": r["id"], "event": event, "session": session})
                return 0
        for r in fired:
            ledger_append(p, {"kind": "fire", "rule": r["id"], "event": event, "decision": r["decision"],
                              "session": session, "fp": fp, "input": summarise(tool_name, tool_input)})
        if event == "PostToolUse" and fired:
            cwd = payload.get("cwd") or os.getcwd()
            notes = run_fixers(fired, tool_input, cwd)
            if notes:
                out["hookSpecificOutput"]["additionalContext"] += "\n" + "\n".join(notes)
        if out:
            print(json.dumps(out, ensure_ascii=False))
    except Exception as exc:  # fail open: a broken guardrail must never wedge Claude Code
        ledger_append(p, {"kind": "error", "event": event, "error": f"{type(exc).__name__}: {exc}"[:300]})
    return 0


def mark_approvals(p, session, fp):
    """A PostToolUse for a call that an `ask` rule stopped means the human approved it."""
    recent = ledger_read(p, tail=True)[-200:]
    done = {(e.get("rule"), e.get("fp")) for e in recent if e.get("kind") == "approved"}
    for e in recent:
        if (e.get("kind") == "fire" and e.get("decision") == "ask" and e.get("fp") == fp
                and e.get("session") == session and (e.get("rule"), fp) not in done):
            ledger_append(p, {"kind": "approved", "rule": e["rule"], "session": session, "fp": fp})
            done.add((e.get("rule"), fp))


# ---------------------------------------------------------------- validation & tests

def validate(rule, existing_ids=()):
    errs = []
    if not isinstance(rule, dict):
        return ["rule must be a JSON object"]
    rid = rule.get("id", "")
    if not ID_RE.match(str(rid)):
        errs.append("id must be lowercase letters, digits and dashes (2-64 chars)")
    if rid in existing_ids:
        errs.append(f"id {rid!r} already exists; remove it first or pick another id")
    if rule.get("class") not in CLASSES:
        errs.append(f"class must be one of {CLASSES}")
    event = rule.get("event")
    if event not in DECISIONS:
        errs.append(f"event must be one of {tuple(DECISIONS)}")
    elif rule.get("decision") not in DECISIONS[event]:
        errs.append(f"decision for {event} must be one of {DECISIONS[event]}")
    if not str(rule.get("message", "")).strip():
        errs.append("message is required: tell Claude what to do instead")
    prov = rule.get("provenance") or {}
    if not prov.get("said") or not prov.get("date"):
        errs.append("provenance.said (the user's words) and provenance.date are required")
    specs = []
    if event in ("PreToolUse", "PostToolUse"):
        if not rule.get("match"):
            errs.append("match is required for tool events")
        specs.append(rule)
    if event == "Stop":
        req = rule.get("require") or {}
        if not (isinstance(req.get("after"), dict) and isinstance(req.get("ran"), dict)):
            errs.append("Stop rules need require.after and require.ran, each {tool, match}")
        else:
            specs += [req["after"], req["ran"]]
    regexes = []
    for spec in specs:
        try:
            re.compile(spec.get("tool", ".*"))
            regexes.append(spec.get("tool", ".*"))
            for pat in list((spec.get("match") or {}).values()) + list((spec.get("unless") or {}).values()):
                kind, _, body = str(pat).partition(":")
                if kind not in ("glob", "re", "cmd"):
                    errs.append(f"pattern {pat!r} must start with glob:, re:, or cmd:")
                elif kind != "glob":
                    re.compile(body)
                    regexes.append(body)
        except re.error as exc:
            errs.append(f"bad regex: {exc}")
    slow = [rx for rx in regexes if regex_is_slow(rx)]
    if slow:
        errs.append(f"regex too slow on adversarial input (catastrophic backtracking): {slow[0]!r}")
    if rule.get("run") and event != "PostToolUse":
        errs.append("run (auto-fix) is only allowed on PostToolUse rules")
    if "unknown_writes" in rule and (rule["unknown_writes"] != "ask" or event != "PreToolUse"):
        errs.append('unknown_writes must be "ask" and only on PreToolUse rules')
    if rule.get("sandbox"):
        path_pat = str((rule.get("match") or {}).get("path", ""))
        if event != "PreToolUse" or not path_pat.startswith("glob:"):
            errs.append('sandbox: true needs a PreToolUse rule matching {"path": "glob:..."}')
        elif os.path.realpath(HERE) == os.path.realpath(user_dir()) and not re.match(r"^(/|~/)", path_pat[5:]):
            errs.append("a user-scope sandbox rule needs an absolute or ~/ glob")
    fx = rule.get("fixtures") or {}
    for kind in ("bad", "good", "near_miss"):
        if not isinstance(fx.get(kind), list) or not fx[kind]:
            errs.append(f"fixtures.{kind} needs at least one example")
    pd = rule.get("permission_deny", [])
    if not isinstance(pd, list) or not all(isinstance(x, str) and re.match(r"^\w+(\(.*\))?$", x) for x in pd):
        errs.append('permission_deny must be a list like ["Bash(git push --force *)"]')
    return errs


REDOS_PROBE = r"""
import re, sys
rx = re.compile(sys.argv[1])
for s in ("a" * 4000 + "!", "/" * 4000 + "!", " " * 4000 + "x", "-" * 4000 + "!", "git push " + "-f " * 1500 + "!",
          "ab" * 2000 + "!", "a/" * 2000 + "!", "0" * 4000 + "x"):
    rx.search(s)
"""


def regex_is_slow(pattern, limit=1.5):
    """Every hook call runs every regex; one that backtracks catastrophically would stall
    each tool call until the hook timeout. Probe it in a child process with a time limit."""
    import subprocess
    try:
        subprocess.run([sys.executable, "-c", REDOS_PROBE, pattern], timeout=limit,
                       capture_output=True, check=False)
        return False
    except subprocess.TimeoutExpired:
        return True


def fixture_payload(rule, fx):
    if rule["event"] == "Stop":
        return {"_calls": [(c.get("tool_name", ""), c.get("tool_input") or {}) for c in fx.get("transcript", [])],
                "cwd": fx.get("cwd", "/project")}
    return {"tool_name": fx.get("tool_name", ""), "tool_input": fx.get("tool_input") or {},
            "cwd": fx.get("cwd", "/project")}


def run_suite(rules):
    """Every bad fixture must fire its own rule; no good/near_miss fixture may fire ANY rule."""
    failures, checks = [], 0
    for rule in rules:
        fx = rule.get("fixtures") or {}
        for kind in ("bad", "good", "near_miss"):
            for i, case in enumerate(fx.get(kind, [])):
                checks += 1
                fired, _ = evaluate(rules, rule["event"], fixture_payload(rule, case), builtin=False)
                ids = [r["id"] for r in fired]
                label = f"{rule['id']} {kind}[{i}] {describe(case)}"
                if kind == "bad" and rule["id"] not in ids:
                    failures.append(f"MISSED   {label}: rule did not fire")
                elif kind != "bad":
                    for other in ids:
                        tag = "TOO-BROAD" if other == rule["id"] else "CONFLICT "
                        failures.append(f"{tag} {label}: fired by {other}")
    return checks, failures


def describe(case):
    if "transcript" in case:
        return "transcript[" + ", ".join(summarise(c.get("tool_name", ""), c.get("tool_input") or {})
                                        for c in case["transcript"]) + "]"
    return summarise(case.get("tool_name", ""), case.get("tool_input") or {})


# ---------------------------------------------------------------- settings

def user_dir():
    return os.path.join(os.path.expanduser("~"), ".claude", "guardrails")


LAUNCHER = "import sys;sys.path.insert(0,sys.argv[1]);import forge;sys.exit(forge.main(sys.argv[2:]))"


def is_forge_hook(command):
    return HOOK_MARK in command or ("import forge" in command and "guardrails" in command)


def hook_command(mode, scope_dir):
    """Import forge as a module rather than run it as a script: Python caches the compiled
    bytecode of imported modules only, which saves ~13 ms on every tool call."""
    where = f'"{scope_dir}"' if os.path.abspath(scope_dir) == user_dir() else '"$CLAUDE_PROJECT_DIR/.claude/guardrails"'
    return f'python3 -c "{LAUNCHER}" {where} {mode}'


def register_hooks(settings, scope_dir):
    hooks = settings.setdefault("hooks", {})
    for event, mode, matcher in (("PreToolUse", "pre", "*"), ("PostToolUse", "post", "*"), ("Stop", "stop", None)):
        groups = hooks.setdefault(event, [])
        if any(is_forge_hook(h.get("command", "")) for g in groups for h in g.get("hooks", [])):
            continue
        group = {"hooks": [{"type": "command", "command": hook_command(mode, scope_dir), "timeout": 30}]}
        if matcher:
            group = {"matcher": matcher, **group}
        groups.append(group)
    return settings


def settings_diff(before, after, path):
    import difflib
    a = json.dumps(before, indent=2, ensure_ascii=False).splitlines(keepends=True)
    b = json.dumps(after, indent=2, ensure_ascii=False).splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, path + " (before)", path + " (after)"))


# ---------------------------------------------------------------- CLI

def cmd_install(args):
    import shutil
    scope = arg_value(args, "--scope", "project")
    if scope == "user":
        base = user_dir()
    elif scope == "project":
        project = os.path.abspath(arg_value(args, "--project-dir", os.getcwd()))
        base = os.path.join(project, ".claude", "guardrails")
    else:
        return fail("--scope must be project or user")
    p = paths(base)
    os.makedirs(base, exist_ok=True)
    target = os.path.join(base, "forge.py")
    if os.path.abspath(__file__) != target:
        old = file_version(target)
        shutil.copyfile(os.path.abspath(__file__), target)
        os.chmod(target, 0o755)
        if old and old != VERSION:
            print(f"Dispatcher updated {old} -> {VERSION}.")
        corpus_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reference", "corpus.json")
        if os.path.exists(corpus_src):
            shutil.copyfile(corpus_src, os.path.join(base, "corpus.json"))
    if not os.path.exists(p["rules"]):
        write_json(p["rules"], [])
    gi = os.path.join(base, ".gitignore")
    existing = open(gi).read() if os.path.exists(gi) else "# per-person activity; rules.json and forge.py are shared\n"
    for line in ("ledger.jsonl", "ledger.1.jsonl", "__pycache__/"):
        if line not in existing.splitlines():
            existing += line + "\n"
    with open(gi, "w") as f:
        f.write(existing)
    before = load_json(p["settings"], {})
    after = register_hooks(json.loads(json.dumps(before)), base)
    if after != before:
        write_json(p["settings"], after)
        print(settings_diff(before, after, p["settings"]))
        print("Hooks registered. If this session does not pick them up, open /hooks or restart Claude Code.")
    else:
        print(f"Already installed at {base}; hooks unchanged.")
    print(f"guardrails dir: {base} (dispatcher {VERSION})")
    return 0


def file_version(path):
    try:
        with open(path, encoding="utf-8") as f:
            m = re.search(r'^VERSION = "([^"]+)"', f.read(), re.M)
        return m.group(1) if m else "1.x"
    except FileNotFoundError:
        return None


def cmd_doctor(_args):
    """Health check of this installed scope. Exit 0 when healthy, 1 otherwise."""
    p = paths()
    problems, notes = [], []
    try:
        rules = load_rules(p, log=False)
        notes.append(f"rules.json: {len(rules)} rule(s)")
    except RulesUnreadable as exc:
        rules = []
        problems.append(f"{exc}. Every mutating tool call is asking the user until this is fixed.")
    raw = load_json(p["rules"], []) if not problems else []
    if isinstance(raw, list) and len(raw) != len(rules):
        problems.append(f"{len(raw) - len(rules)} malformed rule(s) are being skipped")
    try:
        settings = load_json(p["settings"], {})
    except ValueError:
        settings = {}
        problems.append(f"{p['settings']} is not valid JSON")
    for event in ("PreToolUse", "PostToolUse", "Stop"):
        groups = (settings.get("hooks") or {}).get(event, [])
        if not any(is_forge_hook(h.get("command", "")) for g in groups for h in g.get("hooks", [])):
            problems.append(f"{event} hook is not registered in {p['settings']} (run install)")
    if settings.get("disableAllHooks"):
        problems.append(f"disableAllHooks is set in {p['settings']}: no guardrail runs")
    root = os.path.dirname(os.path.dirname(HERE))
    for extra in (os.path.join(root, ".claude", "settings.local.json"),
                  os.path.join(os.path.expanduser("~"), ".claude", "settings.json")):
        try:
            if load_json(extra, {}).get("disableAllHooks"):
                problems.append(f"disableAllHooks is set in {extra}: no guardrail runs")
        except (ValueError, AttributeError):
            pass
    import glob as _glob
    home = os.path.expanduser("~")
    copies = [os.path.join(home, ".claude", "skills", "forge", "scripts", "forge.py")]
    copies += _glob.glob(os.path.join(home, ".claude", "plugins", "cache", "**", "skills", "forge", "scripts", "forge.py"),
                         recursive=True)  # installed as a plugin
    versions = [v for v in (file_version(c) for c in copies) if v and v != "1.x"]
    latest = max(versions, key=lambda v: tuple(int(x) for x in re.findall(r"\d+", v)), default=None)
    if latest and latest != VERSION:
        problems.append(f"dispatcher is {VERSION}, the skill has {latest}: run install to update it")
    locked = [r for r in rules if r.get("sandbox")]
    if locked:
        sb = settings.get("sandbox", {})
        missing = [g for r in locked for g in sandbox_globs(r) if g not in sb.get("filesystem", {}).get("denyWrite", [])]
        if missing:
            problems.append(f"sandbox denyWrite is missing {missing} (remove and re-add the rule)")
        if not sb.get("enabled"):
            problems.append("sandbox-locked rules exist but the sandbox is off: scripts can still write protected "
                            "paths (forge.py sandbox on, after the user agrees)")
        ok, detail = sandbox_capability()
        if ok:
            notes.append(f"sandbox: machine can run it ({detail})")
        else:
            problems.append(f"sandbox cannot run on this machine: {detail}")
    checks, failures = run_suite(rules)
    if failures:
        problems.append(f"fixture suite RED: {len(failures)} of {checks} checks fail (run forge.py test)")
    else:
        notes.append(f"fixture suite GREEN ({checks} checks)")
    recent_errors = [e for e in ledger_read(p, tail=True) if e.get("kind") == "error"][-3:]
    for e in recent_errors:
        notes.append(f"recent dispatcher error {e.get('ts', '')}: {e.get('error', '')[:120]}")
    print(f"Guardrail doctor: {HERE} (dispatcher {VERSION})")
    for n in notes:
        print(f"  ok    {n}")
    for pr in problems:
        print(f"  FIX   {pr}")
    print("  HEALTHY" if not problems else f"  {len(problems)} problem(s)")
    return 0 if not problems else 1


CORRECTION_RE = re.compile(
    r"(?i)\b(don'?t|do not|never|stop|always|again|i told you|i said|not what i|instead of|you keep|wrong|"
    r"shouldn'?t|should not|please don'?t|no,)\b|لا ت|أبدا|ابدا|دائما|توقف|مرة أخرى")
STOPWORDS = set("the a an and or to of in on for with this that it is are be you your me my i we do don't dont not "
                "never always again stop please just can could would should about from at as by was were have has "
                "what when then than there here they them so if but no yes ok".split())


def correction_texts(transcripts_dir):
    """User turns from past session transcripts that read like corrections."""
    out, seen = [], set()
    for path in sorted(glob_files(transcripts_dir)):
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if e.get("type") != "user" or e.get("isMeta") or not isinstance(e.get("message"), dict):
                        continue
                    if e.get("uuid") and e["uuid"] in seen:  # resumed/forked sessions copy earlier turns verbatim
                        continue
                    seen.add(e.get("uuid"))
                    content = e["message"].get("content")
                    texts = [content] if isinstance(content, str) else [
                        b.get("text", "") for b in content or [] if isinstance(b, dict) and b.get("type") == "text"]
                    for t in texts:
                        t = t.strip()
                        if t and not t.startswith("<") and len(t) < 1500 and CORRECTION_RE.search(t):
                            out.append((e.get("timestamp", "")[:10], os.path.basename(path)[:8], t))
        except OSError:
            continue
    return out


def glob_files(d, recursive=False):
    """Session transcripts in d; recursive also picks up <session>/subagents/*.jsonl."""
    if not recursive:
        try:
            return [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".jsonl")]
        except OSError:
            return []
    found = []
    for base, _dirs, files in os.walk(d):
        found += [os.path.join(base, f) for f in files if f.endswith(".jsonl")]
    return found


def transcripts_dir_for(project):
    return os.path.join(os.path.expanduser("~"), ".claude", "projects", re.sub(r"[^A-Za-z0-9]", "-", project))


MAX_BACKTEST_CALLS = 50000


def history_calls(dirs):
    """Every tool call Claude made in past sessions: (date, session, cwd, tool_name, tool_input).
    Deduplicated by tool_use id, since resumed and forked sessions copy earlier turns."""
    calls, seen = [], set()
    files = sorted((f for d in dirs for f in glob_files(d, recursive=True)), key=lambda f: os.path.getmtime(f))
    for path in files[-400:]:
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if '"tool_use"' not in line:
                        continue
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    msg = e.get("message") if isinstance(e.get("message"), dict) else {}
                    for b in msg.get("content") or []:
                        if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("id") not in seen:
                            seen.add(b.get("id"))
                            calls.append((e.get("timestamp", "")[:10], e.get("sessionId", "")[:8],
                                          e.get("cwd", ""), b.get("name", ""), b.get("input") or {}))
        except OSError:
            continue
    return calls[-MAX_BACKTEST_CALLS:]


def backtest(rule, calls):
    """Replay one rule over past tool calls. Returns (hits, sessions_seen) where each hit is
    (date, session, summary). Stop rules are judged per session, at its end."""
    hits = []
    if rule["event"] == "Stop":
        by_session = {}
        for date, sid, cwd, name, inp in calls:
            by_session.setdefault(sid, (date, cwd, []))[2].append((name, inp))
        for sid, (date, cwd, seq) in by_session.items():
            if stop_gate_unmet(rule, seq, cwd or "/"):
                armed = [c for c in seq if call_matches(rule["require"]["after"], c[0], c[1], cwd or "/")][-1]
                hits.append((date, sid, f"finished after {summarise(*armed)} with no matching run after it",
                             armed[0], armed[1]))
        return hits, len(by_session)
    for date, sid, cwd, name, inp in calls:
        fired, _ = evaluate([rule], rule["event"], {"tool_name": name, "tool_input": inp, "cwd": cwd or "/"},
                            builtin=False)
        if fired:
            hits.append((date, sid, hit_summary(rule, name, inp, cwd or "/"), name, inp))
    return hits, len({c[1] for c in calls})


def hit_summary(rule, name, inp, cwd):
    """The part of a long Bash command that made the rule fire, not just its first line."""
    cmd = inp.get("command") if isinstance(inp.get("command"), str) else None
    if not cmd:
        return summarise(name, inp)
    for field, pat in (rule.get("match") or {}).items():
        kind, _, body = pat.partition(":")
        if field == "command" and kind == "cmd":
            for sub in split_command(cmd):
                if re.search(body, sub):
                    return redact(f"{name}: {sub}")[:160]
        if field == "path":
            for v in field_values(inp, "path"):
                if pattern_matches(pat, [v], cwd):
                    return redact(f"{name}: writes {v}  (in: {' '.join(cmd.split())[:80]})")[:160]
    return redact(f"{name}: {' '.join(cmd.split())}")[:160]


def default_history_dirs(args):
    """Project scope: this project's transcripts. User scope: every project's."""
    if "--transcripts" in args:
        return [arg_value(args, "--transcripts", "")]
    if os.path.realpath(HERE) == os.path.realpath(user_dir()):
        root = os.path.join(os.path.expanduser("~"), ".claude", "projects")
        return [os.path.join(root, d) for d in os.listdir(root)] if os.path.isdir(root) else []
    project = arg_value(args, "--project-dir", os.path.dirname(os.path.dirname(HERE)))
    return [transcripts_dir_for(os.path.abspath(project))]


EVIDENCE_LOW = 20


def rule_surface(rule):
    """A rule's area: its tools, the command heads its bad fixtures use, and the directory above the
    paths it protects. Exposure = how many past calls happened in that area."""
    spec = rule["require"]["after"] if rule["event"] == "Stop" else rule
    heads, parent = set(), None
    for fx in (rule.get("fixtures") or {}).get("bad", []):
        calls = [(c.get("tool_name"), c.get("tool_input") or {}) for c in fx.get("transcript", [])] or \
                [(fx.get("tool_name"), fx.get("tool_input") or {})]
        for _name, inp in calls:
            cmd = inp.get("command") if isinstance(inp.get("command"), str) else ""
            heads |= {sub.split()[0] for sub in split_command(cmd) if sub.split()}
    path_pat = str((spec.get("match") or {}).get("path", ""))
    if path_pat.startswith("glob:"):
        prefix = glob_prefix(path_pat[5:])
        parent = os.path.dirname(prefix) if prefix else ""
    cmd_rule = any(str(p).startswith("cmd:") for p in (spec.get("match") or {}).values())
    return spec.get("tool", ".*"), (heads if cmd_rule else set()), parent


def on_surface(surface, name, inp, cwd):
    tool_rx, heads, parent = surface
    if not re.fullmatch(tool_rx, name or ""):
        return False
    if heads:
        cmd = inp.get("command") if isinstance(inp.get("command"), str) else ""
        if not any(sub.split()[0] in heads for sub in split_command(cmd) if sub.split()):
            return False
    if parent is not None:
        vals = field_values(inp, "path")
        if not vals:
            return False
        if parent and not any(c == parent or c.startswith(parent + "/")
                              for v in vals for c in path_candidates(v, cwd)):
            return False
    return True


def evidence_label(exposure):
    return "NONE" if exposure == 0 else "LOW" if exposure < EVIDENCE_LOW else "OK"


def corpus_calls(root):
    """Day-one test set, independent of session history: (source, tool, input) from the project's own
    config (package.json scripts, Makefile, CI steps), a sample of its tracked files, and a built-in
    list of common developer work in 8 domains."""
    import subprocess
    out = []
    pkg_path = os.path.join(root, "package.json")
    try:
        pkg = load_json(pkg_path, {}) if os.path.exists(pkg_path) else {}
    except ValueError:
        pkg = {}
    for name, body in ((pkg.get("scripts") or {}).items() if isinstance(pkg, dict) else []):
        out.append(("config:package.json", "Bash", {"command": f"npm run {name}"}))
        out += [("config:package.json", "Bash", {"command": part.strip()})
                for part in re.split(r"&&|;|\|\|", str(body)) if part.strip()]
    for mk in ("Makefile", "makefile", "GNUmakefile", "justfile"):
        try:
            with open(os.path.join(root, mk), encoding="utf-8") as f:
                text = f.read()
        except OSError:
            continue
        out += [(f"config:{mk}", "Bash", {"command": f"make {t}"})
                for t in re.findall(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", text, re.M) if not t.startswith(".")]
        out += [(f"config:{mk}", "Bash", {"command": line.strip().lstrip("@-")})
                for line in re.findall(r"^\t(.+)$", text, re.M)]
    wf_dir = os.path.join(root, ".github", "workflows")
    for wf in (sorted(os.listdir(wf_dir)) if os.path.isdir(wf_dir) else []):
        try:
            with open(os.path.join(wf_dir, wf), encoding="utf-8") as f:
                text = f.read()
        except OSError:
            continue
        out += [(f"config:ci/{wf}", "Bash", {"command": c.strip()})
                for c in re.findall(r"^\s*-?\s*run:\s*(.+)$", text, re.M) if c.strip() not in ("", "|", ">")]
    try:
        files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True,
                               timeout=10).stdout.split("\n")
    except (OSError, subprocess.TimeoutExpired):
        files = []
    per_dir = {}
    for f in files:
        top = f.split("/")[0] if "/" in f else "."
        if f and not f.startswith(".claude/") and per_dir.setdefault(top, 0) < 3:
            per_dir[top] += 1
            out.append(("files", "Edit", {"file_path": f}))
    corpus_path = next((p for p in (os.path.join(HERE, "corpus.json"),
                                    os.path.join(HERE, "..", "reference", "corpus.json")) if os.path.exists(p)), None)
    for domain, items in (load_json(corpus_path, {}) if corpus_path else {}).items():
        if domain.startswith("_"):
            continue
        for it in items:
            if isinstance(it, str):
                out.append((f"common:{domain}", "Bash", {"command": it}))
            else:
                out.append((f"common:{domain}", it.get("tool", "Edit"), {"file_path": it.get("file_path", "")}))
    return out


def corpus_hits(rule, corpus, root):
    if rule["event"] == "Stop":
        return []
    hits = []
    for source, name, inp in corpus:
        fired, _ = evaluate([rule], rule["event"], {"tool_name": name, "tool_input": inp, "cwd": root}, builtin=False)
        if fired:
            hits.append((source, hit_summary(rule, name, inp, root), name, inp))
    return hits


def run_backtest(rule, history, corpus, root):
    hits, sessions = backtest(rule, history)
    surface = rule_surface(rule)
    exposure = sum(1 for _d, _s, cwd, name, inp in history if on_surface(surface, name, inp, cwd or root))
    return {"history_calls": len(history), "sessions": sessions, "exposure": exposure,
            "evidence": evidence_label(exposure), "hits": hits, "corpus": corpus_hits(rule, corpus, root)}


def backtest_report(rule, result, limit=6):
    hits, exp = result["hits"], result["exposure"]
    lines = [f"Backtest of {rule['id']}:",
             f"  project history: {result['history_calls']} past tool calls in {result['sessions']} session(s), "
             f"{exp} in this rule's area -> evidence {result['evidence']}"]
    if hits:
        counts = {}
        for d, _, s, *_ in hits:
            counts[f"{d}  {s}"] = counts.get(f"{d}  {s}", 0) + 1
        lines.append(f"  would have fired {len(hits)} time(s):")
        lines += [f"    {k}" + (f"  (x{c})" if c > 1 else "") for k, c in list(counts.items())[:limit]]
        if len(counts) > limit:
            lines.append(f"    ... and {len(counts) - limit} more")
    elif result["evidence"] == "OK":
        lines.append(f"  never fired on the {exp} past calls in its area: no false positives in real use so far.")
    else:
        lines.append("  NOT ENOUGH HISTORY to vouch for this rule either way; judge it on the day-one results below.")
    by_source = {}
    for source, summary, _n, _i in result["corpus"]:
        by_source.setdefault(source, []).append(summary)
    if by_source:
        lines.append(f"  day-one test set: would fire on {len(result['corpus'])} action(s):")
        for source, items in by_source.items():
            shown = list(dict.fromkeys(items))
            lines.append(f"    {source} ({len(items)}): " + " | ".join(x[:60] for x in shown[:3])
                         + (" | ..." if len(shown) > 3 else ""))
    else:
        lines.append("  day-one test set (project config, repo files, common work in 8 domains): fires on nothing.")
    lines.append("  Label each hit: a real case of the mistake (keep; can become a `bad` fixture) or legitimate "
                 "work (narrow the rule; can become a `near_miss` fixture). `--fixtures` prints them as JSON.")
    return "\n".join(lines)


def cmd_backtest(args):
    """forge.py backtest RULE.json|-|--all [--transcripts DIR] [--project-dir DIR] [--fixtures]"""
    if not args:
        return fail("usage: forge.py backtest RULE.json|-|--all [--transcripts DIR] [--project-dir DIR] [--fixtures]")
    root = os.path.abspath(arg_value(args, "--project-dir", os.path.dirname(os.path.dirname(HERE))))
    os.environ.setdefault("CLAUDE_PROJECT_DIR", root)
    rules = load_rules(paths(), log=False) if args[0] == "--all" else [read_rule_arg(args[0])]
    history = history_calls(default_history_dirs(args))
    corpus = corpus_calls(root)
    for rule in rules:
        result = run_backtest(rule, history, corpus, root)
        if "--fixtures" in args:  # every hit as a ready-to-paste fixture, for the human to label bad or near_miss
            found = [{"tool_name": h[3], "tool_input": h[4], "_seen": f"history {h[0]}"} for h in result["hits"]]
            found += [{"tool_name": n, "tool_input": i, "_seen": src} for src, _s, n, i in result["corpus"]]
            print(json.dumps({"rule": rule["id"], "hits_as_fixtures": found}, indent=1, ensure_ascii=False))
        else:
            print(backtest_report(rule, result))
    return 0


def cmd_harvest(args):
    """Cluster repeated corrections from past sessions; each cluster is a /forge candidate."""
    project = os.path.abspath(arg_value(args, "--project-dir", os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()))
    default_dir = os.path.join(os.path.expanduser("~"), ".claude", "projects", re.sub(r"[^A-Za-z0-9]", "-", project))
    tdir = arg_value(args, "--transcripts", default_dir)
    min_count = int(arg_value(args, "--min", "2"))
    items = correction_texts(tdir)
    words = lambda t: {w for w in re.findall(r"[\w'.\-/]{3,}", t.lower()) if w not in STOPWORDS}
    clusters = []  # [tokens, [items]]
    for item in items:
        toks = words(item[2])
        if not toks:
            continue
        best = max(clusters, key=lambda c: len(toks & c[0]) / len(toks | c[0]), default=None)
        if best and len(toks & best[0]) / len(toks | best[0]) >= 0.3:
            best[1].append(item)
            best[0] |= toks
        else:
            clusters.append([set(toks), [item]])
    repeated = sorted([c for c in clusters if len({i[1] for i in c[1]}) >= min_count or len(c[1]) >= min_count + 1],
                      key=lambda c: -len(c[1]))
    print(f"Harvest: {len(items)} correction-like messages in {len(glob_files(tdir))} session(s) under {tdir}")
    if not repeated:
        print(f"No correction repeated {min_count}+ times. Nothing to forge yet.")
    for c in repeated[:10]:
        sessions = len({i[1] for i in c[1]})
        text = " ".join(i[2] for i in c[1])
        kinds = []
        if re.search(r"[\w.-]+/[\w./*-]+|\.\w{1,5}\b|\b(file|folder|dir(ectory)?)\b", text, re.I):
            kinds.append("path rule (glob on `path`)")
        if re.search(r"\b(git|npm|pnpm|yarn|pip|docker|make|push|install|commit|run|deploy|migrate)\b", text, re.I):
            kinds.append("command rule (`cmd:` on `command`)")
        if re.search(r"\b(test|tests|done|finish|before you)\b", text, re.I):
            kinds.append("stop gate")
        print(f"\n{len(c[1])}x across {sessions} session(s); likely {' or '.join(kinds) or 'prose'}:")
        for date, _, text in c[1][:3]:
            print(f"   {date}  \"{redact(' '.join(text.split()))[:160]}\"")
    print("\nNothing was changed. Pick a cluster and run /forge with it to make it a guardrail.")
    return 0


def read_rule_arg(src):
    raw = sys.stdin.read() if src == "-" else open(src, encoding="utf-8").read()
    return json.loads(raw)


def cmd_add(args):
    if not args:
        return fail("usage: forge.py add RULE.json|- [--dry-run]")
    p = paths()
    rule = read_rule_arg(args[0])
    rules = load_json(p["rules"], [])
    errs = validate(rule, {r["id"] for r in rules})
    if errs:
        print("INVALID RULE:\n  " + "\n  ".join(errs))
        return 2
    rule.setdefault("created", iso())
    candidate = rules + [rule]
    checks, failures = run_suite(candidate)
    if failures:
        print(f"RED: {len(failures)} of {checks} checks failed; nothing was written.\n  " + "\n  ".join(failures))
        print("Narrow the pattern or add an `unless`; never delete a fixture to go green.")
        return 3
    print(f"GREEN: {checks} checks passed across {len(candidate)} rule(s).")
    if rule["class"] == "safety" and not rule.get("permission_deny"):
        print("NOTE: safety rule without permission_deny: only one layer of protection.")
    if "--no-backtest" not in args:
        root = os.path.abspath(arg_value(args, "--project-dir", os.path.dirname(os.path.dirname(HERE))))
        os.environ.setdefault("CLAUDE_PROJECT_DIR", root)
        result = run_backtest(rule, history_calls(default_history_dirs(args)), corpus_calls(root), root)
        print(backtest_report(rule, result, limit=3))
        rule.setdefault("provenance", {})["backtest"] = {  # travels with rules.json to teammates
            "date": iso()[:10], "history_calls": result["history_calls"], "exposure": result["exposure"],
            "evidence": result["evidence"], "history_hits": len(result["hits"]), "day_one_hits": len(result["corpus"])}
    if rule.get("decision") == "ask" or rule.get("unknown_writes") == "ask":
        asking = [r for r in rules if r.get("decision") == "ask" or r.get("unknown_writes") == "ask"]
        per_week = prompts_per_week(p)
        if asking:
            print(f"PROMPT BUDGET: {len(asking)} other rule(s) already ask the user ({per_week:.0f} prompts in the "
                  f"last 7 days). Prefer deny-with-reason unless the user really wants to decide each time.")
    before = load_json(p["settings"], {})
    after = json.loads(json.dumps(before))
    if sandbox_globs(rule):
        set_deny_write(after, add=sandbox_globs(rule))
        ok, detail = sandbox_capability()
        state = "on" if before.get("sandbox", {}).get("enabled") else "OFF (run `forge.py sandbox on` after the user agrees)"
        print(f"SANDBOX LOCK: {sandbox_globs(rule)[0]} added to sandbox.filesystem.denyWrite; sandbox is {state}; "
              f"machine: {'OK' if ok else 'cannot run it yet: ' + detail}")
    deny = after.setdefault("permissions", {}).setdefault("deny", [])
    for entry in rule.get("permission_deny", []):
        if entry not in deny:
            deny.append(entry)
    if not after["permissions"]["deny"]:
        del after["permissions"]["deny"]
        if not after["permissions"]:
            del after["permissions"]
    if "--dry-run" in args:
        print("DRY RUN: rule not written.")
        diff = settings_diff(before, after, p["settings"])
        if diff:
            print(diff)
        return 0
    write_json(p["rules"], candidate)
    if after != before:
        write_json(p["settings"], after)
        print(settings_diff(before, after, p["settings"]))
    ledger_append(p, {"kind": "added", "rule": rule["id"]})
    print(f"Added {rule['id']} ({rule['class']}, {rule['event']} -> {rule['decision']}). Undo: forge.py remove {rule['id']}")
    return 0


def cmd_remove(args):
    if not args:
        return fail("usage: forge.py remove RULE_ID")
    p = paths()
    rules = load_json(p["rules"], [])
    hit = [r for r in rules if r["id"] == args[0]]
    if not hit:
        return fail(f"no rule {args[0]!r}")
    rule = hit[0]
    keep = [r for r in rules if r["id"] != args[0]]
    archive = load_json(p["archive"], [])
    archive.append({**rule, "removed": iso()})
    write_json(p["archive"], archive)
    write_json(p["rules"], keep)
    still_needed = {e for r in keep for e in r.get("permission_deny", [])}
    drop = [e for e in rule.get("permission_deny", []) if e not in still_needed]
    sandbox_drop = [g for g in sandbox_globs(rule) if g not in {x for r in keep for x in sandbox_globs(r)}]
    if drop or sandbox_drop:
        before = load_json(p["settings"], {})
        after = json.loads(json.dumps(before))
        if drop:
            deny = after.get("permissions", {}).get("deny", [])
            after.setdefault("permissions", {})["deny"] = [e for e in deny if e not in drop]
        if sandbox_drop:
            set_deny_write(after, drop=sandbox_drop)
        write_json(p["settings"], after)
        print(settings_diff(before, after, p["settings"]))
    ledger_append(p, {"kind": "removed", "rule": rule["id"]})
    print(f"Removed {rule['id']} (archived in rules.archive.json).")
    return 0


def cmd_list(_args):
    rules = load_json(paths()["rules"], [])
    if not rules:
        print("No guardrails yet.")
    for r in rules:
        print(f"{r['id']:<28} {r['class']:<10} {r['event']:<11} {r['decision']:<6} {r['message'][:70]}")
    return 0


def cmd_test(_args):
    rules = load_json(paths()["rules"], [])
    checks, failures = run_suite(rules)
    if failures:
        print(f"RED: {len(failures)} of {checks} checks failed.\n  " + "\n  ".join(failures))
        return 1
    print(f"GREEN: {checks} checks passed across {len(rules)} rule(s).")
    return 0


def cmd_explain(args):
    raw = sys.stdin.read() if not args or args[0] == "-" else args[0]
    payload = json.loads(raw)
    event = payload.get("hook_event_name", "PreToolUse")
    fired, out = evaluate(load_rules(paths(), log=False), event, payload)
    print(json.dumps({"fired": [r["id"] for r in fired], "output": out}, indent=2, ensure_ascii=False))
    return 0


def cmd_split(args):
    cmd = " ".join(args)
    for sub in split_command(cmd):
        print(sub)
    writes = bash_writes(cmd)
    if writes:
        print("writes: " + " ".join(t + (" (deletes)" if d else "") for t, d in writes))
    for reason in bash_unknown_writes(cmd):
        print("unknown: " + reason)
    return 0


def prompts_per_week(p):
    cutoff = now() - _dt.timedelta(days=7)
    count = 0
    for e in ledger_read(p, tail=False):
        if e.get("kind") == "fire" and e.get("decision") == "ask":
            try:
                count += _dt.datetime.fromisoformat(e["ts"]) >= cutoff
            except (KeyError, ValueError):
                pass
    return count


# ---------------------------------------------------------------- sandbox double lock

def sandbox_globs(rule):
    return [rule["match"]["path"][5:]] if rule.get("sandbox") else []


def set_deny_write(settings, add=(), drop=()):
    """Merge/unmerge sandbox.filesystem.denyWrite entries, pruning empty containers."""
    sb = settings.setdefault("sandbox", {})
    fs = sb.setdefault("filesystem", {})
    deny = [e for e in fs.get("denyWrite", []) if e not in drop]
    deny += [e for e in add if e not in deny]
    fs["denyWrite"] = deny
    if not deny:
        del fs["denyWrite"]
    if not fs:
        del sb["filesystem"]
    if not sb:
        del settings["sandbox"]
    return settings


def sandbox_capability():
    """(ok, detail): can this machine actually run Claude Code's sandbox?"""
    import shutil
    import subprocess
    if sys.platform == "darwin":
        return (bool(shutil.which("sandbox-exec")), "macOS Seatbelt (sandbox-exec)")
    if not sys.platform.startswith("linux"):
        return False, "sandboxing needs macOS, Linux or WSL2"
    missing = [t for t in ("bwrap", "socat") if not shutil.which(t)]
    if "socat" not in missing:
        try:
            if subprocess.run(["socat", "-V"], capture_output=True, timeout=5).returncode != 0:
                missing.append("socat (installed but does not run)")
        except (OSError, subprocess.TimeoutExpired):
            missing.append("socat (installed but does not run)")
    problems = [f"install {', '.join(missing)} (e.g. sudo apt install bubblewrap socat)"] if missing else []
    if "bwrap" not in missing:
        try:
            r = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                hint = r.stderr.strip()[:80]
                if "uid map" in r.stderr or "Permission denied" in r.stderr:
                    hint += ("; on Ubuntu 23.10+ AppArmor blocks unprivileged user namespaces for bwrap: "
                             "give /usr/bin/bwrap an AppArmor profile that allows userns (needs sudo)")
                problems.append(f"bwrap cannot create a sandbox here ({hint})")
        except (OSError, subprocess.TimeoutExpired) as exc:
            problems.append(f"bwrap test failed ({exc})")
    return (not problems, "; ".join(problems) or "bubblewrap + socat work")


NETWORK_CMDS = re.compile(r"^(curl|wget|ssh|scp|rsync|git (push|pull|fetch|clone|ls-remote)|npm (install|i|ci|publish|update)"
                          r"|pnpm (install|add|i)|yarn (add|install)?|pip3? install|uv (pip|add|sync)|cargo (build|add|install)"
                          r"|go (get|mod download)|docker (pull|push|build)|gh |apt(-get)? install|brew install)\b")


def sandbox_impact(root):
    """What past Bash commands in this project would have hit the sandbox's default limits."""
    calls = [c for c in history_calls([transcripts_dir_for(root)]) if c[3] == "Bash"]
    outside, network = [], []
    real_root = os.path.realpath(root)
    for date, sid, cwd, name, inp in calls:
        cmd = inp.get("command", "")
        for t, _ in bash_writes(cmd):
            target = os.path.realpath(os.path.join(cwd or root, expand(t, cwd or root)))
            if not (target == real_root or target.startswith(real_root + os.sep)) and not target.startswith("/tmp") \
                    and target != "/dev/null":
                outside.append(f"{date}  {summarise(name, inp)[:110]}")
                break
        if any(NETWORK_CMDS.search(sub) for sub in split_command(cmd)):
            network.append(f"{date}  {summarise(name, inp)[:110]}")
    return len(calls), outside, network


def cmd_sandbox(args):
    """forge.py sandbox status | on [--strict] | off | exclude "CMD" | unexclude "CMD" """
    p = paths()
    action = args[0] if args else "status"
    before = load_json(p["settings"], {})
    after = json.loads(json.dumps(before))
    sb = after.setdefault("sandbox", {})
    if action == "status":
        rules = [r for r in load_rules(p, log=False) if r.get("sandbox")]
        ok, detail = sandbox_capability()
        print(f"sandbox.enabled: {bool(before.get('sandbox', {}).get('enabled'))}")
        print(f"denyWrite: {before.get('sandbox', {}).get('filesystem', {}).get('denyWrite', [])}")
        print(f"excludedCommands: {before.get('sandbox', {}).get('excludedCommands', [])}")
        print(f"allowUnsandboxedCommands: {before.get('sandbox', {}).get('allowUnsandboxedCommands', True)}")
        print(f"rules using the sandbox lock: {[r['id'] for r in rules] or 'none'}")
        print(f"this machine: {'OK' if ok else 'CANNOT RUN'}: {detail}")
        root = os.path.dirname(os.path.dirname(HERE))
        total, outside, network = sandbox_impact(root)
        if total:
            print(f"impact on past work ({total} Bash commands): {len(outside)} wrote outside the project "
                  f"(would be blocked), {len(network)} used the network (would prompt per domain the first time)")
            for label, rows in (("outside", outside), ("network", network)):
                for r in list(dict.fromkeys(rows))[:3]:
                    print(f"    {label}: {r}")
        return 0
    if action == "on":
        sb["enabled"] = True
        if "--strict" in args:
            sb["allowUnsandboxedCommands"] = False  # removes the per-command escape hatch
    elif action == "off":
        sb["enabled"] = False
    elif action in ("exclude", "unexclude") and len(args) > 1:
        ex = [e for e in sb.get("excludedCommands", []) if e != args[1]]
        sb["excludedCommands"] = ex + [args[1]] if action == "exclude" else ex
    else:
        return fail('usage: forge.py sandbox status | on [--strict] | off | exclude "CMD" | unexclude "CMD"')
    write_json(p["settings"], after)
    print(settings_diff(before, after, p["settings"]) or "no change")
    if action == "on":
        ok, detail = sandbox_capability()
        print("Sandbox on. Every Bash command now runs sandboxed: writes outside the project are blocked, network "
              "access prompts per domain, and sandboxed commands no longer ask for permission.")
        if not ok:
            print(f"WARNING: this machine cannot run the sandbox yet: {detail}")
    return 0


def cmd_audit(args):
    p = paths()
    days = float(arg_value(args, "--days", "30"))
    per_day = float(arg_value(args, "--noisy-per-day", "5"))
    min_asks = int(arg_value(args, "--min-asks", "5"))
    rules = load_rules(p, log=False)
    ledger = ledger_read(p, tail=False)
    cutoff = now() - _dt.timedelta(days=days)

    def ts(e):
        try:
            return _dt.datetime.fromisoformat(e["ts"])
        except (KeyError, ValueError):
            return None

    report = []
    for r in rules:
        mine = [e for e in ledger if e.get("rule") == r["id"]]
        fires = [e for e in mine if e.get("kind") == "fire"]
        recent = [e for e in fires if (ts(e) or cutoff) >= cutoff]
        asks = [e for e in fires if e.get("decision") == "ask"]
        approved = [e for e in mine if e.get("kind") == "approved"]
        created = None
        try:
            created = _dt.datetime.fromisoformat(r.get("created", ""))
        except ValueError:
            pass
        age_days = (now() - created).days if created else None
        flags = []
        if not recent and r["class"] != "safety" and (age_days is None or age_days >= days):
            flags.append(f"SILENT: no firings in {days:g} days. Dead rule, or Claude learned it. Consider removing.")
        window = min(days, max(1, age_days if age_days is not None else days))
        if len(recent) / window > per_day:
            flags.append(f"NOISY: {len(recent)} firings in {window:g} days. Pattern may be too broad, "
                         f"or Claude keeps retrying; check the examples.")
        if len(asks) >= min_asks and len(approved) / len(asks) >= 0.6:
            advice = ("Safety ask: the confirmation may be the point; narrow it rather than demote."
                      if r["class"] == "safety" else "Demote (nudge) or narrow it.")
            flags.append(f"OVERRIDDEN: you approved {len(approved)} of {len(asks)} asks. {advice}")
        if r["decision"] == "nudge" and len(recent) >= 10:
            flags.append(f"ESCALATE?: nudged {len(recent)} times and Claude keeps doing it. Consider a deny rule.")
        report.append((r, len(fires), len(recent), flags, [e.get("input", "") for e in recent[-3:]]))
    errors = [e for e in ledger if e.get("kind") == "error" and (ts(e) or cutoff) >= cutoff]
    print(f"Guardrail audit ({len(rules)} rules, window {days:g} days)")
    week = now() - _dt.timedelta(days=7)
    asks = [e for e in ledger if e.get("kind") == "fire" and e.get("decision") == "ask" and (ts(e) or week) >= week]
    approved_week = [e for e in ledger if e.get("kind") == "approved" and (ts(e) or week) >= week]
    by_rule = {}
    for e in asks:
        by_rule[e.get("rule")] = by_rule.get(e.get("rule"), 0) + 1
    print(f"\nPrompts in the last 7 days: {len(asks)} (you approved {len(approved_week)})"
          + (": " + ", ".join(f"{k} {v}" for k, v in sorted(by_rule.items(), key=lambda kv: -kv[1])) if by_rule else ""))
    if len(asks) > 7 * float(arg_value(args, "--prompts-per-day", "3")):
        print("  PROMPT FATIGUE: that many prompts trains anyone to click Allow without reading. Narrow the top "
              "rule, or turn it into a deny with a corrective reason.")
    for r, total, rec, flags, examples in report:
        state = "OK" if not flags else "FLAGGED"
        print(f"\n{state:<8} {r['id']} [{r['class']}/{r['decision']}] total fires {total}, recent {rec}")
        for f in flags:
            print(f"         - {f}")
        for ex in examples:
            print(f"         e.g. {ex}")
    if errors:
        print(f"\n{len(errors)} dispatcher error(s) in window; latest: {errors[-1].get('error')}")
    print("\nNothing was changed. Decide per flagged rule, then use `forge.py remove` or edit and re-add.")
    return 0


def arg_value(args, name, default):
    if name in args:
        i = args.index(name)
        if i + 1 < len(args):
            return args[i + 1]
    return default


def fail(msg):
    print(msg, file=sys.stderr)
    return 2


def main(argv):
    if not argv:
        print(__doc__)
        return 0
    mode, args = argv[0], argv[1:]
    hooks = {"pre": "PreToolUse", "post": "PostToolUse", "stop": "Stop"}
    if mode in hooks:
        return hook(hooks[mode])
    commands = {"install": cmd_install, "add": cmd_add, "remove": cmd_remove, "list": cmd_list,
                "test": cmd_test, "explain": cmd_explain, "split": cmd_split, "audit": cmd_audit,
                "doctor": cmd_doctor, "harvest": cmd_harvest, "backtest": cmd_backtest, "sandbox": cmd_sandbox,
                "version": lambda _a: print(VERSION) or 0}
    if mode not in commands:
        return fail(f"unknown command {mode!r}\n{__doc__}")
    return commands[mode](args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
