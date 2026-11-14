#!/usr/bin/env python3
"""nginxcheck: lint nginx configuration files for common security mistakes.

Read-only. Never starts nginx and never executes anything it reads.
Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or input error.
"""
import argparse
import glob
import json
import os
import re
import stat as statmod
import sys

__version__ = "1.0.0"

SEVERITIES = ["info", "low", "medium", "high"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

DEFAULT_MAX_SIZE = 1024 * 1024
MAX_NEST = 100
MAX_FILES = 200
MAX_GLOB = 500
DEFAULT_MAX_DEPTH = 8

LOCATION_MODS = ("=", "~", "~*", "^~")
SECURITY_HEADERS = {"strict-transport-security", "x-frame-options", "x-content-type-options",
                    "content-security-policy", "referrer-policy", "permissions-policy"}
WEAK_CIPHER_TOKENS = {"NULL": "high", "ANULL": "high", "ENULL": "high", "EXP": "high", "EXPORT": "high",
                      "EXPORT40": "high", "EXPORT56": "high", "LOW": "medium", "MD5": "medium", "RC4": "high",
                      "DES": "high", "3DES": "medium", "ADH": "high", "AECDH": "medium", "RC2": "high",
                      "IDEA": "medium", "SEED": "low", "PSK": "low", "SRP": "low", "ANON": "high"}
ATTACKER_VARS = re.compile(r"\$(host|http_[A-Za-z0-9_]+|arg_[A-Za-z0-9_]+|args|cookie_[A-Za-z0-9_]+|"
                           r"query_string|[0-9]+|server_name|request)\b|\$\{(host|http_\w+|arg_\w+|cookie_\w+|\d+)\}")
PATH_VARS = {"uri", "request_uri", "is_args", "args", "document_uri", "query_string"}


def clean(s, limit=300):
    out = []
    for ch in str(s):
        o = ord(ch)
        if ch == "\t":
            out.append(" ")
        elif o < 32 or o == 127 or 0x80 <= o < 0xA0 or o in (0x202E, 0x202D, 0x2066, 0x2067, 0x2068, 0x2069):
            out.append("\\x%02x" % o if o < 256 else "\\u%04x" % o)
        else:
            out.append(ch)
    r = "".join(out)
    if len(r) > limit:
        r = r[:limit] + "..."
    return r


# ------------------------------------------------------------------ tokenizer / parser

def tokenize(text):
    """Yield (kind, value, line). kind: 'w' word, '{', '}', ';', 'err'."""
    i, n, line = 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
        elif ch in " \t\r\f\v":
            i += 1
        elif ch == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif ch in "{};":
            yield (ch, ch, line)
            i += 1
        elif ch in "\"'":
            q = ch
            start_line = line
            i += 1
            buf = []
            closed = False
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    buf.append(text[i + 1] if text[i + 1] in "\"'\\" else c + text[i + 1])
                    if text[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if c == q:
                    closed = True
                    i += 1
                    break
                if c == "\n":
                    line += 1
                buf.append(c)
                i += 1
            if not closed:
                yield ("err", "unterminated quoted string", start_line)
                return
            yield ("w", "".join(buf), start_line)
        else:
            buf = []
            while i < n:
                c = text[i]
                if c in " \t\r\n\f\v;{}":
                    # allow ${var} inside words
                    break
                if c == "$" and i + 1 < n and text[i + 1] == "{":
                    j = text.find("}", i)
                    if j == -1 or "\n" in text[i:j]:
                        buf.append(c)
                        i += 1
                        continue
                    buf.append(text[i:j + 1])
                    i = j + 1
                    continue
                if c == "\\" and i + 1 < n and text[i + 1] not in "\n":
                    buf.append(text[i:i + 2])
                    i += 2
                    continue
                buf.append(c)
                i += 1
            yield ("w", "".join(buf), line)


class Node:
    __slots__ = ("name", "args", "line", "file", "children", "parent")

    def __init__(self, name, args, line, file, parent):
        self.name = name
        self.args = args
        self.line = line
        self.file = file
        self.children = None
        self.parent = parent

    def eff_children(self):
        """Children with include nodes replaced by what they include."""
        out = []
        if self.children is None:
            return out
        stack = [iter(self.children)]
        while stack:
            try:
                c = next(stack[-1])
            except StopIteration:
                stack.pop()
                continue
            if c.name == "include" and c.children is not None:
                stack.append(iter(c.children))
            else:
                out.append(c)
        return out

    def find(self, name):
        return [c for c in self.eff_children() if c.name == name]


def parse_tokens(tokens, file, add_error):
    """Return list of top-level Nodes."""
    root = Node("<root>", [], 0, file, None)
    root.children = []
    stack = [root]
    pending = []
    pline = 0
    for kind, val, line in tokens:
        if kind == "err":
            add_error(line, val)
            break
        if kind == "w":
            if not pending:
                pline = line
            pending.append(val)
            continue
        cur = stack[-1]
        if kind == ";":
            if pending:
                n = Node(pending[0], pending[1:], pline, file, cur)
                cur.children.append(n)
            else:
                add_error(line, "empty directive (stray ';')")
            pending = []
        elif kind == "{":
            if not pending:
                add_error(line, "block without a name")
                pending = ["<anonymous>"]
                pline = line
            n = Node(pending[0], pending[1:], pline, file, cur)
            n.children = []
            cur.children.append(n)
            pending = []
            if len(stack) >= MAX_NEST:
                add_error(line, "nesting deeper than %d; parsing stopped" % MAX_NEST)
                return root.children
            stack.append(n)
        elif kind == "}":
            if pending:
                add_error(line, "missing ';' before '}'")
                n = Node(pending[0], pending[1:], pline, file, cur)
                cur.children.append(n)
                pending = []
            if len(stack) == 1:
                add_error(line, "unexpected '}'")
            else:
                stack.pop()
    if pending:
        add_error(pline, "missing ';' at end of file")
    if len(stack) > 1:
        add_error(stack[-1].line, "unclosed block '%s'" % clean(stack[-1].name, 40))
    return root.children


def walk(nodes):
    """Depth first over nodes, descending through blocks and includes."""
    stack = [iter(nodes)]
    while stack:
        try:
            n = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        yield n
        if n.children:
            stack.append(iter(n.children))


def real_parent(node):
    return node.parent


def context_names(node):
    out = []
    p = node.parent
    while p is not None and p.name != "<root>":
        if p.name != "include":
            out.append(p.name)
        p = p.parent
    return out


# ------------------------------------------------------------------ checker

class Checker:
    def __init__(self, root=None, use_stat=True, max_size=DEFAULT_MAX_SIZE, max_depth=DEFAULT_MAX_DEPTH,
                 rebase=None):
        self.root = os.path.realpath(root) if root else None
        self.use_stat = use_stat
        self.max_size = max_size
        self.max_depth = max_depth
        self.rebase = rebase.rstrip("/") if rebase else None
        self.findings = []
        self.errors = []
        self.files = []
        self.trees = []
        self._seen = set()
        self._chain = []

    def add(self, file, line, sev, fid, msg):
        key = (file, line, fid, msg)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({"file": clean(file), "line": line, "severity": sev, "id": fid,
                              "message": clean(msg, 500)})

    def err(self, msg):
        self.errors.append(clean(msg, 500))

    # -- loading
    def add_text(self, name, text, prefix=None, depth=0):
        self.files.append(clean(name))
        nodes = parse_tokens(tokenize(text), name,
                             lambda ln, m: self.add(name, ln, "medium", "PARSE-ERROR", m))
        for n in walk(nodes):
            if n.name == "include" and n.children is None:
                self.expand_include(n, prefix, depth)
        self.trees.append(nodes)
        return nodes

    def load_file(self, path, depth=0):
        if len(self.files) >= MAX_FILES:
            self.err("file limit (%d) reached; skipped %s" % (MAX_FILES, path))
            return None
        try:
            real = os.path.realpath(path)
            st = os.stat(path)
        except OSError as e:
            self.err("cannot read %s: %s" % (path, e.strerror or e))
            return None
        if not statmod.S_ISREG(st.st_mode):
            self.err("%s is not a regular file (skipped)" % path)
            return None
        if st.st_size > self.max_size:
            self.err("%s is larger than the %d byte cap (skipped)" % (path, self.max_size))
            return None
        if real in self._chain:
            self.add(path, 0, "low", "INCLUDE-CYCLE", "include loop detected at %s" % clean(path))
            return None
        try:
            with open(path, "rb") as fh:
                data = fh.read(self.max_size + 1)
        except OSError as e:
            self.err("cannot read %s: %s" % (path, e.strerror or e))
            return None
        if len(data) > self.max_size:
            self.err("%s is larger than the %d byte cap (skipped)" % (path, self.max_size))
            return None
        if b"\0" in data:
            self.err("%s contains NUL bytes; looks binary (skipped)" % path)
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
            self.add(path, 0, "low", "BAD-ENCODING", "file is not valid UTF-8; invalid bytes were replaced")
        self._chain.append(real)
        try:
            return self.add_text(path, text, prefix=os.path.dirname(path) or ".", depth=depth)
        finally:
            self._chain.pop()

    def expand_include(self, node, prefix, depth):
        if not node.args:
            self.add(node.file, node.line, "medium", "PARSE-ERROR", "include without a path")
            return
        pat = node.args[0]
        node.children = []
        if "$" in pat:
            self.add(node.file, node.line, "info", "INCLUDE-VARIABLE",
                     "include path %s contains a variable and is not followed" % clean(pat, 80))
            return
        if depth >= self.max_depth:
            self.add(node.file, node.line, "info", "INCLUDE-DEPTH",
                     "include depth limit (%d) reached; %s not followed" % (self.max_depth, clean(pat, 80)))
            return
        if self.root is None or prefix is None:
            self.add(node.file, node.line, "info", "INCLUDE-NOT-FOLLOWED",
                     "include %s not followed (no root directory; give a file path)" % clean(pat, 80))
            return
        if os.path.isabs(pat):
            if self.rebase and (pat == self.rebase or pat.startswith(self.rebase + "/")):
                full = os.path.join(self.root, pat[len(self.rebase):].lstrip("/"))
            else:
                full = pat
        else:
            full = os.path.join(prefix if prefix else self.root, pat)
        is_glob = any(c in pat for c in "*?[")
        try:
            matches = sorted(glob.glob(full))
        except (OSError, re.error):
            matches = []
        if len(matches) > MAX_GLOB:
            self.add(node.file, node.line, "info", "INCLUDE-GLOB-CAP",
                     "include %s matched more than %d files; only the first %d were read" % (clean(pat, 60), MAX_GLOB, MAX_GLOB))
            matches = matches[:MAX_GLOB]
        if not matches:
            if not is_glob:
                self.add(node.file, node.line, "low", "INCLUDE-NOT-FOUND",
                         "include file %s not found; nginx refuses to start when a non-glob include is missing" % clean(pat, 80))
            return
        for m in matches:
            m = os.path.normpath(m)
            try:
                rm = os.path.realpath(m)
            except OSError:
                continue
            if not self.inside_root(rm):
                self.add(node.file, node.line, "info", "INCLUDE-OUTSIDE-ROOT",
                         "include %s resolves outside the root directory and was not read" % clean(m, 100))
                continue
            sub = self.load_file(m, depth + 1)
            if sub is not None:
                for s in sub:
                    s.parent = node.parent
                node.children.extend(sub)

    def inside_root(self, real):
        try:
            return os.path.commonpath([self.root, real]) == self.root
        except ValueError:
            return False

    # -- analysis
    def analyze(self):
        servers = []
        https = []
        stream_like = []
        all_nodes = []
        for tree in self.trees:
            for n in walk(tree):
                all_nodes.append(n)
        seen_ids = set()
        for n in all_nodes:
            if id(n) in seen_ids:
                continue
            seen_ids.add(id(n))
            ctx = context_names(n)
            if n.name == "http" and n.children is not None:
                https.append(n)
            elif n.name == "server" and n.children is not None:
                top = ctx[0] if ctx else None
                if top in ("stream", "mail"):
                    stream_like.append(n)
                elif top in (None, "http") or "http" in ctx:
                    servers.append(n)
        # fragment servers (no http block seen) are treated as http servers
        for srv in servers + stream_like:
            self.check_tls(srv)
        for srv in servers:
            self.check_server_http(srv)
        for h in https:
            self.check_default_server(h.find("server"))
            self.check_headers_tree(h, None)
            self.check_server_tokens_http(h)
        frag = [s for s in servers if not any(p.name == "http" for p in self.parents(s))]
        if frag:
            self.check_default_server(frag)
            for s in frag:
                self.check_headers_tree(s, None)
        for n in all_nodes:
            self.check_node(n)
        if servers and not any(n.name.startswith("limit_req") for n in all_nodes):
            first = servers[0]
            self.add(first.file, first.line, "info", "NO-LIMIT-REQ",
                     "no limit_req / limit_req_zone anywhere; nothing slows brute force or request floods at nginx level")

    @staticmethod
    def parents(node):
        p = node.parent
        while p is not None and p.name != "<root>":
            yield p
            p = p.parent

    def eff(self, node, name):
        """Nearest directive 'name' at node or an ancestor level (last one wins)."""
        cur = node
        while cur is not None and cur.name != "<root>":
            found = cur.find(name) if cur.children is not None else []
            if found:
                return found[-1]
            cur = cur.parent
        return None

    def eff_all(self, node, name):
        cur = node
        while cur is not None and cur.name != "<root>":
            found = cur.find(name) if cur.children is not None else []
            if found:
                return found
            cur = cur.parent
        return []

    def is_tls(self, srv):
        for l in srv.find("listen"):
            if any(a in ("ssl", "quic") for a in l.args[1:]):
                return True
        return self.eff(srv, "ssl_certificate") is not None

    def check_tls(self, srv):
        if not self.is_tls(srv):
            return
        proto = self.eff(srv, "ssl_protocols")
        if proto is None:
            self.add(srv.file, srv.line, "medium", "SSL-PROTOCOLS-MISSING",
                     "TLS server without ssl_protocols; older nginx builds still allow TLSv1 and TLSv1.1. "
                     "Set 'ssl_protocols TLSv1.2 TLSv1.3;'")
        else:
            bad = [a for a in proto.args if a.lower() in ("sslv2", "sslv3", "tlsv1", "tlsv1.1")]
            for b in bad:
                sev = "high" if b.lower().startswith("ssl") else "medium"
                self.add(proto.file, proto.line, sev, "SSL-PROTOCOLS-WEAK",
                         "ssl_protocols enables %s, which is obsolete and broken" % clean(b, 20))
        ciph = self.eff(srv, "ssl_ciphers")
        if ciph is not None and ciph.args:
            self.check_ciphers(ciph)
        for k in self.eff_all(srv, "ssl_certificate_key"):
            self.check_key(k)

    def check_ciphers(self, ciph):
        spec = ciph.args[0]
        toks = [t for t in re.split(r"[:, ]", spec) if t]
        negated = set()
        for t in toks:
            if t[0] in "!-":
                negated.add(t[1:].upper())
        found = {}
        for t in toks:
            if t[0] in "!-+@":
                continue
            u = t.upper()
            for part in u.split("+"):
                part = part.replace("-", "") if part in ("A-NULL", "E-NULL") else part
                if part in WEAK_CIPHER_TOKENS and part not in negated and not (part == "ANULL" and "ANULL" in negated):
                    found[part] = WEAK_CIPHER_TOKENS[part]
            if u in ("ALL", "COMPLEMENTOFALL"):
                if not ({"ANULL", "ENULL"} <= negated):
                    found["ALL"] = "medium"
            if u == "3DES" or u == "DES-CBC3-SHA":
                found["3DES"] = "medium"
        for k, sev in sorted(found.items()):
            if k == "ALL":
                msg = "ssl_ciphers uses ALL without excluding aNULL and eNULL, which enables unauthenticated and unencrypted suites"
            else:
                msg = "ssl_ciphers allows weak cipher class %s" % k
            self.add(ciph.file, ciph.line, sev, "SSL-CIPHERS-WEAK", msg)

    def check_key(self, k):
        if not k.args or not self.use_stat:
            return
        path = k.args[0]
        if "$" in path or path.startswith(("data:", "engine:")):
            return
        if not os.path.isabs(path):
            base = self.root or "."
            path = os.path.join(base, path)
        try:
            st = os.stat(path)
        except OSError:
            self.add(k.file, k.line, "info", "KEY-NOT-FOUND",
                     "ssl_certificate_key %s not found on this host; permissions not checked" % clean(k.args[0], 100))
            return
        mode = statmod.S_IMODE(st.st_mode)
        if mode & 0o006:
            self.add(k.file, k.line, "high", "KEY-WORLD-ACCESS",
                     "private key %s has mode %04o and is accessible to every local user" % (clean(k.args[0], 100), mode))
        elif mode & 0o020:
            self.add(k.file, k.line, "medium", "KEY-GROUP-WRITABLE",
                     "private key %s has mode %04o and is group-writable" % (clean(k.args[0], 100), mode))
        elif mode & 0o040:
            self.add(k.file, k.line, "info", "KEY-GROUP-READABLE",
                     "private key %s has mode %04o and is group-readable; make sure the group is minimal" % (clean(k.args[0], 100), mode))

    # per server (http)
    def listens(self, srv):
        out = []
        for l in srv.find("listen"):
            if not l.args:
                continue
            addr = l.args[0]
            m = re.search(r":(\d+)$", addr)
            if m:
                port = int(m.group(1))
            elif addr.isdigit():
                port = int(addr)
            else:
                port = 80
            flags = l.args[1:]
            out.append({"addr": addr, "port": port, "ssl": any(a in ("ssl", "quic") for a in flags),
                        "default": any(a in ("default_server", "default") for a in flags), "node": l})
        return out

    def check_server_http(self, srv):
        ls = self.listens(srv)
        if not ls:
            ls = [{"addr": "*:80", "port": 80, "ssl": False, "default": False, "node": srv}]
        plain = [l for l in ls if not l["ssl"] and not l["addr"].startswith("unix:")
                 and not re.match(r"^(127\.\d+\.\d+\.\d+|\[::1\]|localhost)(:\d+)?$", l["addr"])]
        if not plain:
            return
        if self.has_redirect(srv) or self.has_early_deny(srv):
            return
        names = set(a for n in srv.find("server_name") for a in n.args if a != "_")
        tls_names = set()
        for s in self.all_servers():
            if s is not srv and self.is_tls(s):
                tls_names.update(a for n in s.find("server_name") for a in n.args)
        if names & tls_names:
            self.add(srv.file, srv.line, "medium", "HTTP-NO-REDIRECT",
                     "plain HTTP server for %s has a TLS twin but does not redirect to https; users can stay on cleartext"
                     % clean(", ".join(sorted(names & tls_names)), 100))
        else:
            self.add(srv.file, srv.line, "low", "HTTP-NO-REDIRECT",
                     "server listens on plain HTTP (port %d) and does not redirect to https" % plain[0]["port"])

    def all_servers(self):
        out = []
        for tree in self.trees:
            for n in walk(tree):
                if n.name == "server" and n.children is not None and "stream" not in context_names(n) and "mail" not in context_names(n):
                    out.append(n)
        return out

    def has_redirect(self, srv):
        for n in walk(srv.children or []):
            if n.name == "return" and n.args and re.match(r"^30[1278]$", n.args[0]):
                if len(n.args) > 1 and n.args[1].lower().startswith("https://"):
                    return True
            if n.name == "rewrite" and len(n.args) >= 2 and n.args[1].lower().startswith("https://"):
                return True
        return False

    def has_early_deny(self, srv):
        for n in srv.find("return"):
            if n.args and re.match(r"^(4\d\d)$", n.args[0]):
                return True
        return False

    def check_default_server(self, servers):
        groups = {}
        for s in servers:
            for l in self.listens(s):
                if l["addr"].startswith("unix:"):
                    continue
                groups.setdefault(l["port"], []).append((s, l))
        for port, items in sorted(groups.items()):
            uniq = []
            for s, l in items:
                if s not in uniq:
                    uniq.append(s)
            if len(uniq) >= 2 and not any(l["default"] for s, l in items):
                s = uniq[0]
                self.add(s.file, s.line, "low", "DEFAULT-SERVER-MISSING",
                         "%d servers share port %d but none is marked default_server; requests with an unknown Host go to "
                         "the first one. Add a catch-all that returns 444" % (len(uniq), port))

    def check_server_tokens_http(self, http):
        servers = http.find("server")
        top = http.find("server_tokens")
        bad = False
        for t in top:
            if t.args and t.args[0] in ("on", "build"):
                bad = True
                self.add(t.file, t.line, "medium" if t.args[0] == "on" else "low", "SERVER-TOKENS-ON",
                         "server_tokens %s exposes the nginx version in headers and error pages" % t.args[0])
        if not top:
            if servers:
                unset = [s for s in servers if not s.find("server_tokens")]
                if unset:
                    self.add(http.file, http.line, "low", "SERVER-TOKENS-DEFAULT",
                             "server_tokens is not set to off in http; nginx defaults to on and shows its version "
                             "(%d server(s) inherit that)" % len(unset))

    def check_headers_tree(self, start, inherited):
        # iterative: (node, inherited headers dict)
        stack = [(start, inherited)]
        while stack:
            node, inh = stack.pop()
            own = self.headers_of(node)
            effective = own if own else inh
            if own and inh:
                lost = [h for h in inh if h not in own]
                if lost and node.name in ("server", "location", "if", "limit_except"):
                    sec = [h for h in lost if h in SECURITY_HEADERS]
                    self.add(node.file, node.line, "medium" if sec else "low", "ADD-HEADER-INHERITANCE",
                             "add_header here replaces every add_header from the level above; %s no longer sent in this %s"
                             % (clean(", ".join(sorted(lost)), 100) + (" is" if len(lost) == 1 else " are"), node.name))
            if node.name == "server" and node.children is not None and "stream" not in context_names(node):
                if self.is_tls(node):
                    self.check_security_headers(node, effective or {})
            for c in node.eff_children():
                if c.children is not None and c.name in ("http", "server", "location", "if", "limit_except"):
                    stack.append((c, effective))

    @staticmethod
    def headers_of(node):
        out = {}
        for h in node.find("add_header"):
            if h.args:
                out.setdefault(h.args[0].lower(), []).append(h)
        return out

    def check_security_headers(self, srv, eff):
        need = [("strict-transport-security", "medium", "HSTS-MISSING",
                 "TLS server without Strict-Transport-Security; browsers can be downgraded to HTTP"),
                ("x-frame-options", "low", "XFO-MISSING", "TLS server without X-Frame-Options (clickjacking)"),
                ("x-content-type-options", "low", "XCTO-MISSING",
                 "TLS server without X-Content-Type-Options: nosniff (MIME sniffing)")]
        for h, sev, fid, msg in need:
            present = h in eff
            if h == "x-frame-options" and not present:
                for d in eff.get("content-security-policy", []):
                    if any("frame-ancestors" in a for a in d.args):
                        present = True
            if not present:
                self.add(srv.file, srv.line, sev, fid, msg)
        for d in eff.get("strict-transport-security", []):
            val = " ".join(d.args[1:])
            m = re.search(r"max-age\s*=\s*(\d+)", val)
            if not m:
                self.add(d.file, d.line, "low", "HSTS-WEAK", "Strict-Transport-Security has no max-age")
            elif int(m.group(1)) < 15552000:
                self.add(d.file, d.line, "low", "HSTS-WEAK",
                         "Strict-Transport-Security max-age=%s is under 6 months" % m.group(1))

    # per node
    def check_node(self, n):
        name = n.name
        if name == "autoindex" and n.args and n.args[0] == "on":
            self.add(n.file, n.line, "medium", "AUTOINDEX-ON", "autoindex on lists directory contents to anyone")
        elif name == "server_tokens" and n.args and n.args[0] in ("on", "build") and not (n.parent is not None and n.parent.name == "http"):
            self.add(n.file, n.line, "medium" if n.args[0] == "on" else "low", "SERVER-TOKENS-ON",
                     "server_tokens %s exposes the nginx version in headers and error pages" % n.args[0])
        elif name == "client_max_body_size" and n.args and re.match(r"^0[kKmMgG]?$", n.args[0]):
            self.add(n.file, n.line, "medium", "BODY-SIZE-UNLIMITED",
                     "client_max_body_size 0 disables the request body limit")
        elif name == "proxy_pass" and n.args:
            self.check_proxy_pass(n)
        elif name == "location" and n.children is not None:
            self.check_alias(n)
        elif name == "if" and n.children is not None:
            self.check_if(n)
        elif name == "ssl_certificate_key" and n.parent is not None and n.parent.name not in ("server",):
            pass

    def check_proxy_pass(self, n):
        target = n.args[0]
        if "$" not in target:
            return
        m = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", target)
        rest = target[m.end():] if m else target
        host_part = rest.split("/", 1)[0]
        first_var = host_part.find("$")
        host_var = first_var >= 0
        if first_var > 0:
            var = re.match(r"\$\{?(\w+)\}?", host_part[first_var:])
            if var and var.group(1) in PATH_VARS:
                host_var = False  # literal host, request variable appended as a path suffix
        if host_var:
            sev = "high" if ATTACKER_VARS.search(host_part) else "medium"
            self.add(n.file, n.line, sev, "PROXY-PASS-VARIABLE",
                     "proxy_pass %s builds the upstream from a variable%s; if a client can influence it, nginx can be "
                     "pointed at internal services (SSRF)"
                     % (clean(target, 100), " controlled by the request" if sev == "high" else " (check it comes from a trusted map)"))
        else:
            self.add(n.file, n.line, "info", "PROXY-PASS-PATH-VARIABLE",
                     "proxy_pass %s appends a request variable to a fixed upstream; encoded or '..' input may reach other paths"
                     % clean(target, 100))

    def check_alias(self, loc):
        args = loc.args
        if not args:
            return
        if args[0] in LOCATION_MODS:
            mod, path = args[0], (args[1] if len(args) > 1 else "")
        else:
            mod, path = "", args[0]
        if mod in ("~", "~*", "=") or not path or path.startswith("@"):
            return
        for a in loc.find("alias"):
            if not a.args:
                continue
            apath = a.args[0]
            if not path.endswith("/") and apath.endswith("/"):
                self.add(a.file, a.line, "high", "ALIAS-TRAVERSAL",
                         "location %s has no trailing slash but alias %s does; a request such as %s../ can walk out of the "
                         "aliased directory. Make both end in '/' or neither"
                         % (clean(path, 60), clean(apath, 60), clean(path, 60)))
            elif path.endswith("/") and not apath.endswith("/") and "$" not in apath:
                self.add(a.file, a.line, "low", "ALIAS-SLASH-MISMATCH",
                         "location %s ends with '/' but alias %s does not; paths are joined without a separator"
                         % (clean(path, 60), clean(apath, 60)))

    def check_if(self, n):
        p = n.parent
        if p is None or p.name != "location":
            return
        safe = {"return", "rewrite", "set", "break", "error_page", "include"}
        bad = sorted(set(c.name for c in n.eff_children() if c.name not in safe))
        if bad:
            self.add(n.file, n.line, "medium", "IF-IN-LOCATION",
                     "'if' inside a location containing %s: 'if' creates a nested location, so other directives can be "
                     "silently ignored or applied to the wrong requests; prefer map, try_files or separate locations"
                     % clean(", ".join(bad), 100))


# ------------------------------------------------------------------ output

def build_report(chk, min_sev):
    fl = [x for x in chk.findings if SEV_RANK[x["severity"]] >= SEV_RANK[min_sev]]
    fl.sort(key=lambda x: (x["file"], x["line"], -SEV_RANK[x["severity"]], x["id"]))
    counts = {s: 0 for s in SEVERITIES}
    for x in fl:
        counts[x["severity"]] += 1
    return {"tool": "nginxcheck", "version": __version__, "files": chk.files, "findings": fl,
            "summary": counts, "errors": chk.errors}


def render_text(rep):
    out = []
    for x in rep["findings"]:
        loc = x["file"] + (":%d" % x["line"] if x["line"] else "")
        out.append("%-6s %-24s %s  %s" % (x["severity"].upper(), x["id"], loc, x["message"]))
    for e in rep["errors"]:
        out.append("ERROR  %s" % e)
    s = rep["summary"]
    out.append("%d file(s) checked; %d finding(s): %d high, %d medium, %d low, %d info"
               % (len(rep["files"]), len(rep["findings"]), s["high"], s["medium"], s["low"], s["info"]))
    return "\n".join(out)


def build_parser():
    p = argparse.ArgumentParser(prog="nginxcheck",
                                description="Lint nginx configuration for common security mistakes. Read-only.",
                                epilog="Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or input error.")
    p.add_argument("paths", nargs="*", help="nginx.conf files, or a directory (nginx.conf in it, else *.conf); '-' reads stdin; "
                                           "default /etc/nginx/nginx.conf if readable")
    p.add_argument("--root", help="directory that includes must stay inside (default: the directory of each config file)")
    p.add_argument("--rebase", metavar="PREFIX",
                   help="treat absolute include paths under PREFIX (such as /etc/nginx) as relative to --root; for audited copies")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--no-stat", action="store_true", help="do not stat ssl_certificate_key files")
    p.add_argument("--fail-on", choices=SEVERITIES, default="low", help="lowest severity that gives exit code 1 (default low)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this severity")
    p.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="include depth cap (default 8)")
    p.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE, help="max bytes read per file (default 1 MiB)")
    p.add_argument("--version", action="version", version="nginxcheck " + __version__)
    return p


def expand_inputs(paths, chk):
    out = []
    for p in paths:
        if p == "-":
            out.append("-")
            continue
        try:
            isdir = os.path.isdir(p)
        except OSError:
            isdir = False
        if isdir:
            main_conf = os.path.join(p, "nginx.conf")
            if os.path.isfile(main_conf):
                out.append(main_conf)
            else:
                try:
                    names = sorted(n for n in os.listdir(p) if n.endswith(".conf"))[:MAX_GLOB]
                except OSError as e:
                    chk.err("cannot list %s: %s" % (p, e.strerror or e))
                    continue
                out.extend(os.path.join(p, n) for n in names)
        else:
            out.append(p)
    return out


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.max_size < 1 or args.max_depth < 0:
        print("nginxcheck: --max-size must be positive and --max-depth non-negative", file=sys.stderr)
        return 2
    paths = list(args.paths)
    if not paths:
        d = "/etc/nginx/nginx.conf"
        if os.path.isfile(d) and os.access(d, os.R_OK):
            paths = [d]
        else:
            print("nginxcheck: no input and /etc/nginx/nginx.conf is not readable; pass a file path", file=sys.stderr)
            return 2
    probe = Checker(use_stat=not args.no_stat, max_size=args.max_size, max_depth=args.max_depth)
    inputs = expand_inputs(paths, probe)
    chk = None
    allfind, allerr, allfiles = [], list(probe.errors), []
    ran = False
    for p in inputs:
        root = args.root or (os.path.dirname(os.path.abspath(p)) if p != "-" else None)
        chk = Checker(root=root, use_stat=not args.no_stat, max_size=args.max_size,
                      max_depth=args.max_depth, rebase=args.rebase)
        if p == "-":
            data = sys.stdin.buffer.read(args.max_size + 1)
            if len(data) > args.max_size:
                chk.err("<stdin> is larger than the %d byte cap" % args.max_size)
            elif b"\0" in data:
                chk.err("<stdin> contains NUL bytes; looks binary")
            else:
                chk.add_text("<stdin>", data.decode("utf-8", errors="replace"))
        else:
            chk.load_file(p)
        chk.analyze()
        allfind.extend(chk.findings)
        allerr.extend(chk.errors)
        allfiles.extend(chk.files)
        ran = True
    merged = Checker()
    merged.findings, merged.errors, merged.files = allfind, allerr, allfiles
    rep = build_report(merged, args.min_severity)
    if args.json:
        print(json.dumps(rep, indent=2, sort_keys=True))
    else:
        print(render_text(rep))
    thr = SEV_RANK[args.fail_on]
    if any(SEV_RANK[x["severity"]] >= thr for x in rep["findings"]):
        return 1
    if allerr or not ran:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
