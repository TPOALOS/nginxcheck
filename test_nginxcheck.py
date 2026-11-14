import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

import nginxcheck as nc

TLS_OK = """
server {
    listen 443 ssl;
    server_name a.example.com;
    ssl_certificate /etc/ssl/a.pem;
    ssl_certificate_key /etc/ssl/a.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
}
"""


def check(text, use_stat=False):
    c = nc.Checker(use_stat=use_stat)
    c.add_text("t.conf", text)
    c.analyze()
    return c


def ids(c):
    return [f["id"] for f in c.findings]


def sev(c, fid):
    return [f["severity"] for f in c.findings if f["id"] == fid]


def http(body):
    return "http {\n%s\n}\n" % body


def run_cli(argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    old = nc.sys.stdin
    if stdin is not None:
        class FakeIn:
            buffer = io.BytesIO(stdin)
        nc.sys.stdin = FakeIn()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = nc.main(argv)
            except SystemExit as e:
                code = e.code
    finally:
        nc.sys.stdin = old
    return code, out.getvalue(), err.getvalue()


class TestTokenizer(unittest.TestCase):
    def toks(self, t):
        return [(k, v) for k, v, _ in nc.tokenize(t)]

    def test_basic(self):
        self.assertEqual(self.toks("a b;"), [("w", "a"), ("w", "b"), (";", ";")])

    def test_comment_skipped(self):
        self.assertEqual(self.toks("# hi\na;"), [("w", "a"), (";", ";")])

    def test_hash_inside_word_kept(self):
        self.assertEqual(self.toks("a b#c;")[1], ("w", "b#c"))

    def test_quoted_semicolon(self):
        self.assertEqual(self.toks('add_header X "a;b";')[2], ("w", "a;b"))

    def test_quoted_brace(self):
        self.assertEqual(self.toks("x '{';")[1], ("w", "{"))

    def test_single_quotes(self):
        self.assertEqual(self.toks("x 'a b';")[1], ("w", "a b"))

    def test_unterminated_quote(self):
        self.assertEqual(self.toks('x "abc')[-1][0], "err")

    def test_variable_braces(self):
        self.assertEqual(self.toks("set $a ${b};")[2], ("w", "${b}"))

    def test_line_numbers(self):
        self.assertEqual([l for _, _, l in nc.tokenize("a;\n\nb;")], [1, 1, 3, 3])

    def test_block_tokens(self):
        self.assertEqual([k for k, _ in self.toks("s { a; }")], ["w", "{", "w", ";", "}"])


class TestParser(unittest.TestCase):
    def parse(self, t):
        errs = []
        nodes = nc.parse_tokens(nc.tokenize(t), "t", lambda l, m: errs.append(m))
        return nodes, errs

    def test_nested(self):
        nodes, errs = self.parse("http { server { listen 80; } }")
        self.assertEqual(errs, [])
        self.assertEqual(nodes[0].children[0].children[0].args, ["80"])

    def test_missing_semicolon_before_brace(self):
        nodes, errs = self.parse("http { a b }")
        self.assertTrue(errs)

    def test_unclosed_block(self):
        _, errs = self.parse("http { a;")
        self.assertTrue(any("unclosed" in e for e in errs))

    def test_extra_close(self):
        _, errs = self.parse("a; }")
        self.assertTrue(errs)

    def test_missing_semicolon_eof(self):
        _, errs = self.parse("a b")
        self.assertTrue(errs)

    def test_deep_nesting_capped(self):
        _, errs = self.parse("a {" * 500)
        self.assertTrue(any("nesting" in e for e in errs))

    def test_parse_error_reported_as_finding(self):
        c = check("http { server { listen 80;")
        self.assertIn("PARSE-ERROR", ids(c))

    def test_empty_directive(self):
        _, errs = self.parse(";;")
        self.assertTrue(errs)

    def test_location_args(self):
        nodes, _ = self.parse("location ~* \\.php$ { return 404; }")
        self.assertEqual(nodes[0].args, ["~*", "\\.php$"])


class TestTokensVersion(unittest.TestCase):
    def test_on_explicit(self):
        c = check(http("server_tokens on;"))
        self.assertEqual(sev(c, "SERVER-TOKENS-ON"), ["medium"])

    def test_off_clean(self):
        c = check(http("server_tokens off;"))
        self.assertNotIn("SERVER-TOKENS-ON", ids(c))
        self.assertNotIn("SERVER-TOKENS-DEFAULT", ids(c))

    def test_default_when_unset(self):
        c = check(http("server { listen 80; }"))
        self.assertIn("SERVER-TOKENS-DEFAULT", ids(c))

    def test_on_in_server(self):
        c = check(http("server_tokens off;\nserver { server_tokens on; }"))
        self.assertIn("SERVER-TOKENS-ON", ids(c))

    def test_build_low(self):
        self.assertEqual(sev(check(http("server_tokens build;")), "SERVER-TOKENS-ON"), ["low"])


class TestTls(unittest.TestCase):
    def test_protocols_missing(self):
        c = check(http("server { listen 443 ssl; ssl_certificate a; ssl_certificate_key b; }"))
        self.assertIn("SSL-PROTOCOLS-MISSING", ids(c))

    def test_protocols_inherited_from_http(self):
        c = check(http("ssl_protocols TLSv1.2;\nserver { listen 443 ssl; }"))
        self.assertNotIn("SSL-PROTOCOLS-MISSING", ids(c))

    def test_sslv3_high(self):
        c = check(http("server { listen 443 ssl; ssl_protocols SSLv3 TLSv1.2; }"))
        self.assertEqual(sev(c, "SSL-PROTOCOLS-WEAK"), ["high"])

    def test_tls11_medium(self):
        c = check(http("server { listen 443 ssl; ssl_protocols TLSv1.1 TLSv1.2; }"))
        self.assertEqual(sev(c, "SSL-PROTOCOLS-WEAK"), ["medium"])

    def test_good_protocols(self):
        c = check(http("server { listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3; }"))
        self.assertNotIn("SSL-PROTOCOLS-WEAK", ids(c))
        self.assertNotIn("SSL-PROTOCOLS-MISSING", ids(c))

    def test_non_tls_server_not_checked(self):
        c = check(http("server { listen 80; }"))
        self.assertNotIn("SSL-PROTOCOLS-MISSING", ids(c))

    def test_ciphers_rc4(self):
        c = check(http("server { listen 443 ssl; ssl_ciphers HIGH:RC4; }"))
        self.assertIn("SSL-CIPHERS-WEAK", ids(c))

    def test_ciphers_negated_ok(self):
        c = check(http('server { listen 443 ssl; ssl_ciphers "HIGH:!aNULL:!MD5:!RC4:!3DES"; }'))
        self.assertNotIn("SSL-CIPHERS-WEAK", ids(c))

    def test_ciphers_null(self):
        c = check(http("server { listen 443 ssl; ssl_ciphers eNULL:HIGH; }"))
        self.assertIn("SSL-CIPHERS-WEAK", ids(c))

    def test_ciphers_all_flagged(self):
        c = check(http("server { listen 443 ssl; ssl_ciphers ALL; }"))
        self.assertIn("SSL-CIPHERS-WEAK", ids(c))

    def test_ciphers_3des(self):
        c = check(http("server { listen 443 ssl; ssl_ciphers HIGH:3DES; }"))
        self.assertIn("SSL-CIPHERS-WEAK", ids(c))

    def test_ciphers_modern_clean(self):
        c = check(http("server { listen 443 ssl; ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384; }"))
        self.assertNotIn("SSL-CIPHERS-WEAK", ids(c))

    def test_tls_detected_by_certificate(self):
        c = check(http("server { listen 8443; ssl_certificate a.pem; }"))
        self.assertIn("SSL-PROTOCOLS-MISSING", ids(c))

    def test_stream_server_tls(self):
        c = check("stream { server { listen 853 ssl; } }")
        self.assertIn("SSL-PROTOCOLS-MISSING", ids(c))


class TestHeaders(unittest.TestCase):
    def test_all_present_clean(self):
        c = check(http(TLS_OK))
        for i in ("HSTS-MISSING", "XFO-MISSING", "XCTO-MISSING", "HSTS-WEAK"):
            self.assertNotIn(i, ids(c))

    def test_missing_all(self):
        c = check(http("server { listen 443 ssl; ssl_protocols TLSv1.3; }"))
        for i in ("HSTS-MISSING", "XFO-MISSING", "XCTO-MISSING"):
            self.assertIn(i, ids(c))

    def test_headers_from_http_level(self):
        body = ('add_header Strict-Transport-Security "max-age=31536000";'
                "add_header X-Frame-Options DENY; add_header X-Content-Type-Options nosniff;"
                "server { listen 443 ssl; ssl_protocols TLSv1.3; }")
        c = check(http(body))
        self.assertNotIn("HSTS-MISSING", ids(c))

    def test_csp_frame_ancestors_counts(self):
        body = ('server { listen 443 ssl; ssl_protocols TLSv1.3; add_header Content-Security-Policy "frame-ancestors none";'
                'add_header Strict-Transport-Security "max-age=31536000"; add_header X-Content-Type-Options nosniff; }')
        self.assertNotIn("XFO-MISSING", ids(check(http(body))))

    def test_header_names_case_insensitive(self):
        body = ('server { listen 443 ssl; ssl_protocols TLSv1.3; add_header strict-transport-security "max-age=31536000";'
                "add_header x-frame-options DENY; add_header X-CONTENT-TYPE-OPTIONS nosniff; }")
        self.assertNotIn("HSTS-MISSING", ids(check(http(body))))

    def test_non_tls_not_flagged(self):
        c = check(http("server { listen 80; }"))
        self.assertNotIn("HSTS-MISSING", ids(c))

    def test_hsts_short_max_age(self):
        body = ('server { listen 443 ssl; ssl_protocols TLSv1.3; add_header Strict-Transport-Security "max-age=300";'
                "add_header X-Frame-Options DENY; add_header X-Content-Type-Options nosniff; }")
        self.assertIn("HSTS-WEAK", ids(check(http(body))))

    def test_inheritance_trap_location(self):
        body = TLS_OK.replace("}\n", "location /a { add_header X-Extra 1; }\n}\n", 1)
        # rebuild: put location inside server
        body = TLS_OK.rstrip()[:-1] + "location /a { add_header X-Extra 1; }\n}\n"
        c = check(http(body))
        self.assertEqual(sev(c, "ADD-HEADER-INHERITANCE"), ["medium"])

    def test_inheritance_ok_when_repeated(self):
        loc = ("location /a { add_header X-Extra 1; add_header Strict-Transport-Security \"max-age=31536000\"; "
               "add_header X-Frame-Options DENY; add_header X-Content-Type-Options nosniff; }")
        body = TLS_OK.rstrip()[:-1] + loc + "}\n"
        self.assertNotIn("ADD-HEADER-INHERITANCE", ids(check(http(body))))

    def test_inheritance_from_http_to_server(self):
        body = 'add_header X-Frame-Options DENY;\nserver { listen 80; add_header X-One 1; }'
        self.assertIn("ADD-HEADER-INHERITANCE", ids(check(http(body))))

    def test_inheritance_nonsecurity_low(self):
        body = 'server { listen 80; add_header X-A 1; location / { add_header X-B 2; } }'
        self.assertEqual(sev(check(http(body)), "ADD-HEADER-INHERITANCE"), ["low"])

    def test_no_trap_when_location_has_no_headers(self):
        body = 'server { listen 80; add_header X-A 1; location / { return 200; } }'
        self.assertNotIn("ADD-HEADER-INHERITANCE", ids(check(http(body))))


class TestLocations(unittest.TestCase):
    def test_autoindex_on(self):
        self.assertEqual(sev(check(http("server { location / { autoindex on; } }")), "AUTOINDEX-ON"), ["medium"])

    def test_autoindex_off_clean(self):
        self.assertNotIn("AUTOINDEX-ON", ids(check(http("server { location / { autoindex off; } }"))))

    def test_alias_traversal(self):
        c = check(http("server { location /img { alias /srv/img/; } }"))
        self.assertEqual(sev(c, "ALIAS-TRAVERSAL"), ["high"])

    def test_alias_matching_slashes_ok(self):
        c = check(http("server { location /img/ { alias /srv/img/; } }"))
        self.assertNotIn("ALIAS-TRAVERSAL", ids(c))

    def test_alias_both_no_slash_ok(self):
        c = check(http("server { location /img { alias /srv/img; } }"))
        self.assertNotIn("ALIAS-TRAVERSAL", ids(c))

    def test_alias_slash_mismatch(self):
        c = check(http("server { location /img/ { alias /srv/img; } }"))
        self.assertIn("ALIAS-SLASH-MISMATCH", ids(c))

    def test_alias_regex_location_skipped(self):
        c = check(http("server { location ~ ^/img { alias /srv/img/; } }"))
        self.assertNotIn("ALIAS-TRAVERSAL", ids(c))

    def test_alias_prefix_modifier(self):
        c = check(http("server { location ^~ /img { alias /srv/img/; } }"))
        self.assertIn("ALIAS-TRAVERSAL", ids(c))

    def test_body_size_unlimited(self):
        self.assertIn("BODY-SIZE-UNLIMITED", ids(check(http("client_max_body_size 0;"))))

    def test_body_size_limited(self):
        self.assertNotIn("BODY-SIZE-UNLIMITED", ids(check(http("client_max_body_size 10m;"))))

    def test_if_with_proxy_pass(self):
        c = check(http("server { location / { if ($x) { proxy_pass http://b; } } }"))
        self.assertIn("IF-IN-LOCATION", ids(c))

    def test_if_with_return_ok(self):
        c = check(http("server { location / { if ($x) { return 403; } } }"))
        self.assertNotIn("IF-IN-LOCATION", ids(c))

    def test_if_in_server_not_flagged(self):
        c = check(http("server { if ($x) { return 403; } }"))
        self.assertNotIn("IF-IN-LOCATION", ids(c))


class TestProxyPass(unittest.TestCase):
    def pp(self, target):
        return check(http("server { location / { proxy_pass %s; } }" % target))

    def test_host_var_high(self):
        self.assertEqual(sev(self.pp("http://$http_host$request_uri"), "PROXY-PASS-VARIABLE"), ["high"])

    def test_arg_var_high(self):
        self.assertEqual(sev(self.pp("http://$arg_target"), "PROXY-PASS-VARIABLE"), ["high"])

    def test_plain_var_medium(self):
        self.assertEqual(sev(self.pp("http://$backend"), "PROXY-PASS-VARIABLE"), ["medium"])

    def test_bare_variable(self):
        self.assertIn("PROXY-PASS-VARIABLE", ids(self.pp("$upstream")))

    def test_path_variable_info(self):
        c = self.pp("http://backend$request_uri")
        self.assertEqual(sev(c, "PROXY-PASS-PATH-VARIABLE"), ["info"])
        self.assertNotIn("PROXY-PASS-VARIABLE", ids(c))

    def test_static_clean(self):
        c = self.pp("http://127.0.0.1:9000")
        self.assertNotIn("PROXY-PASS-VARIABLE", ids(c))

    def test_static_with_path_clean(self):
        c = self.pp("http://backend/app/")
        self.assertEqual([i for i in ids(c) if i.startswith("PROXY")], [])


class TestServerLevel(unittest.TestCase):
    def test_no_limit_req_info(self):
        c = check(http("server { listen 80; }"))
        self.assertEqual(sev(c, "NO-LIMIT-REQ"), ["info"])

    def test_limit_req_present(self):
        c = check(http("limit_req_zone $binary_remote_addr zone=a:10m rate=5r/s;\nserver { listen 80; }"))
        self.assertNotIn("NO-LIMIT-REQ", ids(c))

    def test_default_server_missing(self):
        c = check(http("server { listen 80; server_name a; } server { listen 80; server_name b; }"))
        self.assertIn("DEFAULT-SERVER-MISSING", ids(c))

    def test_default_server_present(self):
        c = check(http("server { listen 80 default_server; return 444; } server { listen 80; server_name b; }"))
        self.assertNotIn("DEFAULT-SERVER-MISSING", ids(c))

    def test_single_server_no_default_needed(self):
        c = check(http("server { listen 80; }"))
        self.assertNotIn("DEFAULT-SERVER-MISSING", ids(c))

    def test_different_ports_not_grouped(self):
        c = check(http("server { listen 80; } server { listen 8080; }"))
        self.assertNotIn("DEFAULT-SERVER-MISSING", ids(c))

    def test_http_no_redirect(self):
        c = check(http("server { listen 80; server_name a.example.com; root /srv; }"))
        self.assertIn("HTTP-NO-REDIRECT", ids(c))

    def test_http_with_redirect_clean(self):
        c = check(http("server { listen 80; server_name a; return 301 https://$host$request_uri; }"))
        self.assertNotIn("HTTP-NO-REDIRECT", ids(c))

    def test_redirect_in_location(self):
        c = check(http("server { listen 80; location / { return 308 https://$host$request_uri; } }"))
        self.assertNotIn("HTTP-NO-REDIRECT", ids(c))

    def test_http_deny_catchall_clean(self):
        c = check(http("server { listen 80 default_server; return 444; }"))
        self.assertNotIn("HTTP-NO-REDIRECT", ids(c))

    def test_loopback_listener_skipped(self):
        c = check(http("server { listen 127.0.0.1:8080; root /srv; }"))
        self.assertNotIn("HTTP-NO-REDIRECT", ids(c))

    def test_twin_raises_severity(self):
        c = check(http("server { listen 80; server_name a.example.com; }\n" + TLS_OK))
        self.assertEqual(sev(c, "HTTP-NO-REDIRECT"), ["medium"])

    def test_fragment_server_without_http(self):
        c = check("server { listen 80; server_name a; }")
        self.assertIn("HTTP-NO-REDIRECT", ids(c))


class TestFilesAndIncludes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        os.mkdir(os.path.join(self.d, "conf.d"))

    def tearDown(self):
        self.tmp.cleanup()

    def w(self, rel, text, mode=None):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        if mode is not None:
            os.chmod(p, mode)
        return p

    def load(self, rel="nginx.conf", **kw):
        c = nc.Checker(root=self.d, use_stat=kw.pop("use_stat", False), **kw)
        c.load_file(os.path.join(self.d, rel))
        c.analyze()
        return c

    def test_include_glob_followed(self):
        self.w("nginx.conf", "http { include conf.d/*.conf; }")
        self.w("conf.d/a.conf", "server { listen 80; autoindex on; }")
        self.assertIn("AUTOINDEX-ON", ids(self.load()))

    def test_include_context_inherited(self):
        self.w("nginx.conf", "http { server_tokens off; include conf.d/*.conf; }")
        self.w("conf.d/a.conf", "server { listen 443 ssl; ssl_protocols TLSv1.3; }")
        self.assertNotIn("SERVER-TOKENS-DEFAULT", ids(self.load()))

    def test_include_missing_nonglob(self):
        self.w("nginx.conf", "http { include nothere.conf; }")
        self.assertIn("INCLUDE-NOT-FOUND", ids(self.load()))

    def test_include_glob_no_match_silent(self):
        self.w("nginx.conf", "http { include conf.d/*.conf; }")
        self.assertNotIn("INCLUDE-NOT-FOUND", ids(self.load()))

    def test_include_outside_root_not_read(self):
        with tempfile.TemporaryDirectory() as other:
            with open(os.path.join(other, "x.conf"), "w") as f:
                f.write("server { autoindex on; }")
            self.w("nginx.conf", "http { include %s/x.conf; }" % other)
            c = self.load()
            self.assertIn("INCLUDE-OUTSIDE-ROOT", ids(c))
            self.assertNotIn("AUTOINDEX-ON", ids(c))

    def test_include_dotdot_blocked(self):
        with tempfile.TemporaryDirectory() as other:
            with open(os.path.join(other, "x.conf"), "w") as f:
                f.write("server { autoindex on; }")
            sub = os.path.join(self.d, "sub")
            os.mkdir(sub)
            self.w("sub/nginx.conf", "http { include ../../%s/x.conf; }" % os.path.basename(other))
            c = nc.Checker(root=sub, use_stat=False)
            c.load_file(os.path.join(sub, "nginx.conf"))
            c.analyze()
            self.assertNotIn("AUTOINDEX-ON", ids(c))

    def test_symlink_escape_blocked(self):
        with tempfile.TemporaryDirectory() as other:
            with open(os.path.join(other, "x.conf"), "w") as f:
                f.write("server { autoindex on; }")
            os.symlink(os.path.join(other, "x.conf"), os.path.join(self.d, "conf.d", "link.conf"))
            self.w("nginx.conf", "http { include conf.d/*.conf; }")
            c = self.load()
            self.assertNotIn("AUTOINDEX-ON", ids(c))
            self.assertIn("INCLUDE-OUTSIDE-ROOT", ids(c))

    def test_include_cycle_terminates(self):
        self.w("nginx.conf", "http { include a.conf; }")
        self.w("a.conf", "include b.conf;")
        self.w("b.conf", "include a.conf;")
        c = self.load()
        self.assertIn("INCLUDE-CYCLE", ids(c))

    def test_self_include_terminates(self):
        self.w("nginx.conf", "include nginx.conf;")
        self.assertIn("INCLUDE-CYCLE", ids(self.load()))

    def test_depth_cap(self):
        for i in range(12):
            self.w("f%d.conf" % i, "include f%d.conf;" % (i + 1))
        self.w("f12.conf", "autoindex on;")
        c = self.load("f0.conf", max_depth=3)
        self.assertIn("INCLUDE-DEPTH", ids(c))
        self.assertNotIn("AUTOINDEX-ON", ids(c))

    def test_include_variable_not_followed(self):
        self.w("nginx.conf", "include $x/*.conf;")
        self.assertIn("INCLUDE-VARIABLE", ids(self.load()))

    def test_rebase_absolute_include(self):
        self.w("nginx.conf", "http { include /etc/nginx/conf.d/*.conf; }")
        self.w("conf.d/a.conf", "server { autoindex on; }")
        c = self.load(rebase="/etc/nginx")
        self.assertIn("AUTOINDEX-ON", ids(c))

    def test_size_cap(self):
        self.w("nginx.conf", "# " + "a" * 5000)
        c = self.load(max_size=100)
        self.assertTrue(c.errors)

    def test_binary_rejected(self):
        p = os.path.join(self.d, "nginx.conf")
        with open(p, "wb") as f:
            f.write(b"\x00\x01\x02")
        c = self.load()
        self.assertTrue(c.errors)
        self.assertEqual(c.files, [])

    def test_bad_encoding(self):
        p = os.path.join(self.d, "nginx.conf")
        with open(p, "wb") as f:
            f.write(b"# \xff\xfe\nhttp { }\n")
        self.assertIn("BAD-ENCODING", ids(self.load()))

    def test_fifo_skipped(self):
        p = os.path.join(self.d, "nginx.conf")
        os.mkfifo(p)
        c = self.load()
        self.assertTrue(c.errors)

    def test_symlink_loop(self):
        p = os.path.join(self.d, "nginx.conf")
        os.symlink(p, p)
        self.assertTrue(self.load().errors)

    def test_missing_file(self):
        c = nc.Checker(root=self.d)
        c.load_file(os.path.join(self.d, "nope.conf"))
        self.assertTrue(c.errors)

    def test_key_world_readable(self):
        self.w("a.key", "k", 0o644)
        self.w("nginx.conf", "http { server { listen 443 ssl; ssl_certificate a.pem; ssl_certificate_key a.key; } }")
        c = self.load(use_stat=True)
        self.assertEqual(sev(c, "KEY-WORLD-ACCESS"), ["high"])

    def test_key_private_clean(self):
        self.w("a.key", "k", 0o600)
        self.w("nginx.conf", "http { server { listen 443 ssl; ssl_certificate a.pem; ssl_certificate_key a.key; } }")
        c = self.load(use_stat=True)
        self.assertFalse([i for i in ids(c) if i.startswith("KEY-")])

    def test_key_group_readable_info(self):
        self.w("a.key", "k", 0o640)
        self.w("nginx.conf", "http { server { listen 443 ssl; ssl_certificate a.pem; ssl_certificate_key a.key; } }")
        self.assertEqual(sev(self.load(use_stat=True), "KEY-GROUP-READABLE"), ["info"])

    def test_key_no_stat(self):
        self.w("a.key", "k", 0o644)
        self.w("nginx.conf", "http { server { listen 443 ssl; ssl_certificate a.pem; ssl_certificate_key a.key; } }")
        self.assertNotIn("KEY-WORLD-ACCESS", ids(self.load(use_stat=False)))

    def test_key_missing_info(self):
        self.w("nginx.conf", "http { server { listen 443 ssl; ssl_certificate a.pem; ssl_certificate_key gone.key; } }")
        self.assertIn("KEY-NOT-FOUND", ids(self.load(use_stat=True)))

    def test_key_variable_path_skipped(self):
        self.w("nginx.conf", "http { server { listen 443 ssl; ssl_certificate a.pem; ssl_certificate_key /k/$ssl_server_name.key; } }")
        self.assertFalse([i for i in ids(self.load(use_stat=True)) if i.startswith("KEY-")])

    def test_control_chars_sanitised(self):
        self.w("nginx.conf", "http { server { location /\x1b[31m { autoindex on; } } }")
        rep = nc.build_report(self.load(), "info")
        self.assertNotIn("\x1b", nc.render_text(rep))


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def w(self, name, text):
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    CLEAN = ("http { server_tokens off; limit_req_zone $binary_remote_addr zone=a:1m rate=1r/s;\n"
             "server { listen 80 default_server; return 444; } }\n")

    def test_clean_exit_0(self):
        code, out, _ = run_cli(["--no-stat", self.w("nginx.conf", self.CLEAN)])
        self.assertEqual(code, 0, out)

    def test_findings_exit_1(self):
        p = self.w("nginx.conf", "http { server_tokens on; }")
        code, out, _ = run_cli([p])
        self.assertEqual(code, 1)
        self.assertIn("SERVER-TOKENS-ON", out)

    def test_missing_file_exit_2(self):
        code, _, _ = run_cli([os.path.join(self.d, "none.conf")])
        self.assertEqual(code, 2)

    def test_bad_flag_exit_2(self):
        code, _, _ = run_cli(["--nope"])
        self.assertEqual(code, 2)

    def test_json(self):
        p = self.w("nginx.conf", "http { server_tokens on; }")
        code, out, _ = run_cli(["--json", p])
        data = json.loads(out)
        self.assertEqual(data["tool"], "nginxcheck")
        self.assertTrue(any(f["id"] == "SERVER-TOKENS-ON" for f in data["findings"]))

    def test_directory_input(self):
        self.w("nginx.conf", "http { server_tokens on; }")
        code, out, _ = run_cli([self.d])
        self.assertEqual(code, 1)

    def test_directory_without_nginx_conf(self):
        self.w("a.conf", "server { autoindex on; }")
        code, out, _ = run_cli([self.d])
        self.assertIn("AUTOINDEX-ON", out)

    def test_stdin(self):
        code, out, _ = run_cli(["-"], stdin=b"http { server_tokens on; }")
        self.assertEqual(code, 1)
        self.assertIn("<stdin>", out)

    def test_fail_on_high(self):
        p = self.w("nginx.conf", "http { server_tokens on; }")
        code, _, _ = run_cli(["--fail-on", "high", p])
        self.assertEqual(code, 0)

    def test_min_severity(self):
        p = self.w("nginx.conf", "http { server { listen 80; } }")
        code, out, _ = run_cli(["--min-severity", "medium", p])
        self.assertNotIn("NO-LIMIT-REQ", out)

    def test_bad_max_size(self):
        code, _, _ = run_cli(["--max-size", "0", "x"])
        self.assertEqual(code, 2)

    def test_binary_exit_2(self):
        p = os.path.join(self.d, "nginx.conf")
        with open(p, "wb") as f:
            f.write(b"\x00\x00")
        code, _, _ = run_cli([p])
        self.assertEqual(code, 2)

    def test_does_not_execute(self):
        marker = os.path.join(self.d, "marker")
        p = self.w("nginx.conf", "http { server { location / { proxy_pass http://$(touch %s); } } }" % marker)
        run_cli([p])
        self.assertFalse(os.path.exists(marker))

    def test_fuzz_no_crash(self):
        import random
        rnd = random.Random(11)
        alphabet = list("http server{};# \n\"'$location alias /autoindex on\\\x00\x1b")
        for _ in range(300):
            txt = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 150)))
            c = nc.Checker(use_stat=False)
            c.add_text("fuzz", txt)
            c.analyze()


if __name__ == "__main__":
    unittest.main()
