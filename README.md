# nginxcheck

**Catch the nginx setting that leaks your version, your files or your TLS.** nginx configs are copied between servers for years. A
`location /img` with `alias /srv/img/` lets a request walk out of the directory, `add_header` in one location silently drops the security
headers set one level up, `ssl_protocols` is forgotten and TLSv1 stays on, a private key is readable by every user. nginxcheck reads your
config (following `include` globs inside a root directory) and lists these mistakes with a severity. It never starts nginx and never runs
anything it reads.

```
$ nginxcheck nginx.conf
LOW    DEFAULT-SERVER-MISSING   conf.d/extra.conf:1  2 servers share port 80 but none is marked default_server; requests with an unknown Host go to the first one. Add a catch-all that returns 444
LOW    HTTP-NO-REDIRECT         conf.d/extra.conf:1  server listens on plain HTTP (port 80) and does not redirect to https
INFO   NO-LIMIT-REQ             conf.d/extra.conf:1  no limit_req / limit_req_zone anywhere; nothing slows brute force or request floods at nginx level
MEDIUM SERVER-TOKENS-ON         nginx.conf:4  server_tokens on exposes the nginx version in headers and error pages
MEDIUM HTTP-NO-REDIRECT         nginx.conf:5  plain HTTP server for app.example.com has a TLS twin but does not redirect to https; users can stay on cleartext
HIGH   PROXY-PASS-VARIABLE      nginx.conf:8  proxy_pass http://$http_host$request_uri builds the upstream from a variable controlled by the request; if a client can influence it, nginx can be pointed at internal services (SSRF)
MEDIUM HSTS-MISSING             nginx.conf:10  TLS server without Strict-Transport-Security; browsers can be downgraded to HTTP
LOW    XCTO-MISSING             nginx.conf:10  TLS server without X-Content-Type-Options: nosniff (MIME sniffing)
HIGH   KEY-WORLD-ACCESS         nginx.conf:14  private key keys/app.key has mode 0644 and is accessible to every local user
MEDIUM SSL-PROTOCOLS-WEAK       nginx.conf:15  ssl_protocols enables TLSv1, which is obsolete and broken
HIGH   SSL-CIPHERS-WEAK         nginx.conf:16  ssl_ciphers allows weak cipher class RC4
MEDIUM BODY-SIZE-UNLIMITED      nginx.conf:18  client_max_body_size 0 disables the request body limit
HIGH   ALIAS-TRAVERSAL          nginx.conf:19  location /img has no trailing slash but alias /srv/img/ does; a request such as /img../ can walk out of the aliased directory. Make both end in '/' or neither
MEDIUM AUTOINDEX-ON             nginx.conf:19  autoindex on lists directory contents to anyone
MEDIUM ADD-HEADER-INHERITANCE   nginx.conf:20  add_header here replaces every add_header from the level above; x-frame-options is no longer sent in this location
MEDIUM IF-IN-LOCATION           nginx.conf:22  'if' inside a location containing proxy_pass: 'if' creates a nested location, so other directives can be silently ignored or applied to the wrong requests; prefer map, try_files or separate locations
2 file(s) checked; 16 finding(s): 4 high, 8 medium, 3 low, 1 info
$ echo $?
1
```

(The sample is a small synthetic config, `nginx.conf` plus `conf.d/extra.conf`, with a `keys/app.key` of mode 0644.)

One file, standard library only, Python 3.9 or newer.

## Usage

```
nginxcheck                                  # /etc/nginx/nginx.conf, if readable
nginxcheck /etc/nginx/nginx.conf
nginxcheck ./nginx-copy/ --rebase /etc/nginx --no-stat
nginxcheck --json --fail-on high nginx.conf
cat site.conf | nginxcheck -
```

| Option | Meaning |
|---|---|
| `PATH...` | config files; a directory means `nginx.conf` inside it, or else every `*.conf` there; `-` reads stdin (includes are not followed) |
| `--root DIR` | includes must resolve inside this directory (default: the directory of the config file); anything else, including symlinks that escape it, is reported and not read |
| `--rebase PREFIX` | treat absolute includes under PREFIX (such as `/etc/nginx`) as relative to `--root`, for audited copies |
| `--no-stat` | do not look at `ssl_certificate_key` files on this host |
| `--max-depth N` | include depth cap (default 8); there is also a 200 file cap, 500 matches per glob and a 1 MiB cap per file (`--max-size`) |
| `--fail-on SEV` | lowest severity that gives exit code 1 (`info`, `low`, `medium`, `high`; default `low`) |
| `--min-severity SEV` | hide findings below this severity |
| `--json` | machine-readable output: `files`, `findings` (`file`, `line`, `severity`, `id`, `message`), `summary`, `errors` |

## What it checks

- `server_tokens on` (or left at the default) 
- TLS servers: no `ssl_protocols`, or SSLv2/SSLv3/TLSv1/TLSv1.1 enabled; weak ciphers (`NULL`, `EXPORT`, `RC4`, `DES`, `3DES`, `MD5`, `ADH`, `ALL` without `!aNULL`...) unless negated
- TLS servers missing `Strict-Transport-Security`, `X-Frame-Options` (a CSP `frame-ancestors` counts) or `X-Content-Type-Options`; HSTS with a short or missing `max-age`
- the `add_header` inheritance trap: a block with its own `add_header` drops every `add_header` from the level above
- `autoindex on`; `alias` traversal (location without trailing slash, alias with one); alias/location slash mismatch
- `proxy_pass` built from variables (high when the variable comes from the request, such as `$http_host`, `$arg_x`, `$1`; medium otherwise); request variables appended to a fixed upstream (info)
- `if` inside `location` with directives other than `return`, `rewrite`, `set`, `break`
- `client_max_body_size 0`; no `limit_req` anywhere (info)
- several servers on one port with no `default_server`; plain HTTP servers without an `https://` redirect (medium when a TLS server has the same name)
- `ssl_certificate_key` files that are world-readable or group-writable (via `stat`; info when group-readable)
- parse problems: unbalanced braces, missing semicolons, unterminated quotes, missing includes

## Exit codes

`0` nothing at or above `--fail-on`; `1` findings at or above it (parse errors count); `2` usage error, or an input could not be used (missing, binary, too large, not a regular file) and there were no findings.

## Limits

- It is a static reader. It does not run `nginx -t`, does not know your nginx version (the default TLS protocol list changed in 1.23.4, so a missing `ssl_protocols` is flagged on all versions), and does not know which modules are compiled in.
- Inheritance is modelled for the directives above only. Headers set by other means (`more_set_headers`, upstream headers, `proxy_hide_header`, Lua) are invisible, so `*-MISSING` can be a false alarm.
- `default_server` is grouped by port only, not by address, and `listen` options outside `ssl`, `quic`, `default_server` are ignored. `if`, `map`, `geo`, `lua` and `njs` bodies are parsed as ordinary blocks; Lua or njs code may produce parse errors.
- Regex `location`s with `alias` and other traversal paths (`root` plus `$uri` tricks, `try_files` oddities) are not analysed. `proxy_pass` variables are judged by name, not by tracing `map` values.
- Includes with variables are not expanded; includes outside `--root` are not read; only `http`, `stream` and `mail` servers are considered (`stream` and `mail` get the TLS checks only).
- The key check reads the real file mode of the path on this machine; for a copied config the file is usually absent, hence `--no-stat`.
- It cannot see live traffic, WAF rules, or settings made outside the files you give it.

---

**More tools by [TPOALOS](https://github.com/TPOALOS):** [cookiecheck](https://github.com/TPOALOS/cookiecheck) · [mailauth-lint](https://github.com/TPOALOS/mailauth-lint) · [dmarc-report](https://github.com/TPOALOS/dmarc-report) · [all 51 tools](https://tpoalos.github.io)
