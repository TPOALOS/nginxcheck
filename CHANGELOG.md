# Changelog

## 1.0.0

First release.

- Tokenises and parses nginx configuration (comments, quotes, blocks) and follows `include` globs inside a root directory with depth, size and file-count caps
- Checks server_tokens, TLS protocols and ciphers, HSTS / X-Frame-Options / X-Content-Type-Options, the add_header inheritance trap, autoindex, alias traversal, proxy_pass variables, `if` in location, unlimited body size, missing limit_req, missing default_server, plain HTTP without redirect, private key permissions
- Read-only; text and `--json` output; exit code 0 clean, 1 findings, 2 input error
