# Repository Guidelines

## Project Structure & Module Organization

This repository currently contains course references rather than an implementation. `计算机网络课程设计课件.pdf` defines the DNS Relay assignment, `RFC1035.pdf` is the protocol reference, `第14章 DNS域名系统.pdf` provides background, and `课程设计验收记录.doc` is the submission record.

Keep new work separate from these source documents. Put relay code in `src/`, automated checks in `tests/`, runtime data such as `dnsrelay.txt` in `config/`, and reports or packet captures in `docs/`. Do not modify reference PDFs to record project changes.

## Build, Test, and Development Commands

No build system, dependency manifest, or test runner is committed yet. When adding the implementation, include a root-level README with exact setup and run commands, and add one reproducible entry point such as `make run` and `make test`.

Useful checks for the current repository are:

- `pdfinfo RFC1035.pdf` — confirms PDF metadata and page count.
- `pdftotext RFC1035.pdf -` — extracts protocol text for searching.
- `find . -maxdepth 2 -type f` — reviews the submitted file set.

## Coding Style & Naming Conventions

Use UTF-8 text and four-space indentation. Apply the standard formatter for the chosen language (for example, Black for Python or clang-format for C++), and commit its configuration. Prefer descriptive protocol names such as `DnsHeader`, `parse_question`, and `upstream_server`; avoid unexplained abbreviations. Keep packet parsing, local-record lookup, upstream forwarding, and logging in separate modules.

## Testing Guidelines

Tests must cover the three required paths: a `0.0.0.0` local entry returns NXDOMAIN, a known domain returns its configured address, and an unknown domain is forwarded upstream. Also test malformed or truncated packets, transaction-ID preservation, case-insensitive domain matching, upstream timeouts, and concurrent requests. Name tests after behavior, such as `test_known_domain_returns_local_address`.

## Commit & Pull Request Guidelines

There is no Git metadata or established commit history in this directory. Until a project convention exists, use short imperative commits with scoped prefixes, for example `feat: forward uncached DNS queries` or `docs: add packet-capture results`.

Pull requests should describe behavior changes, list commands run, and link the relevant requirement. Include Wireshark screenshots or sanitized packet captures for protocol changes. Never commit credentials, private DNS data, machine-specific paths, or large generated captures.
