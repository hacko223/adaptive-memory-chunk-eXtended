# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :x:                |
| < 0.2   | :x:                |

Only the latest `0.3.x` release receives security fixes. Older versions are end-of-life and will not be patched — please upgrade before reporting an issue tied to an unsupported version.

## Reporting a Vulnerability

If you discover a security vulnerability in amcx, please **do not open a public issue**. Instead, report it privately by opening a [GitHub Security Advisory](https://github.com/hacko223/adaptive-memory-chunk-eXtended/security/advisories/new) on this repository.

When reporting, please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce it (a minimal code sample helps a lot)
- The version of `amcx` you tested against
- Whether the issue affects `detection.py` (bypass detection), the `.amcx` file format itself, or another part of the library

### What to expect

- You will get an initial response within **5 business days**.
- We will confirm whether the issue is accepted or declined within **14 days** of the initial response.
- If accepted, we will work on a fix and aim to release a patched version as soon as possible. You will be credited in the changelog unless you prefer to stay anonymous.
- If declined, we will explain why (e.g. not reproducible, out of scope, or working as intended).

### Scope

This policy covers the `amcx` Python package itself — the `.amcx` binary format, the reader/writer, compression, mirror/recovery, and the `detection.py` bypass scanner. It does not cover third-party code that uses `amcx`, nor the `docs/` website hosted via GitHub Pages.

Thank you for helping keep amcx and its users safe.
