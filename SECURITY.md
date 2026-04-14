# Security Policy

## Supported Versions

OpenSC releases are made roughly once a year, unless important security is discovered.

OpenSC does not release micro updates for previously released versions and does not
backport security fixes into them. Only the last release is supported.

| Version  | Supported          |
| -------- | ------------------ |
| 0.27.0+  | :white_check_mark: |
| < 0.27.0 | :x:                |

## Reporting a Vulnerability

If you discovered security vulnerability in supported version of OpenSC,
you can either report it with a button "Report a vulnerability" in
[Security tab](https://github.com/OpenSC/OpenSC/security/advisories/new)
(Do not create normal public issue with security relevant information!)
or you can send email to any recently active
project developers frankmorgner(at)gmail.com, deengert(at)gmail.com and/or
jakuje(at)gmail.com .

You can expect update on the issue no later than in two weeks.

## What Qualifies as a Security Issue

Please use the private vulnerability reporting process only for issues that have **security impact**. This includes, but is not limited to:

- Memory safety issues such as buffer overflows, use-after-free, or out-of-bounds writes
- Authentication or authorization bypasses
- Cryptographic weaknesses
- Information disclosure vulnerabilities (e.g., private keys, or PINs)
- Privilege escalation or unintended access to protected functionality
- Code execution vulnerabilities, including arbitrary code execution or command injection

The following types of issues should not be reported as security vulnerabilities and should instead be filed as normal public issues:

- Build failures or installation problems
- General bugs without security impact
- Feature requests or usability improvements
- Performance issues
- Minor crashes without a clear security implication

If you are unsure whether your finding qualifies as a security issue, please err on the side of caution and report it through the private channel.
