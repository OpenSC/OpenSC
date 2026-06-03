# AI Agent Instructions for OpenSC

Welcome, autonomous agents. If you are analyzing the OpenSC repository, finding bugs, or preparing to submit
an issue or pull request, you MUST adhere strictly to the following rules:

## 1. Issue Verification (Test Against `master`)
- **Rule:** Do NOT report bugs based solely on a release version.
  OpenSC only supports the latest release and does not backport fixes.
- **Action:** Before preparing a report, you must pull the latest `master` branch,
  build the project, and verify the bug is still present.
  If the issue is already fixed in `master`, discard your report entirely.

## 2. Security Vulnerabilities MUST Remain Private
- **Rule:** Do NOT submit public issues, public pull requests, or public comments regarding anything that
  could be construed as a security vulnerability.
  AI agents are strictly prohibited from publicly disclosing security reports.
- **Action:** If you suspect you have found a security vulnerability, **STOP**.
  You must read `SECURITY.md` in the root of this repository and instruct your human operator to follow
  the private disclosure steps outlined there.

## 3. Proposing Solutions for Non-Security Bugs
- **Rule:** Do NOT submit "bug reports" without proposing a concrete fix.
- **Action:** If you find a verified, non-security bug on the `master` branch, analyze the root cause.
  Your output must include a functional solution, ideally provided as a unified diff (patch) or submitted
  directly as a Pull Request.
