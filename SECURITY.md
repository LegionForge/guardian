# Security Policy — legionforge-guardian

## Threat Model

Guardian protects LLM agents against **adversarial inputs that manipulate tool
execution**. Specifically:

### What Guardian Protects Against

| Threat | Guardian's Defense |
|---|---|
| **Prompt injection via tool arguments** | Check 3: 9-pattern destructive pattern detector on all tool args |
| **Unregistered tool invocation** | Check 1: tool registry — unknown tools are halted immediately |
| **Tool tampering after registration** | Checks 1+5: revocation + hash integrity verification |
| **Forbidden capability invocation** | Check 2: explicit denylist (`register_tool`, `spawn_agent_direct`, etc.) |
| **Novel tool sequences** | Check 4: sequence contracts — deviations are sandboxed |
| **Out-of-scope tool access** | Check 0: JWT task token scoping — tools outside the token's grant are blocked |
| **Emergent threat patterns** | Check 6: adaptive rules hot-reloaded from DB without restart |
| **Audit trail tampering** | SHA-256 hash chain on every check result — verifiable offline |

### What Guardian Does NOT Protect Against

Guardian is a **tool-invocation firewall**, not a full security solution. It does
not protect against:

- **Prompt injection in LLM outputs that don't reach tool calls.** If an injected
  prompt causes the LLM to produce harmful text without calling a tool, Guardian is
  not in that path.
- **Compromised tool implementations.** Guardian validates that the right tool is
  called with safe arguments. It does not sandbox the tool's execution environment.
- **Model-level attacks** (jailbreaks, training data poisoning, model extraction).
  These operate above or below Guardian's enforcement boundary.
- **Network-level attacks on the sidecar itself.** Guardian should run on localhost
  and should not be exposed to the internet. Treat it as an internal trust boundary,
  not an internet-facing service.
- **Insider threats.** An operator with DB access can modify `tool_registry` or
  `threat_rules` directly. Guardian trusts its own database.
- **Zero-day patterns not in the current pattern set.** The 9-pattern destructive
  pattern detector covers known adversarial techniques. Novel attack patterns require
  new rules (via adaptive rules or a code update).

### Deployment Security Notes

- Run Guardian on `127.0.0.1` (localhost), not `0.0.0.0`, unless you have network
  controls in place. The `/check` endpoint must not be internet-accessible.
- `TASK_TOKEN_SECRET` must be set in production (`GUARDIAN_REQUIRE_AUTH=true`).
  Store it in a secrets manager (Vault, AWS Secrets Manager, macOS Keychain) —
  not in plaintext environment files.
- The PostgreSQL user Guardian connects with should have `SELECT/INSERT` only on
  `tool_registry`, `threat_rules`, `threat_events`, and `audit_log`. Do not grant
  `DROP`, `CREATE`, or `TRUNCATE`.
- Guardian's audit log (`audit_log` table) uses a SHA-256 hash chain. Do not delete
  rows — use the `prune_audit_log()` function provided by LegionForge which
  maintains the chain integrity.

---

## Vulnerability Reporting

**Please do not report security vulnerabilities in public GitHub issues.**

Report vulnerabilities to: **security@legionforge.org**

Include:
- A description of the vulnerability
- Steps to reproduce
- Affected version
- Your assessment of impact and exploitability

We will acknowledge receipt within 48 hours and provide a timeline for a fix.
Valid reports are credited in the release notes unless you prefer to remain anonymous.

### Scope

In scope for vulnerability reports:
- Authentication bypass on `/check` or `/rules`
- Pattern bypass — a proof-of-concept that gets a destructive pattern through Check 3
- Sequence contract bypass
- Hash integrity bypass (tools that pass Check 5 despite being tampered)
- Audit log forgery — producing a valid hash chain entry without the chain key
- Denial-of-service on the hot path (`/check`) via crafted input

Out of scope:
- Vulnerabilities requiring DB-level write access (insider threat — by design)
- Attacks on the LLM itself (outside Guardian's boundary)
- Issues with frameworks that Guardian is integrated into

---

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1.0 | No |
