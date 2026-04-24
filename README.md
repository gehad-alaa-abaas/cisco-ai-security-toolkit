# 🛡️ Cisco AI Security Toolkit

> A developer's guide to Cisco AI Defense and open-source AI security tools, featuring a unified Python helper script that scans prompts, audits agent tools, validates model outputs, and logs everything — before your agent ships.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Cisco AI Defense](https://img.shields.io/badge/Cisco-AI%20Defense-blue.svg)](https://www.cisco.com/c/en/us/products/security/ai-defense.html)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-green.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## Repository Structure

```
cisco-ai-security-toolkit/
│
├── README.md                          ← You are here
├── requirements.txt                   ← Python dependencies
│
├── scripts/
│   └── cisco_ai_security_helper.py   ← Unified security helper script
│
├── configs/
│   └── config.yaml                   ← Agent config for the helper script
│
└── .github/
    └── workflows/
        └── ai-security-check.yml     ← CI/CD pipeline integration
```

---

## What Is Cisco AI Defense?

**[Cisco AI Defense](https://www.cisco.com/c/en/us/products/security/ai-defense.html)** is Cisco's purpose-built security platform for organizations developing and deploying AI applications — including agentic AI systems, LLM-powered products, and AI pipelines.

| Capability | What It Protects Against |
|------------|--------------------------|
| Prompt Injection Detection | Adversarial inputs designed to hijack agent behavior |
| Model Output Validation | PII leakage, harmful content, and policy violations in responses |
| API Access Governance | Unauthorized model access, shadow AI usage |
| Agent Behavior Monitoring | Anomalous actions, policy drift at runtime |
| Data Loss Prevention for AI | Sensitive data exfiltrated via prompts or outputs |
| Compliance Reporting | Audit trails for SOC2, GDPR, HIPAA, and more |

---

## ⚠️ Security Starts With You — The Developer

Cisco AI Defense provides enterprise guardrails. But no platform compensates for two mistakes developers make before any tool is involved:

> **1. Sharing too much data with the agent**
> Every piece of context you send to a model is an attack surface. Customer records, credentials, internal system data — send the minimum required for the task. If you feed an agent your entire database, you've already lost.

> **2. Granting excessive API key privileges**
> If your agent's credentials can delete records, push to production, and send emails as executives, a single compromised session is catastrophic. Scope your keys. Use read-only where possible. Rotate aggressively.

**You are the first line of defense.**

---

## Cisco Open-Source AI Security Repos

| Repo | What It Does |
|------|-------------|
| [defenseclaw](https://github.com/cisco-ai-defense/defenseclaw) | Adversarial prompt testing — generates injection/jailbreak variants and tests your app's defenses |
| [skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Static analysis of agent tool definitions — flags overly permissive or ambiguously scoped capabilities |
| [a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner) | Multi-agent architecture analysis — detects credential sharing, context oversharing, and auth gaps between agents |
| [ai-defense-python-sdk](https://github.com/cisco-ai-defense/ai-defense-python-sdk) | Official Python SDK — programmatic access to prompt scanning, output validation, policy enforcement, and audit logging |

See [docs/cisco-repos.md](docs/cisco-repos.md) for detailed descriptions of each repo.

---

## The Helper Script

[`scripts/cisco_ai_security_helper.py`](scripts/cisco_ai_security_helper.py) combines all four tools into a single pre-deployment security check:

1. **Prompt injection scan** (DefenseClaw) — checks your test prompt for known attack patterns
2. **Tool privilege audit** (Skill Scanner) — flags overly permissive agent tools
3. **Output validation** (AI Defense SDK) — scans a test output for PII and policy violations
4. **Inter-agent message analysis** (A2A Scanner) — checks for credential sharing and missing auth
5. **Audit log** (AI Defense SDK) — writes the full assessment to a structured audit trail

---

## Getting Started

```bash
# 1. Clone the repo
git clone https://github.com/gehad-alaa-abaas/cisco-ai-security-toolkit
cd cisco-ai-security-toolkit

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy and edit the config
cp configs/config.yaml my-agent-config.yaml
# Edit my-agent-config.yaml with your agent's tools, test prompts, and test outputs

# 4. Run the assessment
python scripts/cisco_ai_security_helper.py --config my-agent-config.yaml

# 5. (Optional) Write full report to JSON
python scripts/cisco_ai_security_helper.py --config my-agent-config.yaml --output-json report.json
```

See [docs/getting-started.md](docs/getting-started.md) for full setup instructions including CI/CD integration.

---

## Additional Resources

- [Cisco AI Defense](https://www.cisco.com/c/en/us/products/security/ai-defense.html)
- [Cisco AI Defense GitHub](https://github.com/cisco-ai-defense)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [agentops-security-workflows](https://github.com/gehad-alaa-abaas/agentops-security-workflows)
- [agentic-ai-landscape](https://github.com/gehad-alaa-abaas/agentic-ai-landscape)
