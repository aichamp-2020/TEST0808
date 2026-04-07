# Platform Governance PoC

**AI-powered cloud governance agent** built with the Anthropic Claude SDK.
Validates drift detection, RBAC enforcement, onboarding checklists, and generates
audit-ready compliance reports — aligned to your Platform BRD.

---

## Architecture

```
platform_governance/
├── main.py                          # Entry point — orchestrates all agents
├── config.py                        # Config + env var loading
├── requirements.txt
├── .env.example                     # → copy to .env and fill in keys
├── agents/
│   ├── drift_detector.py            # Azure vs Terraform drift detection
│   ├── rbac_enforcer.py             # RBAC + Separation of Duties checks
│   ├── onboarding_validator.py      # Platform checklist validation
│   └── compliance_reporter.py       # Claude SDK → AI compliance narrative
└── mock_data/
    ├── terraform.tfstate.json       # Mock Terraform state (source of truth)
    └── rbac_policy.json             # Separation of duties policy
```

### What each agent does

| Agent | BRD Section | What it validates |
|---|---|---|
| `DriftDetectionAgent` | 3.1 | Azure Portal vs Terraform state vs approved code |
| `RBACEnforcementAgent` | 3.4 | Least-privilege, SOD matrix, forbidden roles |
| `OnboardingValidatorAgent` | 3.5 / 6.1 | 14-point platform checklist, mandatory gates |
| `ComplianceReportAgent` | 3.3 | Claude-generated audit narrative + remediation roadmap |

---

## Setup (Company Laptop)

### 1. Clone / copy the project

```bash
cd ~/projects
# paste the platform_governance/ folder here
cd platform_governance
```

### 2. Create virtual environment

```bash
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Mac / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
# Open .env and set your ANTHROPIC_API_KEY
```

Get your API key from: https://console.anthropic.com

---

## Running the PoC

### Full governance check (recommended)

Runs all four agents and generates `governance_report.json`:

```bash
python main.py --mode full --repo insurance-repo --env dev
```

### Run individual agents

```bash
# Drift detection only
python main.py --mode drift

# RBAC enforcement only
python main.py --mode rbac

# Onboarding checklist only
python main.py --mode onboard
```

### Different environments

```bash
python main.py --mode full --repo banking-repo --env uat
python main.py --mode full --repo insurance-repo --env prod
```

### Enable auto-revert of drifted resources

```bash
AUTO_REVERT=true python main.py --mode drift
```

---

## Expected Output

```
╭──────────────────────────────────────────────────╮
│  Platform Governance PoC                          │
│  Cloud Compliance | Drift Detection | RBAC        │
╰──────────────────────────────────────────────────╯

──── Step 1: Infrastructure Drift Detection ────
Scanning: insurance-repo [dev]

Drift Report — insurance-repo (dev)
┌─────────────────────────────┬──────────────────┬────────────────┬──────────┐
│ Resource ID                 │ Type             │ Drift Type     │ Severity │
├─────────────────────────────┼──────────────────┼────────────────┼──────────┤
│ stgplatformpoc              │ storageAccounts  │ MODIFIED       │ MEDIUM   │
│ kv-platform-poc             │ vaults           │ MODIFIED       │ HIGH     │
│ vm-rogue-001                │ virtualMachines  │ UNAUTHORIZED   │ HIGH     │
└─────────────────────────────┴──────────────────┴────────────────┴──────────┘

──── Step 2: RBAC Enforcement ────
...

──── Step 4: AI Compliance Report (Claude) ────
## Executive Summary
Overall governance posture: HIGH RISK ...
...

✅ Governance report exported to: governance_report.json
```

---

## Using with GitHub Copilot

Open the project in VS Code with Copilot enabled. Key areas where Copilot helps:

- **`agents/drift_detector.py`** → extend `_get_azure_live_state()` with real
  `azure.mgmt.resource` SDK calls. Copilot will autocomplete the client methods.
- **`agents/rbac_enforcer.py`** → extend `_get_azure_role_assignments()` with
  `AuthorizationManagementClient.role_assignments.list()`.
- **`agents/compliance_reporter.py`** → Copilot autocompletes `self.client.messages.create()`
  parameters as you type.

### Copilot prompt examples (type these as comments and let Copilot complete):

```python
# Get all role assignments for resource group using azure-mgmt-authorization
# Filter resources by tag managed_by != terraform
# Run terraform plan and capture JSON output to detect drift
# Send drift events to Azure Event Hub for audit logging
```

---

## Moving to Production

| Area | PoC (now) | Production |
|---|---|---|
| Azure state | Mock JSON | `azure.mgmt.resource.ResourceManagementClient` |
| Terraform state | Local file | Azure Blob backend via REST API |
| RBAC assignments | Mock list | `AuthorizationManagementClient.role_assignments.list()` |
| Drift revert | Log only | `subprocess.run(["terraform", "apply", "-target=..."])` |
| Report export | JSON file | Azure Blob Storage + Event Hub audit trail |
| Scheduling | Manual | Azure DevOps pipeline / cron / Logic App |

---

## Output Files

| File | Contents |
|---|---|
| `governance_report.json` | Full audit-ready JSON: drift + RBAC + onboarding + AI narrative |

---

## Security Notes

- Never commit `.env` — it contains your API key
- `AUTO_REVERT=true` should only be enabled in non-prod environments
- The `governance_report.json` may contain resource IDs — treat as internal
