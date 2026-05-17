"""
ServiceNow → Jira Story Creator  (SPN AAD + Azure Key Vault Edition)
====================================================================
Batch script — use for:
  • Initial backfill of tickets assigned before webhook was live
  • Scheduled sync jobs (cron / Azure Functions Timer Trigger)
  • Manual re-runs after outages

Authenticates to Azure Key Vault using SPN (ClientSecretCredential).
SNOW_PASS and JIRA_API_TOKEN are pulled from Key Vault — never from .env.

Requirements:
    pip install requests python-dotenv azure-identity azure-keyvault-secrets

Run:
    python snow_jira_creator.py

.env — what goes here vs Key Vault:
─────────────────────────────────────────────────────────────────────
    # SPN AAD credentials (used to LOGIN to Key Vault)
    AZURE_TENANT_ID             = xxxx-xxxx-xxxx-xxxx
    AZURE_CLIENT_ID             = xxxx-xxxx-xxxx-xxxx
    AZURE_CLIENT_SECRET         = <spn-client-secret>

    # Key Vault URL
    AZURE_KEYVAULT_URL          = https://your-vault.vault.azure.net/

    # Secret NAMES (just pointers — not the actual values)
    KV_SECRET_SNOW_PASS         = snow-api-password
    KV_SECRET_JIRA_TOKEN        = jira-api-token

    # ServiceNow — non-sensitive
    SNOW_INSTANCE               = your-instance.service-now.com
    SNOW_USER                   = servicenow_api_user
    SNOW_TABLE                  = sc_request
    SNOW_LIMIT                  = 50

    # Jira — non-sensitive
    JIRA_BASE_URL               = https://your-org.atlassian.net
    JIRA_USER                   = jira_service@company.com
    JIRA_PROJECT_KEY            = PROJ
    JIRA_TYPE                   = cloud

    # Team filters
    TEAM_ASSIGNMENT_GROUP       = Cloud Platform Engineering
    TEAM_MEMBERS                = alice@co.com,bob@co.com,sunita@co.com
    TEAM_CATEGORIES             = AI Platform,Data Engineering,Cloud
    TEAM_CIS                    = SafeAlign,AI-Gateway,OpenShift-Cluster
    TEAM_FILTER_STRATEGY        = group

─────────────────────────────────────────────────────────────────────
    Secrets fetched from Key Vault at startup (NEVER in .env):
        snow-api-password   → SNOW_PASS
        jira-api-token      → JIRA_API_TOKEN
"""

import os
import sys
import json
import logging
import requests
from datetime import datetime
from dotenv import load_dotenv

import azure_keyvault_helper as kv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            f"snow_jira_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        ),
    ],
)
log = logging.getLogger(__name__)


# ── Team Config ────────────────────────────────────────────────────────────────
class TeamConfig:
    ASSIGNMENT_GROUP = os.getenv("TEAM_ASSIGNMENT_GROUP", "").strip()
    MEMBERS = [
        m.strip() for m in os.getenv("TEAM_MEMBERS", "").split(",") if m.strip()
    ]
    CATEGORIES = [
        c.strip() for c in os.getenv("TEAM_CATEGORIES", "").split(",") if c.strip()
    ]
    CIS = [
        ci.strip() for ci in os.getenv("TEAM_CIS", "").split(",") if ci.strip()
    ]
    STRATEGY = os.getenv("TEAM_FILTER_STRATEGY", "group").strip().lower()


# ── SNOW Query Builder ─────────────────────────────────────────────────────────
class SnowQueryBuilder:
    BASE_FILTER = "active=true^stateNOT IN6,7"   # exclude Resolved + Closed

    @staticmethod
    def by_group(group_name: str) -> str:
        return f"{SnowQueryBuilder.BASE_FILTER}^assignment_group.name={group_name}"

    @staticmethod
    def by_members(emails: list) -> str:
        if not emails:
            return SnowQueryBuilder.BASE_FILTER
        return (
            f"{SnowQueryBuilder.BASE_FILTER}"
            f"^assigned_to.email={'^ORassigned_to.email='.join(emails)}"
        )

    @staticmethod
    def by_category(categories: list) -> str:
        if not categories:
            return SnowQueryBuilder.BASE_FILTER
        return (
            f"{SnowQueryBuilder.BASE_FILTER}"
            f"^category={'^ORcategory='.join(categories)}"
        )

    @staticmethod
    def by_ci(ci_names: list) -> str:
        if not ci_names:
            return SnowQueryBuilder.BASE_FILTER
        return (
            f"{SnowQueryBuilder.BASE_FILTER}"
            f"^cmdb_ci.name={'^ORcmdb_ci.name='.join(ci_names)}"
        )

    @staticmethod
    def combined_any(
        group: str, members: list, categories: list, cis: list
    ) -> str:
        parts = []
        if group:
            parts.append(f"assignment_group.name={group}")
        for m in members:
            parts.append(f"assigned_to.email={m}")
        for c in categories:
            parts.append(f"category={c}")
        for ci in cis:
            parts.append(f"cmdb_ci.name={ci}")
        if not parts:
            return SnowQueryBuilder.BASE_FILTER
        return SnowQueryBuilder.BASE_FILTER + "^NQ" + "^OR".join(parts)

    @classmethod
    def build(cls) -> str:
        strategy = TeamConfig.STRATEGY
        if strategy == "group":
            if not TeamConfig.ASSIGNMENT_GROUP:
                raise ValueError("TEAM_ASSIGNMENT_GROUP required for strategy=group")
            q = cls.by_group(TeamConfig.ASSIGNMENT_GROUP)
        elif strategy == "members":
            if not TeamConfig.MEMBERS:
                raise ValueError("TEAM_MEMBERS required for strategy=members")
            q = cls.by_members(TeamConfig.MEMBERS)
        elif strategy == "category":
            if not TeamConfig.CATEGORIES:
                raise ValueError("TEAM_CATEGORIES required for strategy=category")
            q = cls.by_category(TeamConfig.CATEGORIES)
        elif strategy == "ci":
            if not TeamConfig.CIS:
                raise ValueError("TEAM_CIS required for strategy=ci")
            q = cls.by_ci(TeamConfig.CIS)
        elif strategy == "any":
            q = cls.combined_any(
                TeamConfig.ASSIGNMENT_GROUP, TeamConfig.MEMBERS,
                TeamConfig.CATEGORIES, TeamConfig.CIS,
            )
        else:
            raise ValueError(f"Unknown TEAM_FILTER_STRATEGY: '{strategy}'")

        log.info(f"[SNOW QUERY] Strategy='{strategy}' → {q}")
        return q


# ── Config ─────────────────────────────────────────────────────────────────────
class Config:
    """
    Non-sensitive values from .env.
    SNOW_PASS and JIRA_API_TOKEN populated only by load_secrets() at startup.
    """

    # ── Non-sensitive (from .env) ──────────────────────────────────────────
    SNOW_INSTANCE = os.getenv("SNOW_INSTANCE", "").strip()
    SNOW_BASE_URL = f"https://{SNOW_INSTANCE}/api/now"
    SNOW_USER     = os.getenv("SNOW_USER", "").strip()
    SNOW_TABLE    = os.getenv("SNOW_TABLE", "sc_request").strip()
    SNOW_LIMIT    = int(os.getenv("SNOW_LIMIT", "50"))

    # caller_id.email dot-walked — gets actual email, not display name
    SNOW_FIELDS = (
        "sys_id,number,short_description,description,"
        "priority,urgency,impact,state,category,"
        "assigned_to,assigned_to.email,"
        "assignment_group,"
        "caller_id,caller_id.email,"
        "opened_at,sys_updated_on,cmdb_ci"
    )

    JIRA_BASE_URL = os.getenv("JIRA_BASE_URL", "").rstrip("/").strip()
    JIRA_USER     = os.getenv("JIRA_USER", "").strip()
    JIRA_PROJECT  = os.getenv("JIRA_PROJECT_KEY", "PROJ").strip()
    JIRA_TYPE     = os.getenv("JIRA_TYPE", "cloud").strip().lower()

    # Key Vault secret NAMES (pointers only — not the values)
    _KV_NAME_SNOW_PASS  = os.getenv("KV_SECRET_SNOW_PASS",  "snow-api-password")
    _KV_NAME_JIRA_TOKEN = os.getenv("KV_SECRET_JIRA_TOKEN", "jira-api-token")

    # Sensitive — populated at startup ONLY
    SNOW_PASS:      str = ""
    JIRA_API_TOKEN: str = ""

    @classmethod
    def load_secrets(cls):
        """Fetches SNOW_PASS and JIRA_API_TOKEN from Azure Key Vault via SPN."""
        log.info("[CONFIG] Loading secrets from Azure Key Vault via SPN ...")
        cls.SNOW_PASS      = kv.get_secret(cls._KV_NAME_SNOW_PASS)
        cls.JIRA_API_TOKEN = kv.get_secret(cls._KV_NAME_JIRA_TOKEN)
        log.info(
            "[CONFIG] Secrets loaded:\n"
            f"         SNOW_PASS      → Key Vault[{cls._KV_NAME_SNOW_PASS}]  ✓\n"
            f"         JIRA_API_TOKEN → Key Vault[{cls._KV_NAME_JIRA_TOKEN}] ✓"
        )

    @classmethod
    def validate(cls):
        missing_env = [
            k for k, v in {
                "SNOW_INSTANCE": cls.SNOW_INSTANCE,
                "SNOW_USER":     cls.SNOW_USER,
                "JIRA_BASE_URL": cls.JIRA_BASE_URL,
                "JIRA_USER":     cls.JIRA_USER,
            }.items() if not v
        ]
        if missing_env:
            raise EnvironmentError(
                f"Missing .env variables: {', '.join(missing_env)}"
            )

        unloaded = [
            name for name, val in [
                ("SNOW_PASS",      cls.SNOW_PASS),
                ("JIRA_API_TOKEN", cls.JIRA_API_TOKEN),
            ] if not val
        ]
        if unloaded:
            raise EnvironmentError(
                f"Key Vault secrets not loaded: {', '.join(unloaded)}"
            )

        log.info(
            f"[CONFIG] Validated ✓ | "
            f"table={cls.SNOW_TABLE} | limit={cls.SNOW_LIMIT} | "
            f"JIRA_TYPE={cls.JIRA_TYPE} | project={cls.JIRA_PROJECT}"
        )


# ── Priority Map ───────────────────────────────────────────────────────────────
PRIORITY_MAP = {
    "1 - Critical": {"name": "Highest"},
    "2 - High":     {"name": "High"},
    "3 - Moderate": {"name": "Medium"},
    "4 - Low":      {"name": "Low"},
    "5 - Planning": {"name": "Lowest"},
}


# ── ServiceNow Client ──────────────────────────────────────────────────────────
class ServiceNowClient:
    """SNOW_USER from .env — SNOW_PASS from Key Vault."""

    def __init__(self):
        self.session = requests.Session()
        self.session.auth = (Config.SNOW_USER, Config.SNOW_PASS)
        self.session.headers.update({
            "Accept": "application/json", "Content-Type": "application/json"
        })

    def get_records(self, query: str) -> list:
        url    = f"{Config.SNOW_BASE_URL}/table/{Config.SNOW_TABLE}"
        params = {
            "sysparm_query":                  query,
            "sysparm_fields":                 Config.SNOW_FIELDS,
            "sysparm_limit":                  Config.SNOW_LIMIT,
            "sysparm_display_value":          "true",
            "sysparm_exclude_reference_link": "true",
        }
        log.info(f"[SNOW] Fetching records from table='{Config.SNOW_TABLE}' ...")
        resp = self.session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        records = resp.json().get("result", [])
        log.info(f"[SNOW] {len(records)} records retrieved.")
        return records


# ── Jira Client ────────────────────────────────────────────────────────────────
class JiraClient:
    """JIRA_USER from .env — JIRA_API_TOKEN from Key Vault."""

    def __init__(self):
        self.base    = Config.JIRA_BASE_URL
        self.session = requests.Session()
        self.session.auth = (Config.JIRA_USER, Config.JIRA_API_TOKEN)
        self.session.headers.update({
            "Accept": "application/json", "Content-Type": "application/json"
        })
        self._user_cache: dict = {}

    def resolve_reporter(self, email: str):
        if not email or not email.strip():
            log.warning("  [REPORTER] No caller email — reporter omitted")
            return None
        key = email.strip().lower()
        if key in self._user_cache:
            return self._user_cache[key]
        result = (
            self._lookup_cloud(key)
            if Config.JIRA_TYPE == "cloud"
            else self._lookup_server(key)
        )
        self._user_cache[key] = result
        return result

    def _lookup_cloud(self, email: str):
        try:
            resp = self.session.get(
                f"{self.base}/rest/api/3/user/search",
                params={"query": email}, timeout=15,
            )
            if resp.status_code == 200:
                for user in resp.json():
                    if (
                        user.get("emailAddress", "").strip().lower() == email
                        and user.get("active", False)
                    ):
                        log.info(
                            f"  [REPORTER] MAPPED {email} → accountId={user['accountId']} ✓"
                        )
                        return {"accountId": user["accountId"]}
            log.warning(f"  [REPORTER] Cloud UNMAPPED: {email}")
        except Exception as exc:
            log.warning(f"  [REPORTER] Cloud error for {email}: {exc}")
        return None

    def _lookup_server(self, email: str):
        try:
            resp = self.session.get(
                f"{self.base}/rest/api/2/user/search",
                params={"username": email, "maxResults": 10}, timeout=15,
            )
            if resp.status_code == 200:
                for user in resp.json():
                    if (
                        user.get("emailAddress", "").strip().lower() == email
                        and user.get("active", False)
                    ):
                        log.info(
                            f"  [REPORTER] MAPPED {email} → name={user['name']} ✓"
                        )
                        return {"name": user["name"]}
            log.warning(f"  [REPORTER] Server UNMAPPED: {email}")
        except Exception as exc:
            log.warning(f"  [REPORTER] Server error for {email}: {exc}")
        return None

    def issue_exists(self, snow_number: str) -> bool:
        jql  = f'project = "{Config.JIRA_PROJECT}" AND summary ~ "SNOW-{snow_number}"'
        resp = self.session.get(
            f"{self.base}/rest/api/2/search",
            params={"jql": jql, "maxResults": 1}, timeout=15,
        )
        return resp.status_code == 200 and resp.json().get("total", 0) > 0

    def create_issue(self, payload: dict) -> dict:
        resp = self.session.post(
            f"{self.base}/rest/api/2/issue", json=payload, timeout=30
        )
        resp.raise_for_status()
        return resp.json()


# ── Field Mapper ───────────────────────────────────────────────────────────────
def map_to_jira(record: dict, reporter_field) -> dict:
    number       = record.get("number",            "UNKNOWN")
    short_desc   = record.get("short_description", "(No summary)")
    description  = record.get("description",       "")
    priority     = PRIORITY_MAP.get(record.get("priority", ""), {"name": "Medium"})
    group        = record.get("assignment_group",  "")
    assigned_to  = record.get("assigned_to",       "")
    category     = record.get("category",          "")
    caller       = record.get("caller_id",         "")
    caller_email = record.get("caller_id.email",   "")
    opened_at    = record.get("opened_at",         "")
    ci           = record.get("cmdb_ci",           "")
    state        = record.get("state",             "")

    body = f"""
*ServiceNow Reference:* {number}
*Assignment Group:* {group}
*Assigned To (SNOW):* {assigned_to}
*Caller / Requester:* {caller} ({caller_email})
*Category:* {category}
*Configuration Item (CI):* {ci}
*Priority (SNOW):* {record.get('priority', '')}
*State:* {state}
*Opened At:* {opened_at}

----
h3. Description

{description or '_No description provided._'}

----
_Auto-created from ServiceNow {number} | Group: {group}_
""".strip()

    fields: dict = {
        "project":     {"key": Config.JIRA_PROJECT},
        "issuetype":   {"name": "Story"},
        "summary":     f"[SNOW-{number}] {short_desc}",
        "description": body,
        "priority":    priority,
        "labels": [
            "servicenow-import",
            f"snow-{state.lower().replace(' ', '-')}",
            f"group-{group.lower().replace(' ', '-')[:30]}",
        ],
    }

    if reporter_field:
        fields["reporter"] = reporter_field

    return {"fields": fields}


# ── Orchestrator ───────────────────────────────────────────────────────────────
def run():
    log.info("=" * 65)
    log.info("[STARTUP] ServiceNow → Jira Batch Creator  v4.0.0")

    # Step 1 — SPN login → Key Vault
    log.info("[STARTUP] Connecting to Azure Key Vault via SPN ...")
    kv.init_keyvault()

    # Step 2 — fetch secrets from Key Vault
    Config.load_secrets()

    # Step 3 — validate env
    Config.validate()

    snow  = ServiceNowClient()
    jira  = JiraClient()
    query = SnowQueryBuilder.build()

    records = snow.get_records(query)
    if not records:
        log.warning("No records found. Check TEAM_* env vars and SNOW query.")
        return

    results = {
        "created":  [],
        "skipped":  [],
        "failed":   [],
        "reporter_summary": {
            "mapped":   [],
            "unmapped": [],
            "no_email": [],
        },
    }

    # User resolution cache — Jira user search called only once per email
    user_cache: dict = {}

    for rec in records:
        number       = rec.get("number", "UNKNOWN")
        group        = rec.get("assignment_group", "?")
        caller_email = rec.get("caller_id.email", "").strip().lower()

        try:
            # ── Deduplication ──────────────────────────────────────────────
            if jira.issue_exists(number):
                log.info(f"  [SKIP]   {number} | group={group} — already in Jira")
                results["skipped"].append(number)
                continue

            # ── Resolve reporter (cached) ──────────────────────────────────
            if caller_email not in user_cache:
                user_cache[caller_email] = jira.resolve_reporter(caller_email)
            reporter_field = user_cache[caller_email]

            # ── Audit trail ────────────────────────────────────────────────
            if not caller_email:
                results["reporter_summary"]["no_email"].append(number)
            elif reporter_field:
                results["reporter_summary"]["mapped"].append(
                    {"snow": number, "email": caller_email}
                )
            else:
                results["reporter_summary"]["unmapped"].append(
                    {"snow": number, "email": caller_email}
                )

            # ── Create Jira issue ──────────────────────────────────────────
            payload  = map_to_jira(rec, reporter_field)
            response = jira.create_issue(payload)
            jira_key = response.get("key", "?")
            jira_url = f"{Config.JIRA_BASE_URL}/browse/{jira_key}"

            log.info(
                f"  [CREATE] {number} → {jira_key} | "
                f"reporter={'mapped' if reporter_field else 'DEFAULT'} | "
                f"group={group}"
            )
            results["created"].append({
                "snow":            number,
                "jira":            jira_key,
                "url":             jira_url,
                "reporter_mapped": reporter_field is not None,
                "caller_email":    caller_email or "(blank)",
            })

        except requests.HTTPError as exc:
            body = exc.response.text[:300] if exc.response else ""
            log.error(
                f"  [FAIL]   {number} — HTTP {exc.response.status_code}: {body}"
            )
            results["failed"].append({
                "snow": number, "error": str(exc), "detail": body
            })
        except Exception as exc:
            log.error(f"  [FAIL]   {number} — {exc}")
            results["failed"].append({"snow": number, "error": str(exc)})

    # ── Summary ────────────────────────────────────────────────────────────────
    log.info("\n" + "=" * 65)
    log.info(
        f"DONE  "
        f"Created={len(results['created'])}  "
        f"Skipped={len(results['skipped'])}  "
        f"Failed={len(results['failed'])}"
    )
    rs = results["reporter_summary"]
    log.info(
        f"REPORTER  "
        f"Mapped={len(rs['mapped'])}  "
        f"Unmapped={len(rs['unmapped'])}  "
        f"NoEmail={len(rs['no_email'])}"
    )

    if rs["unmapped"]:
        log.warning("Unmapped reporters — users not found or inactive in Jira:")
        for item in rs["unmapped"]:
            log.warning(f"    SNOW={item['snow']}  email={item['email']}")

    if rs["no_email"]:
        log.warning("Records with blank caller email in ServiceNow:")
        for ticket in rs["no_email"]:
            log.warning(f"    SNOW={ticket}")

    out = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    log.info(f"Results saved → {out}")
    log.info("=" * 65)


if __name__ == "__main__":
    run()
