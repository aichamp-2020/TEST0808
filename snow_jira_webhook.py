"""
ServiceNow → Jira  AUTO-TRIGGER Webhook Listener
(SPN AAD + Azure Key Vault Edition)
=================================================
Authenticates to Azure Key Vault using Service Principal (SPN) AAD
credentials.  SNOW_PASS, JIRA_API_TOKEN and WEBHOOK_SECRET are pulled
from Key Vault at startup — they are never stored in .env.

Architecture:
    ServiceNow Record Assigned
        ↓ Business Rule fires  (snow_business_rule.js)
        ↓ POST /webhook/snow-assigned
        ↓ HMAC verified with WEBHOOK_SECRET from Key Vault
        ↓ Full record fetched from ServiceNow
        ↓ caller_id.email resolved to Jira accountId / username
        ↓ Jira Story created
        ↓ ServiceNow work_notes patched with Jira URL
        ↓ 200 OK

Requirements:
    pip install fastapi uvicorn[standard] requests python-dotenv \
                azure-identity azure-keyvault-secrets

Run (dev):
    uvicorn snow_jira_webhook:app --host 0.0.0.0 --port 8080 --reload

Run (production):
    gunicorn snow_jira_webhook:app -w 2 -k uvicorn.workers.UvicornWorker \
             --bind 0.0.0.0:8080

.env — what goes here vs Key Vault:
─────────────────────────────────────────────────────────────────────
    # SPN AAD credentials (used to LOGIN to Key Vault)
    AZURE_TENANT_ID             = xxxx-xxxx-xxxx-xxxx
    AZURE_CLIENT_ID             = xxxx-xxxx-xxxx-xxxx
    AZURE_CLIENT_SECRET         = <spn-client-secret>

    # Key Vault URL
    AZURE_KEYVAULT_URL          = https://your-vault.vault.azure.net/

    # Secret NAMES in Key Vault (just pointers — not the actual values)
    KV_SECRET_SNOW_PASS         = snow-api-password
    KV_SECRET_JIRA_TOKEN        = jira-api-token
    KV_SECRET_WEBHOOK_SECRET    = webhook-hmac-secret

    # ServiceNow — non-sensitive
    SNOW_INSTANCE               = your-instance.service-now.com
    SNOW_USER                   = servicenow_api_user

    # Jira — non-sensitive
    JIRA_BASE_URL               = https://your-org.atlassian.net
    JIRA_USER                   = jira_service@company.com
    JIRA_PROJECT_KEY            = PROJ
    JIRA_TYPE                   = cloud

    # Filters
    TEAM_ASSIGNMENT_GROUPS      = Cloud Platform Engineering,AI Platform Team

    # Writeback Jira URL to ServiceNow work_notes
    SNOW_WRITEBACK              = true

    PORT                        = 8080
─────────────────────────────────────────────────────────────────────
    Secrets fetched from Key Vault at startup (NEVER in .env):
        snow-api-password     → SNOW_PASS
        jira-api-token        → JIRA_API_TOKEN
        webhook-hmac-secret   → WEBHOOK_SECRET
"""

import hashlib
import hmac
import json
import logging
import os
import sys
from datetime import datetime
from typing import Optional

import requests
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

import azure_keyvault_helper as kv

load_dotenv()

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            f"webhook_{datetime.now().strftime('%Y%m%d')}.log"
        ),
    ],
)
log = logging.getLogger(__name__)


# ── Config ─────────────────────────────────────────────────────────────────────
class Config:
    """
    NON-SENSITIVE values read from .env at import time.
    SENSITIVE secrets populated only by load_secrets() at startup — never os.getenv().
    """

    # ── Non-sensitive (from .env) ──────────────────────────────────────────
    SNOW_INSTANCE  = os.getenv("SNOW_INSTANCE", "").strip()
    SNOW_BASE_URL  = f"https://{SNOW_INSTANCE}/api/now"
    SNOW_USER      = os.getenv("SNOW_USER", "").strip()

    JIRA_BASE_URL  = os.getenv("JIRA_BASE_URL", "").rstrip("/").strip()
    JIRA_USER      = os.getenv("JIRA_USER", "").strip()
    JIRA_PROJECT   = os.getenv("JIRA_PROJECT_KEY", "PROJ").strip()
    JIRA_TYPE      = os.getenv("JIRA_TYPE", "cloud").strip().lower()

    TEAM_GROUPS = [
        g.strip()
        for g in os.getenv("TEAM_ASSIGNMENT_GROUPS", "").split(",")
        if g.strip()
    ]

    SNOW_WRITEBACK = os.getenv("SNOW_WRITEBACK", "true").lower() == "true"

    # ── Key Vault secret NAMES (not the values) — from .env ───────────────
    _KV_NAME_SNOW_PASS      = os.getenv("KV_SECRET_SNOW_PASS",      "snow-api-password")
    _KV_NAME_JIRA_TOKEN     = os.getenv("KV_SECRET_JIRA_TOKEN",     "jira-api-token")
    _KV_NAME_WEBHOOK_SECRET = os.getenv("KV_SECRET_WEBHOOK_SECRET", "webhook-hmac-secret")

    # ── Sensitive — populated at startup by load_secrets() ONLY ───────────
    SNOW_PASS:      str = ""
    JIRA_API_TOKEN: str = ""
    WEBHOOK_SECRET: str = ""

    @classmethod
    def load_secrets(cls):
        """
        Fetches all 3 sensitive secrets from Azure Key Vault via SPN.
        Must be called after kv.init_keyvault().
        """
        log.info("[CONFIG] Loading secrets from Azure Key Vault via SPN ...")
        cls.SNOW_PASS      = kv.get_secret(cls._KV_NAME_SNOW_PASS)
        cls.JIRA_API_TOKEN = kv.get_secret(cls._KV_NAME_JIRA_TOKEN)
        cls.WEBHOOK_SECRET = kv.get_secret(cls._KV_NAME_WEBHOOK_SECRET)
        log.info(
            "[CONFIG] Secrets loaded:\n"
            f"         SNOW_PASS      → Key Vault[{cls._KV_NAME_SNOW_PASS}]   ✓\n"
            f"         JIRA_API_TOKEN → Key Vault[{cls._KV_NAME_JIRA_TOKEN}]  ✓\n"
            f"         WEBHOOK_SECRET → Key Vault[{cls._KV_NAME_WEBHOOK_SECRET}] ✓"
        )

    @classmethod
    def validate(cls):
        """Validates non-sensitive env vars and confirms secrets were loaded."""
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

        unloaded_secrets = [
            name for name, val in [
                ("SNOW_PASS",      cls.SNOW_PASS),
                ("JIRA_API_TOKEN", cls.JIRA_API_TOKEN),
                ("WEBHOOK_SECRET", cls.WEBHOOK_SECRET),
            ] if not val
        ]
        if unloaded_secrets:
            raise EnvironmentError(
                f"Key Vault secrets not loaded: {', '.join(unloaded_secrets)}\n"
                "Ensure load_secrets() completed without error."
            )

        log.info(
            f"[CONFIG] Validated ✓ | "
            f"JIRA_TYPE={cls.JIRA_TYPE} | "
            f"PROJECT={cls.JIRA_PROJECT} | "
            f"WRITEBACK={cls.SNOW_WRITEBACK} | "
            f"GROUPS={cls.TEAM_GROUPS or 'ALL'}"
        )


# ── Priority Map ───────────────────────────────────────────────────────────────
PRIORITY_MAP = {
    "1 - Critical": {"name": "Highest"},
    "2 - High":     {"name": "High"},
    "3 - Moderate": {"name": "Medium"},
    "4 - Low":      {"name": "Low"},
    "5 - Planning": {"name": "Lowest"},
}


# ── HMAC Signature Verification ───────────────────────────────────────────────
def verify_signature(raw_body: bytes, received_secret: str) -> bool:
    """
    Verifies the X-Snow-Secret header sent by the ServiceNow Business Rule
    against WEBHOOK_SECRET from Key Vault.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    if not Config.WEBHOOK_SECRET:
        log.error("[SECURITY] WEBHOOK_SECRET is empty — all requests will be rejected.")
        return False

    expected = hmac.new(
        Config.WEBHOOK_SECRET.encode(),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, received_secret or "")


# ── ServiceNow Client ──────────────────────────────────────────────────────────
class ServiceNowClient:
    """
    SNOW_USER from .env
    SNOW_PASS from Azure Key Vault (via Config.SNOW_PASS)
    """

    def __init__(self):
        self.base    = Config.SNOW_BASE_URL
        self.session = requests.Session()
        self.session.auth = (Config.SNOW_USER, Config.SNOW_PASS)
        self.session.headers.update({
            "Accept":       "application/json",
            "Content-Type": "application/json",
        })

    def get_full_record(self, table: str, sys_id: str) -> dict:
        """
        Fetches the complete record from ServiceNow.
        Dot-walks caller_id.email and assignment_group.name.
        Always fetches fresh — does not rely on the webhook payload data.
        """
        url    = f"{self.base}/table/{table}/{sys_id}"
        params = {
            "sysparm_fields": (
                "sys_id,number,short_description,description,"
                "priority,urgency,impact,state,category,"
                "assigned_to,assigned_to.email,"
                "assignment_group,assignment_group.name,"
                "caller_id,caller_id.email,"
                "opened_at,sys_updated_on,cmdb_ci"
            ),
            "sysparm_display_value":          "true",
            "sysparm_exclude_reference_link": "true",
        }
        resp = self.session.get(url, params=params, timeout=20)
        resp.raise_for_status()
        return resp.json().get("result", {})

    def write_jira_url_back(
        self, table: str, sys_id: str, jira_key: str, jira_url: str
    ):
        """
        Patches ServiceNow work_notes with the Jira story link.
        Controlled by SNOW_WRITEBACK env var. Failure is non-fatal.
        """
        if not Config.SNOW_WRITEBACK:
            return
        url     = f"{self.base}/table/{table}/{sys_id}"
        payload = {
            "work_notes": (
                f"[Auto-Sync] Jira Story created: {jira_key}\n"
                f"Link: {jira_url}"
            )
        }
        try:
            resp = self.session.patch(url, json=payload, timeout=15)
            resp.raise_for_status()
            log.info(f"  [WRITEBACK] {sys_id} patched with Jira URL ✓")
        except Exception as exc:
            log.warning(f"  [WRITEBACK] Non-fatal failure (Jira was still created): {exc}")


# ── Jira Client ────────────────────────────────────────────────────────────────
class JiraClient:
    """
    JIRA_USER from .env
    JIRA_API_TOKEN from Azure Key Vault (via Config.JIRA_API_TOKEN)
    """

    def __init__(self):
        self.base    = Config.JIRA_BASE_URL
        self.session = requests.Session()
        self.session.auth = (Config.JIRA_USER, Config.JIRA_API_TOKEN)
        self.session.headers.update({
            "Accept":       "application/json",
            "Content-Type": "application/json",
        })
        # Per-process reporter cache: email → reporter dict | None
        self._user_cache: dict[str, Optional[dict]] = {}

    # ── Reporter resolution ────────────────────────────────────────────────

    def resolve_reporter(self, email: str) -> Optional[dict]:
        """
        Maps a caller email to a Jira reporter field.
        Returns {"accountId": "..."} for Jira Cloud
             or {"name": "..."}      for Jira Server / DC
             or None if unresolvable.
        Results cached in memory — Jira user search API called only once per email.
        """
        if not email or not email.strip():
            log.warning("  [REPORTER] No caller email — reporter field will be omitted")
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

    def _lookup_cloud(self, email: str) -> Optional[dict]:
        """Jira Cloud: /rest/api/3/user/search — returns accountId."""
        try:
            resp = self.session.get(
                f"{self.base}/rest/api/3/user/search",
                params={"query": email},
                timeout=15,
            )
            if resp.status_code != 200:
                log.warning(f"  [REPORTER] Cloud search HTTP {resp.status_code} for {email}")
                return None

            for user in resp.json():
                jira_email = user.get("emailAddress", "").strip().lower()
                if jira_email == email:
                    if not user.get("active", False):
                        log.warning(f"  [REPORTER] INACTIVE Jira account for {email}")
                        return None
                    log.info(
                        f"  [REPORTER] MAPPED {email} → accountId={user['accountId']} ✓"
                    )
                    return {"accountId": user["accountId"]}

            log.warning(f"  [REPORTER] UNMAPPED — no active Jira Cloud user: {email}")
        except Exception as exc:
            log.warning(f"  [REPORTER] Cloud lookup error for {email}: {exc}")
        return None

    def _lookup_server(self, email: str) -> Optional[dict]:
        """Jira Server/DC: /rest/api/2/user/search — returns username."""
        try:
            resp = self.session.get(
                f"{self.base}/rest/api/2/user/search",
                params={"username": email, "maxResults": 10},
                timeout=15,
            )
            if resp.status_code != 200:
                log.warning(f"  [REPORTER] Server search HTTP {resp.status_code} for {email}")
                return None

            for user in resp.json():
                jira_email = user.get("emailAddress", "").strip().lower()
                if jira_email == email:
                    if not user.get("active", False):
                        log.warning(f"  [REPORTER] INACTIVE Jira Server account for {email}")
                        return None
                    log.info(
                        f"  [REPORTER] MAPPED {email} → name={user['name']} ✓"
                    )
                    return {"name": user["name"]}

            log.warning(f"  [REPORTER] UNMAPPED — no active Jira Server user: {email}")
        except Exception as exc:
            log.warning(f"  [REPORTER] Server lookup error for {email}: {exc}")
        return None

    # ── Issue operations ───────────────────────────────────────────────────

    def issue_exists(self, snow_number: str) -> bool:
        """Returns True if a Jira story for this SNOW ticket already exists."""
        jql  = f'project = "{Config.JIRA_PROJECT}" AND summary ~ "SNOW-{snow_number}"'
        resp = self.session.get(
            f"{self.base}/rest/api/2/search",
            params={"jql": jql, "maxResults": 1},
            timeout=15,
        )
        return resp.status_code == 200 and resp.json().get("total", 0) > 0

    def create_issue(self, payload: dict) -> dict:
        resp = self.session.post(
            f"{self.base}/rest/api/2/issue",
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()


# ── Field Mapper ───────────────────────────────────────────────────────────────
def build_jira_payload(record: dict, reporter_field: Optional[dict]) -> dict:
    """Converts a ServiceNow record dict into a Jira issue creation payload."""

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
_Auto-created from ServiceNow {number} on assignment event | Group: {group}_
""".strip()

    fields: dict = {
        "project":     {"key": Config.JIRA_PROJECT},
        "issuetype":   {"name": "Story"},
        "summary":     f"[SNOW-{number}] {short_desc}",
        "description": body,
        "priority":    priority,
        "labels": [
            "servicenow-import",
            "auto-assigned",
            f"snow-{state.lower().replace(' ', '-')}",
            f"group-{group.lower().replace(' ', '-')[:30]}",
        ],
    }

    if reporter_field:
        fields["reporter"] = reporter_field

    return {"fields": fields}


# ── FastAPI Application ────────────────────────────────────────────────────────
app = FastAPI(
    title="ServiceNow → Jira Webhook",
    description=(
        "Auto-creates Jira Stories on SNOW assignment events. "
        "Authenticates to Azure Key Vault via SPN (AAD ClientSecretCredential)."
    ),
    version="4.0.0",
)

snow_client: Optional[ServiceNowClient] = None
jira_client: Optional[JiraClient]       = None


@app.on_event("startup")
def startup():
    """
    Startup sequence — runs once when the server starts:
      1. Connect to Key Vault using SPN (AZURE_TENANT_ID / CLIENT_ID / CLIENT_SECRET)
      2. Fetch SNOW_PASS, JIRA_API_TOKEN, WEBHOOK_SECRET from Key Vault
      3. Validate all non-sensitive env vars
      4. Build authenticated HTTP clients
    """
    global snow_client, jira_client

    log.info("=" * 65)
    log.info("[STARTUP] ServiceNow → Jira Webhook  v4.0.0")
    log.info("[STARTUP] Connecting to Azure Key Vault via SPN ...")
    kv.init_keyvault()           # Step 1 — SPN login → Key Vault

    Config.load_secrets()        # Step 2 — fetch secrets
    Config.validate()            # Step 3 — validate env

    snow_client = ServiceNowClient()   # Step 4 — authenticated clients
    jira_client = JiraClient()

    log.info("[STARTUP] Ready ✓  All secrets loaded from Azure Key Vault via SPN.")
    log.info("=" * 65)


# ── Health Check ───────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    """
    Health check for load balancers and monitoring tools.
    Returns config metadata — never exposes secret values.
    """
    return {
        "status":          "ok",
        "timestamp":       datetime.utcnow().isoformat() + "Z",
        "vault_url":       os.getenv("AZURE_KEYVAULT_URL", "(not set)"),
        "spn_client_id":   os.getenv("AZURE_CLIENT_ID",   "(not set)"),
        "jira_type":       Config.JIRA_TYPE,
        "jira_project":    Config.JIRA_PROJECT,
        "snow_instance":   Config.SNOW_INSTANCE,
        "writeback":       Config.SNOW_WRITEBACK,
        "team_groups":     Config.TEAM_GROUPS or ["ALL"],
    }


# ── Webhook Endpoint ───────────────────────────────────────────────────────────
@app.post("/webhook/snow-assigned")
async def snow_assigned(request: Request):
    """
    Main endpoint called by the ServiceNow Business Rule on every assignment.

    Expected JSON payload:
    {
        "sys_id":       "abc123def456",    ← SNOW record sys_id  (required)
        "table":        "sc_request",      ← SNOW table          (required)
        "number":       "REQ0012345",      ← ticket number       (for logging)
        "event":        "assigned",
        "triggered_by": "business_rule"
    }

    Required HTTP headers:
        Content-Type:   application/json
        X-Snow-Secret:  <value of 'webhook-hmac-secret' in Key Vault>
    """

    # ── 1. Read raw body ───────────────────────────────────────────────────
    raw_body = await request.body()

    # ── 2. Verify HMAC signature ───────────────────────────────────────────
    received_secret = request.headers.get("X-Snow-Secret", "")
    if not verify_signature(raw_body, received_secret):
        log.warning(
            f"[SECURITY] Invalid X-Snow-Secret from {request.client.host} — rejected"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing webhook secret.",
        )

    # ── 3. Parse JSON payload ──────────────────────────────────────────────
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body is not valid JSON.",
        )

    sys_id = payload.get("sys_id", "").strip()
    table  = payload.get("table",  "sc_request").strip()
    number = payload.get("number", sys_id)

    if not sys_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="'sys_id' is required in the payload.",
        )

    log.info(
        f"[WEBHOOK] Received | table={table} | number={number} | sys_id={sys_id}"
    )

    # ── 4. Fetch fresh full record from ServiceNow ─────────────────────────
    try:
        record = snow_client.get_full_record(table, sys_id)
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response else "?"
        log.error(f"[SNOW] Fetch failed for sys_id={sys_id}: HTTP {status_code}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"ServiceNow API error: HTTP {status_code}",
        )

    number = record.get("number", number)
    group  = record.get("assignment_group", "")

    # ── 5. Team group filter ───────────────────────────────────────────────
    if Config.TEAM_GROUPS and group not in Config.TEAM_GROUPS:
        log.info(
            f"[FILTER] {number} | group='{group}' not in TEAM_ASSIGNMENT_GROUPS — skipped"
        )
        return JSONResponse(
            status_code=200,
            content={
                "status": "skipped",
                "reason": "group not in team filter",
                "snow":   number,
                "group":  group,
            },
        )

    # ── 6. Deduplication ──────────────────────────────────────────────────
    if jira_client.issue_exists(number):
        log.info(f"[DEDUP] {number} already exists in Jira — skipped")
        return JSONResponse(
            status_code=200,
            content={
                "status": "skipped",
                "reason": "already exists in Jira",
                "snow":   number,
            },
        )

    # ── 7. Resolve reporter ────────────────────────────────────────────────
    caller_email   = record.get("caller_id.email", "").strip().lower()
    reporter_field = jira_client.resolve_reporter(caller_email)

    # ── 8. Create Jira story ───────────────────────────────────────────────
    try:
        jira_payload = build_jira_payload(record, reporter_field)
        response     = jira_client.create_issue(jira_payload)
        jira_key     = response.get("key", "?")
        jira_url     = f"{Config.JIRA_BASE_URL}/browse/{jira_key}"
    except requests.HTTPError as exc:
        body = exc.response.text[:400] if exc.response else "no body"
        log.error(f"[JIRA] Create failed for {number}: {body}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Jira API error: {body}",
        )

    reporter_status = (
        f"mapped ({caller_email})" if reporter_field else "DEFAULT (unmapped)"
    )
    log.info(
        f"[CREATE] {number} → {jira_key} | "
        f"reporter={reporter_status} | group={group}"
    )

    # ── 9. Write Jira URL back to ServiceNow ──────────────────────────────
    snow_client.write_jira_url_back(table, sys_id, jira_key, jira_url)

    return JSONResponse(
        status_code=200,
        content={
            "status":          "created",
            "snow":            number,
            "jira_key":        jira_key,
            "jira_url":        jira_url,
            "reporter_mapped": reporter_field is not None,
            "caller_email":    caller_email or "(blank)",
            "group":           group,
        },
    )


# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "snow_jira_webhook:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8080")),
        reload=False,
        log_level="info",
    )
