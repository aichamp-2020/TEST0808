# ServiceNow → Jira Auto-Trigger  —  Setup Guide
================================================

## Architecture

```
ServiceNow Record
   │  assigned_to or assignment_group changes
   ▼
Business Rule fires  (snow_business_rule.js)
   │  POST /webhook/snow-assigned
   ▼
Webhook Listener  (snow_jira_webhook.py)
   │  verifies X-Snow-Secret header
   │  fetches full record from ServiceNow API
   │  resolves caller email → Jira accountId
   │  creates Jira Story
   │  patches ServiceNow work_notes with Jira URL
   ▼
Jira Story Created  ✅
```

---

## Files

| File | Purpose |
|---|---|
| `snow_jira_webhook.py` | FastAPI webhook listener (run on your server) |
| `snow_business_rule.js` | Paste into ServiceNow Business Rule script field |
| `snow_jira_creator.py` | Original batch script (still useful for backfills) |
| `requirements.txt` | Python dependencies |

---

## Step 1 — Install Dependencies

```bash
pip install fastapi uvicorn requests python-dotenv
```

---

## Step 2 — Configure .env

Create a `.env` file next to `snow_jira_webhook.py`:

```env
# ServiceNow
SNOW_INSTANCE         = your-instance.service-now.com
SNOW_USER             = servicenow_api_user
SNOW_PASS             = servicenow_api_password

# Jira
JIRA_BASE_URL         = https://your-org.atlassian.net
JIRA_USER             = jira_email@company.com
JIRA_API_TOKEN        = your_jira_api_token
JIRA_PROJECT_KEY      = PROJ
JIRA_TYPE             = cloud          # cloud | server

# Webhook Security (generate a strong random string)
WEBHOOK_SECRET        = your_strong_random_secret_here

# Optional: only trigger for these groups (comma-separated)
# Leave blank to process ALL assignment events
TEAM_ASSIGNMENT_GROUPS = Cloud Platform Engineering,AI Platform Team

# Write Jira URL back to ServiceNow work_notes
SNOW_WRITEBACK        = true
```

Generate a secure secret:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Step 3 — Run the Webhook Listener

### Development
```bash
uvicorn snow_jira_webhook:app --host 0.0.0.0 --port 8080 --reload
```

### Production (gunicorn + uvicorn workers)
```bash
pip install gunicorn
gunicorn snow_jira_webhook:app \
  -w 2 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8080
```

### Docker
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY snow_jira_webhook.py .
COPY .env .
EXPOSE 8080
CMD ["uvicorn", "snow_jira_webhook:app", "--host", "0.0.0.0", "--port", "8080"]
```

### systemd (Linux server)
```ini
[Unit]
Description=ServiceNow Jira Webhook
After=network.target

[Service]
User=appuser
WorkingDirectory=/opt/snow-jira
ExecStart=/usr/bin/uvicorn snow_jira_webhook:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Step 4 — Make the Listener Accessible to ServiceNow

ServiceNow's Business Rule needs to reach your webhook over HTTPS.

| Option | How |
|---|---|
| **Cloud VM** | Deploy to Azure App Service, AWS EC2, GCP Cloud Run |
| **Tunnel (dev/test)** | `ngrok http 8080` → gives you a public HTTPS URL |
| **Internal network** | Expose via internal DNS if ServiceNow is on-premise |

Your endpoint will be: `https://<your-host>/webhook/snow-assigned`

---

## Step 5 — ServiceNow Outbound REST Message

1. Go to **System Web Services → Outbound → REST Messages → New**
2. Fill in:
   - **Name**: `Jira Webhook Trigger`
   - **Endpoint**: `https://<your-host>/webhook/snow-assigned`
   - **Auth type**: No authentication
3. Save, then open **HTTP Methods tab → New**:
   - **Method name**: `triggerJira`
   - **HTTP method**: `POST`
4. Under **HTTP Request** tab, add headers:
   - `Content-Type` → `application/json`
   - `X-Snow-Secret` → *(paste your WEBHOOK_SECRET value)*
5. Save the HTTP Method

---

## Step 6 — ServiceNow Business Rule

1. Go to **System Definition → Business Rules → New**
2. Fill in:
   - **Name**: `Trigger Jira Story on Assignment`
   - **Table**: `Service Request [sc_request]`  *(or Incident [incident])*
   - **Active**: ✓
   - **Advanced**: ✓
   - **When**: `after`
   - **Insert**: ✓  **Update**: ✓
3. **Condition** field:
   ```
   (current.assigned_to.changes() || current.assignment_group.changes()) && !current.assigned_to.nil()
   ```
4. **Script** tab: paste the entire contents of `snow_business_rule.js`
5. Save

---

## Step 7 — Jira Project Permission

Ensure your integration service account has **Modify Reporter** permission:

**Jira → Project Settings → Permissions → Modify Reporter**
→ Add your `JIRA_USER` service account

---

## Health Check

```bash
curl https://<your-host>/health
# → {"status":"ok","timestamp":"2025-05-16T10:00:00"}
```

## Test the Webhook Manually

```bash
curl -X POST https://<your-host>/webhook/snow-assigned \
  -H "Content-Type: application/json" \
  -H "X-Snow-Secret: your_strong_random_secret_here" \
  -d '{
    "sys_id":   "test_sys_id_replace_with_real",
    "table":    "sc_request",
    "number":   "REQ0012345",
    "event":    "assigned",
    "triggered_by": "manual_test"
  }'
```

---

## Webhook Response Reference

| Response | Meaning |
|---|---|
| `{"status":"created","jira_key":"PROJ-42"}` | Jira story created successfully |
| `{"status":"skipped","reason":"already exists in Jira"}` | Duplicate — ticket already synced |
| `{"status":"skipped","reason":"group not in team filter"}` | Assignment group not in your filter list |
| HTTP 401 | Wrong or missing `X-Snow-Secret` header |
| HTTP 400 | Missing `sys_id` in payload |
| HTTP 502 | ServiceNow or Jira API call failed |

---

## Batch Backfill

Use the original `snow_jira_creator.py` to sync existing tickets that were
assigned before the webhook was set up:

```bash
python snow_jira_creator.py
```

The deduplication logic in both scripts uses the same JQL check, so
running the batch script after the webhook is live will not create duplicates.
