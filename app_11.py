"""
Agentic Management Platform — Web Dashboard
Flask backend with Server-Sent Events for real-time streaming
"""
import json, time, random, threading, hashlib, uuid, datetime
from collections import deque
from flask import Flask, Response, jsonify, request
from functools import wraps

app = Flask(__name__)
lock = threading.Lock()

# ─── helpers ──────────────────────────────────────────────────────────────────
def now(): return datetime.datetime.utcnow().isoformat(timespec="milliseconds")+"Z"
def ts():  return datetime.datetime.now().strftime("%H:%M:%S.%f")[:11]
def make_key(aid): return "sk-"+hashlib.sha256(f"{aid}:{uuid.uuid4().hex}".encode()).hexdigest()[:32]
def mask(k): return k[:7]+"…"+k[-5:]

RISK = {"query_contracts":25,"run_risk_check":30,"analyse_spend":20,"export_report":40,
        "delete_data":90,"read_audit":10,"approve_workflow":20,"trigger_batch":35,"update_model":50}
SAFE = {"query_contracts","run_risk_check","analyse_spend","read_audit","approve_workflow","trigger_batch"}
USERS= ["dev.chen","approver.jan","alex.admin","viewer.bob","svc.pipeline","finops.lead"]
ACTIONS=list(RISK.keys())
MODELS=["GPT-4o","Claude-Sonnet","GPT-3.5"]
COSTS={"GPT-4o":0.003,"Claude-Sonnet":0.0025,"GPT-3.5":0.0008}
COST_RECS=[
    "Switch batch jobs to GPT-3.5 → save ~40%",
    "Cache RAG results older than 1h → save ~15%",
    "Reduce max_tokens to 800 → save ~22%",
    "Schedule heavy runs off-peak → save ~18%",
    "Use Claude-Haiku for classification → save ~35%",
]

# ─── shared state ──────────────────────────────────────────────────────────────
state = {
    "tick": 0,
    "run_id": uuid.uuid4().hex[:8].upper(),
    "registry": {
        "AGT-POL-001": {
            "name": "Policy Agent",
            "description": "RBAC · guardrails · risk scoring · audit trail",
            "version": "1.4.2", "env": "PROD", "framework": "custom-py",
            "source": "on-prem", "state": "ACTIVE",
            "owner": "platform-team", "registered_at": "2026-03-14 09:05",
            "sub_key": make_key("AGT-POL-001"),
            "endpoint": "https://safealign-agent-management-462973220293.us-central1.run.app/api/agent/pol/v1",
            "tags": ["guardrails","rbac","security"],
            "policies": ["pii-mask","gdpr","rate-limit-100"],
            "rate_limit": 100, "throttle_ms": 50,
            "health": 98, "runs": 0, "tok": 0, "errors": 0,
            "versions": ["1.0.0","1.2.0","1.3.1","1.4.2"],
            "colour": "#a78bfa", "icon": "⚖",
        },
        "AGT-COST-002": {
            "name": "Cost Advisor Agent",
            "description": "FinOps · token budget · savings · alerting",
            "version": "1.1.0", "env": "PROD", "framework": "custom-py",
            "source": "cloud", "state": "ACTIVE",
            "owner": "finops-team", "registered_at": "2026-03-14 09:10",
            "sub_key": make_key("AGT-COST-002"),
            "endpoint": "https://safealign-agent-management-462973220293.us-central1.run.app/api/agent/cost/v1",
            "tags": ["finops","cost","budget"],
            "policies": ["spend-cap-500","alert-90pct"],
            "rate_limit": 60, "throttle_ms": 100,
            "health": 100, "runs": 0, "tok": 0, "errors": 0,
            "versions": ["1.0.0","1.1.0"],
            "colour": "#86efac", "icon": "💰",
        },
    },
    "pending": [],
    "rate_buckets": {"AGT-POL-001": 100, "AGT-COST-002": 60},
    "gw": {
        "req_in":0,"auth_ok":0,"auth_fail":0,
        "routed_pol":0,"routed_cost":0,
        "rate_limited":0,"throttled":0,"e401":0,"e429":0,"e502":0,
        "p50":0.0,"p95":0.0,"active":0,
        "circuit_open":False,"circuit_trips":0,
    },
    "pipeline": [],
    "pol": {
        "step":0,
        "steps":["Recv task from Hub","Load RBAC ruleset","Evaluate risk score",
                 "Check allow/deny list","Apply data masking","Emit policy verdict","Log audit event"],
        "verdict":"PENDING","risk":0,"blocked":0,"allowed":0,
        "runs":0,"tok":0,"errors":0,
        "qvals":{"ALLOW":0.0,"BLOCK":0.0,"ESCALATE":0.0,"DELEGATE":0.0},
        "action":"ALLOW","reward":0.0,"epsilon":0.28,
        "log": [],
    },
    "cost": {
        "step":0,
        "steps":["Recv task from Hub","Pull token usage","Analyse model spend",
                 "Identify waste signals","Generate savings plan","Emit cost report","Update FinOps ledger"],
        "total_usd":0.0,"saved_usd":0.0,"budget":500.0,
        "alerts":0,"runs":0,"tok":0,"errors":0,
        "by_model":{"GPT-4o":0.0,"Claude-Sonnet":0.0,"GPT-3.5":0.0},
        "recs":[], "log":[],
    },
    "gov": {
        "audit_log":[],"policy_viol":0,"gdpr_flags":0,
        "deploys":0,"rollbacks":0,
        "total_tok":0,"tok_budget":5_000_000,
        "lat_hist":[],"err_hist":[],"total_runs":0,"total_errors":0,
    },
    "pods":[
        {"id":"gw-pod-01","agent":"GATEWAY","env":"PROD","rep":3,"cpu":45,"mem":62,"status":"Running"},
        {"id":"hub-pod-02","agent":"HUB","env":"PROD","rep":2,"cpu":38,"mem":55,"status":"Running"},
        {"id":"pol-pod-03","agent":"AGT-POL","env":"PROD","rep":1,"cpu":22,"mem":41,"status":"Running"},
        {"id":"cst-pod-04","agent":"AGT-COST","env":"PROD","rep":1,"cpu":18,"mem":33,"status":"Running"},
    ],
    "events": [],
    "action_log": [],

    # ── RBAC state ──
    "rbac": {
        "roles": {
            "admin":    {"permissions": ["register","rotate_key","set_rate_limit","deploy","rollback","block","govern","read","execute","approve"], "colour": "#f87171"},
            "approver": {"permissions": ["approve","read","execute"], "colour": "#fb923c"},
            "developer":{"permissions": ["read","execute","write"], "colour": "#60a5fa"},
            "viewer":   {"permissions": ["read"], "colour": "#94a3b8"},
            "svc_acct": {"permissions": ["execute"], "colour": "#a78bfa"},
        },
        "users": [
            {"id":"U-001","name":"alex.admin",    "role":"admin",    "active":True},
            {"id":"U-002","name":"dev.chen",      "role":"developer","active":True},
            {"id":"U-003","name":"approver.jan",  "role":"approver", "active":True},
            {"id":"U-004","name":"viewer.bob",    "role":"viewer",   "active":True},
            {"id":"U-005","name":"svc.pipeline",  "role":"svc_acct", "active":True},
        ],
        "demo_log": [],
        "risk_map": {
            "query_contracts":25,"run_risk_check":30,"analyse_spend":20,
            "export_report":40,"delete_data":90,"read_audit":10,
            "approve_workflow":20,"trigger_batch":35,"update_model":50
        },
        "check_count": 0,
        "block_count": 0,
        "allow_count": 0,
    },

    # ── MCP state ──
    "mcp": {
        "servers": {
            "MCP-AUDIT-001": {
                "name": "Audit DB MCP Server",
                "endpoint": "mcp://audit.internal/v1",
                "status": "REGISTERED",
                "allowed_agents": ["AGT-POL-001"],
                "tools": ["read_audit_log","query_violations","get_user_history"],
                "calls": 0, "blocked": 0,
                "last_call": None,
                "verified": True,
            },
            "MCP-FINOPS-002": {
                "name": "FinOps Data MCP Server",
                "endpoint": "mcp://finops.internal/v1",
                "status": "REGISTERED",
                "allowed_agents": ["AGT-COST-002"],
                "tools": ["get_token_usage","get_model_pricing","update_ledger"],
                "calls": 0, "blocked": 0,
                "last_call": None,
                "verified": True,
            },
            "MCP-BILLING-003": {
                "name": "Billing API MCP Server",
                "endpoint": "mcp://billing.internal/v1",
                "status": "REGISTERED",
                "allowed_agents": [],
                "tools": ["get_invoice","charge_account"],
                "calls": 0, "blocked": 0,
                "last_call": None,
                "verified": True,
            },
            "MCP-UNKNOWN-EXT": {
                "name": "External Unknown Server",
                "endpoint": "mcp://external-unknown.io/api",
                "status": "UNREGISTERED",
                "allowed_agents": [],
                "tools": [],
                "calls": 0, "blocked": 0,
                "last_call": None,
                "verified": False,
            },
        },
        "call_log": [],
        "total_calls": 0,
        "blocked_calls": 0,
        "injections_blocked": 0,
    },

    # ── A2A state ──
    "a2a": {
        "agents": {
            "AGT-HUB-000": {
                "name": "Orchestration Hub",
                "can_call": ["AGT-POL-001","AGT-COST-002"],
                "colour": "#f59e0b",
            },
            "AGT-POL-001": {
                "name": "Policy Agent",
                "can_call": [],
                "colour": "#a78bfa",
            },
            "AGT-COST-002": {
                "name": "Cost Advisor",
                "can_call": [],
                "colour": "#86efac",
            },
        },
        "active_flow": None,
        "flow_step": 0,
        "flow_steps": [
            {"label":"Hub receives user request",      "from":"USER",        "to":"AGT-HUB-000","type":"request"},
            {"label":"Hub verifies Agent Card of POL", "from":"AGT-HUB-000","to":"AGT-POL-001", "type":"verify"},
            {"label":"Hub checks delegation scope",    "from":"AGT-HUB-000","to":"PLATFORM",    "type":"rbac"},
            {"label":"Platform issues short-lived token","from":"PLATFORM",  "to":"AGT-HUB-000","type":"token"},
            {"label":"Hub dispatches to Policy Agent", "from":"AGT-HUB-000","to":"AGT-POL-001", "type":"dispatch"},
            {"label":"Policy Agent checks its own scope","from":"AGT-POL-001","to":"PLATFORM",  "type":"rbac"},
            {"label":"Policy Agent executes task",     "from":"AGT-POL-001","to":"AGT-POL-001", "type":"exec"},
            {"label":"Policy Agent returns verdict",   "from":"AGT-POL-001","to":"AGT-HUB-000", "type":"response"},
            {"label":"Hub dispatches to Cost Advisor", "from":"AGT-HUB-000","to":"AGT-COST-002","type":"dispatch"},
            {"label":"Cost Advisor executes & returns","from":"AGT-COST-002","to":"AGT-HUB-000","type":"response"},
            {"label":"Hub aggregates & returns result","from":"AGT-HUB-000","to":"USER",        "type":"response"},
            {"label":"Both hops audit-logged",         "from":"PLATFORM",   "to":"PLATFORM",    "type":"audit"},
        ],
        "call_log": [],
        "total_flows": 0,
        "blocked_flows": 0,
        "tokens_issued": 0,
    },

    # ── OpenAPI → Tool Generator state ──
    "openapi_gen": {
        "generated": [],
        "total_generated": 0,
    },

    # ── Vulnerability Scan state ──
    "vuln": {
        "scans": [],
        "total_scans": 0,
        "total_vulns": 0,
        "last_scan_agent": None,
    },

    # ── Data Masking state ──
    "masking": {
        "rules": [
            {"field": "email",    "pattern": r"\b[\w.+-]+@[\w-]+\.\w+\b",   "mask": "***@***.***",  "active": True},
            {"field": "phone",    "pattern": r"\+?\d[\d\s\-]{7,}\d",          "mask": "***-***-****", "active": True},
            {"field": "api_key",  "pattern": r"sk-[a-f0-9]{20,}",             "mask": "sk-***…***",   "active": True},
            {"field": "ip_addr",  "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "mask": "*.*.*.*", "active": True},
        ],
        "events_masked": 0,
        "fields_masked": 0,
        "log": [],
    },
}

def add_event(msg, level="info"):
    ev = {"ts": ts(), "msg": msg, "level": level}
    state["events"].insert(0, ev)
    state["events"] = state["events"][:50]

def add_audit(msg):
    entry = {"ts": ts(), "msg": msg}
    state["gov"]["audit_log"].insert(0, entry)
    state["gov"]["audit_log"] = state["gov"]["audit_log"][:30]

# ─── simulation loop ──────────────────────────────────────────────────────────
def sim_loop():
    pt = ct = 0
    while True:
        time.sleep(0.5)
        with lock:
            t = state["tick"]; state["tick"] = t+1
            gov = state["gov"]; gw = state["gw"]

            # gateway request
            if t % 2 == 0:
                user = random.choice(USERS); action = random.choice(ACTIONS)
                tid = random.choice(["AGT-POL-001"]*3+["AGT-COST-002"]*2)
                a = state["registry"].get(tid)
                if not a or a["state"] != "ACTIVE":
                    continue
                auth_ok = random.random() > 0.08
                bkt = state["rate_buckets"][tid]; rate_ok = bkt > 0
                if rate_ok: state["rate_buckets"][tid] = max(0, bkt-1)
                lat = max(50, int(random.gauss(480, 180)))
                gw["req_in"] += 1

                if not auth_ok:
                    status="401"; gw["auth_fail"]+=1; gw["e401"]+=1
                    gov["total_errors"]+=1; gov["err_hist"].append(1)
                    add_event(f"AUTH FAIL  {user} → {tid}  [401]","error")
                elif not rate_ok:
                    status="429"; gw["rate_limited"]+=1; gw["e429"]+=1
                    gov["err_hist"].append(1)
                    add_event(f"RATE LIMIT  {user} → {tid}  [429 too many requests]","warn")
                elif random.random() < 0.04:
                    status="502"; gw["e502"]+=1; gw["throttled"]+=1
                    gov["total_errors"]+=1; gov["err_hist"].append(1)
                    add_event(f"THROTTLED  {user} → {tid}  [502]","warn")
                else:
                    status="OK"; gw["auth_ok"]+=1
                    if tid=="AGT-POL-001": gw["routed_pol"]+=1
                    else: gw["routed_cost"]+=1
                    a["runs"]+=1; gov["total_runs"]+=1
                    gov["err_hist"].append(0)
                    gov["lat_hist"].append(lat)
                    if len(gov["lat_hist"]) > 60: gov["lat_hist"] = gov["lat_hist"][-60:]
                    gw["p50"]=lat; gw["p95"]=max(lat*1.4, gw["p95"]*0.95)
                    tok=random.randint(80,600); a["tok"]+=tok; gov["total_tok"]+=tok
                    gw["active"]=random.randint(0,8)
                    add_audit(f"{status}  {user}  →  {tid}  {action}  {lat}ms")
                    add_event(f"OK  {user} → {tid}  {action}  ({lat}ms)","ok")

                state["pipeline"].insert(0, {"s":status,"k":mask(a["sub_key"]),"a":tid,"act":action[:12],"ms":lat if status=="OK" else 0})
                state["pipeline"] = state["pipeline"][:8]
                for aid in state["rate_buckets"]:
                    rl = state["registry"][aid]["rate_limit"]
                    state["rate_buckets"][aid] = min(rl, state["rate_buckets"][aid]+3)

            # policy agent step
            pt += 1
            ps = state["pol"]["step"]
            if ps < len(state["pol"]["steps"]):
                if pt%3==0: state["pol"]["step"]+=1; state["pol"]["runs"]+=1; state["pol"]["tok"]+=random.randint(50,180)
            else:
                if pt%5==0: state["pol"]["step"]=0; pt=0

            if t%2==0:
                for k in state["pol"]["qvals"]:
                    state["pol"]["qvals"][k]=max(-1,min(1,state["pol"]["qvals"][k]+random.gauss(0,0.04)))
                state["pol"]["action"]=max(state["pol"]["qvals"],key=state["pol"]["qvals"].get)
                state["pol"]["reward"]=round(random.gauss(0.2,0.5),3)
                state["pol"]["epsilon"]=max(0.05,state["pol"]["epsilon"]-0.0003)

            if t%4==0:
                user=random.choice(USERS); action=random.choice(ACTIONS)
                risk=RISK.get(action,40); allowed=action in SAFE
                verdict="ALLOW" if allowed else "BLOCK"
                state["pol"]["verdict"]=verdict; state["pol"]["risk"]=risk
                if allowed: state["pol"]["allowed"]+=1
                else:
                    state["pol"]["blocked"]+=1; gov["policy_viol"]+=1
                    state["registry"]["AGT-POL-001"]["errors"]+=1
                state["pol"]["log"].insert(0,{"v":verdict,"u":user,"a":action,"r":risk})
                state["pol"]["log"]=state["pol"]["log"][:8]

            # cost advisor step
            ct+=1
            cs=state["cost"]["step"]
            if cs<len(state["cost"]["steps"]):
                if ct%3==0: state["cost"]["step"]+=1; state["cost"]["runs"]+=1; state["cost"]["tok"]+=random.randint(30,120)
            else:
                if ct%7==0: state["cost"]["step"]=0; ct=0

            if t%5==0:
                mdl=random.choice(MODELS); ntok=random.randint(200,1400)
                spend=round(ntok*COSTS[mdl]/1000,5)
                state["cost"]["by_model"][mdl]=round(state["cost"]["by_model"][mdl]+spend,5)
                state["cost"]["total_usd"]=round(state["cost"]["total_usd"]+spend,4)
                state["registry"]["AGT-COST-002"]["tok"]+=ntok
                if t%15==0:
                    state["cost"]["saved_usd"]=round(state["cost"]["saved_usd"]+spend*random.uniform(0.1,0.4),4)
                    rec=random.choice(COST_RECS)
                    state["cost"]["recs"].insert(0,rec)
                    state["cost"]["recs"]=state["cost"]["recs"][:4]
                if spend>0.04:
                    state["cost"]["alerts"]+=1
                    state["cost"]["log"].insert(0,{"m":mdl,"spend":spend,"tok":ntok,"alert":True})
                    add_event(f"Cost alert: {mdl} ${spend:.4f}  {ntok}tok","warn")
                else:
                    state["cost"]["log"].insert(0,{"m":mdl,"spend":spend,"tok":ntok,"alert":False})
                state["cost"]["log"]=state["cost"]["log"][:6]

            # health + pod jitter
            for aid in state["registry"]:
                h=state["registry"][aid]["health"]
                state["registry"][aid]["health"]=max(85,min(100,h+random.randint(-1,1)))
            for pod in state["pods"]:
                pod["cpu"]=max(5,min(92,pod["cpu"]+random.randint(-3,4)))
                pod["mem"]=max(20,min(88,pod["mem"]+random.randint(-2,3)))

            # periodic data masking events
            if t % 7 == 0:
                mask_fields = random.randint(1, 4)
                state["masking"]["events_masked"] += 1
                state["masking"]["fields_masked"] += mask_fields
                state["masking"]["log"].insert(0, {
                    "ts": ts(), "agent": random.choice(list(state["registry"].keys())),
                    "fields": mask_fields, "rule": random.choice(["email","phone","api_key","ip_addr"])
                })
                state["masking"]["log"] = state["masking"]["log"][:10]

            if len(gov["lat_hist"])>60: gov["lat_hist"]=gov["lat_hist"][-60:]
            if len(gov["err_hist"])>60: gov["err_hist"]=gov["err_hist"][-60:]

threading.Thread(target=sim_loop, daemon=True).start()

# ─── API endpoints ────────────────────────────────────────────────────────────
@app.route("/api/state")
def get_state():
    with lock: return jsonify(state)


# ── RBAC demo route ──────────────────────────────────────────────────────────
@app.route("/api/rbac/check", methods=["POST"])
def rbac_check():
    data = request.get_json()
    user_id  = data.get("user_id","U-002")
    action   = data.get("action","read")
    agent_id = data.get("agent_id","AGT-POL-001")
    with lock:
        rbac = state["rbac"]
        user = next((u for u in rbac["users"] if u["id"]==user_id), None)
        if not user:
            return jsonify({"ok":False,"verdict":"DENY","reason":"User not found"})
        role      = user["role"]
        perms     = rbac["roles"][role]["permissions"]
        allowed   = action in perms
        risk      = rbac["risk_map"].get(action, 40)
        routing   = "allow_direct" if risk<30 else ("log_alert" if risk<70 else ("escalate" if risk<85 else "mandatory_approval"))
        verdict   = "ALLOW" if allowed else "BLOCK"
        rbac["check_count"] += 1
        if allowed: rbac["allow_count"] += 1
        else:       rbac["block_count"] += 1
        entry = {"ts":ts(),"user":user["name"],"role":role,"action":action,
                 "agent":agent_id,"verdict":verdict,"risk":risk,"routing":routing}
        rbac["demo_log"].insert(0, entry)
        rbac["demo_log"] = rbac["demo_log"][:12]
        add_event(f"RBAC {verdict}: {user['name']} ({role}) → {action} on {agent_id} [risk={risk}]",
                  "ok" if allowed else "error")
        add_audit(f"RBAC {verdict}  {user['name']}  {action}  {agent_id}  risk={risk}")
    return jsonify({"ok":True,"verdict":verdict,"role":role,"risk":risk,
                    "routing":routing,"allowed":allowed,
                    "permissions": perms})

# ── MCP demo route ────────────────────────────────────────────────────────────
@app.route("/api/mcp/call", methods=["POST"])
def mcp_call():
    data      = request.get_json()
    agent_id  = data.get("agent_id","AGT-POL-001")
    server_id = data.get("server_id","MCP-AUDIT-001")
    tool      = data.get("tool","read_audit_log")
    inject    = data.get("inject_payload", False)
    with lock:
        mcp = state["mcp"]
        srv = mcp["servers"].get(server_id)
        if not srv:
            return jsonify({"ok":False,"status":"BLOCKED","reason":"Server not in registry"})
        # Check 1: registered?
        if srv["status"] == "UNREGISTERED":
            srv["blocked"] += 1; mcp["blocked_calls"] += 1
            add_event(f"MCP BLOCKED: {agent_id} → {server_id} (unregistered)","error")
            return jsonify({"ok":False,"status":"BLOCKED","reason":"MCP server not registered","check":"registry"})
        # Check 2: agent has scope?
        if agent_id not in srv["allowed_agents"]:
            srv["blocked"] += 1; mcp["blocked_calls"] += 1
            add_event(f"MCP BLOCKED: {agent_id} → {server_id} (no scope)","error")
            return jsonify({"ok":False,"status":"BLOCKED","reason":f"Agent {agent_id} has no scope for this server","check":"scope"})
        # Check 3: tool exists?
        if tool not in srv["tools"]:
            srv["blocked"] += 1; mcp["blocked_calls"] += 1
            return jsonify({"ok":False,"status":"BLOCKED","reason":f"Tool '{tool}' not in server contract","check":"tool_contract"})
        # Check 4: prompt injection?
        if inject:
            mcp["injections_blocked"] += 1; srv["blocked"] += 1
            add_event(f"MCP INJECTION BLOCKED: {server_id} returned malicious payload","error")
            return jsonify({"ok":False,"status":"BLOCKED","reason":"Response validation failed — injection detected","check":"response_validation"})
        # All checks passed
        import datetime as _dt
        srv["calls"] += 1; mcp["total_calls"] += 1
        srv["last_call"] = ts()
        entry = {"ts":ts(),"agent":agent_id,"server":server_id,"tool":tool,
                 "status":"OK","hmac_verified":True,"schema_valid":True}
        mcp["call_log"].insert(0, entry); mcp["call_log"] = mcp["call_log"][:10]
        add_event(f"MCP OK: {agent_id} → {server_id}.{tool} [HMAC✓ schema✓]","ok")
        add_audit(f"MCP_CALL  {agent_id}  {server_id}  {tool}  OK")
    return jsonify({"ok":True,"status":"OK","server":server_id,"tool":tool,
                    "hmac_verified":True,"schema_valid":True,
                    "result":f"Tool '{tool}' executed successfully"})

# ── A2A demo route ────────────────────────────────────────────────────────────
@app.route("/api/a2a/start_flow", methods=["POST"])
def a2a_start():
    data = request.get_json()
    caller  = data.get("caller","AGT-HUB-000")
    callee  = data.get("callee","AGT-POL-001")
    task    = data.get("task","evaluate_policy_risk")
    attack  = data.get("attack",False)
    with lock:
        a2a    = state["a2a"]
        agents = a2a["agents"]
        caller_a = agents.get(caller)
        callee_a = agents.get(callee)
        if not caller_a:
            return jsonify({"ok":False,"status":"BLOCKED","reason":"Caller agent not registered"})
        if not callee_a:
            return jsonify({"ok":False,"status":"BLOCKED","reason":"Callee agent not registered"})
        # Delegation scope check
        if callee not in caller_a.get("can_call",[]):
            a2a["blocked_flows"] += 1
            add_event(f"A2A BLOCKED: {caller} → {callee} (no delegation scope)","error")
            return jsonify({"ok":False,"status":"BLOCKED",
                            "reason":f"{caller} has no delegation scope to call {callee}",
                            "check":"delegation_scope"})
        if attack:
            add_event(f"A2A ATTACK BLOCKED: {caller} → {callee} prompt injection attempt","error")
            return jsonify({"ok":False,"status":"BLOCKED",
                            "reason":"Prompt injection detected in A2A payload — sanitised",
                            "check":"injection_prevention"})
        # Issue short-lived token
        token = "tkn-" + uuid.uuid4().hex[:12]
        a2a["tokens_issued"] += 1; a2a["total_flows"] += 1
        a2a["flow_step"] = 0; a2a["active_flow"] = {"caller":caller,"callee":callee,"task":task,"token":token}
        entry = {"ts":ts(),"caller":caller,"callee":callee,"task":task,
                 "status":"OK","token":token[:12]+"…","ttl":"10min"}
        a2a["call_log"].insert(0, entry); a2a["call_log"] = a2a["call_log"][:10]
        add_event(f"A2A OK: {caller} → {callee}  task={task}  token={token[:8]}… ttl=10min","ok")
        add_audit(f"A2A  {caller}  →  {callee}  {task}  OK  {token[:8]}")
    return jsonify({"ok":True,"status":"OK","caller":caller,"callee":callee,
                    "task":task,"token":token,"ttl_minutes":10,
                    "checks_passed":["registration","delegation_scope","agent_card","least_privilege"]})

@app.route("/api/a2a/flow_step", methods=["POST"])
def a2a_flow_step():
    with lock:
        a2a = state["a2a"]
        if a2a["active_flow"] is None:
            return jsonify({"ok":False,"step":-1})
        step = a2a["flow_step"]
        total = len(a2a["flow_steps"])
        if step < total:
            a2a["flow_step"] += 1
        return jsonify({"ok":True,"step":step,"total":total,
                        "current": a2a["flow_steps"][step] if step < total else None,
                        "complete": step >= total-1})

# ── Catalog search ─────────────────────────────────────────────────────────────
@app.route("/api/catalog/search", methods=["GET"])
def catalog_search():
    q    = request.args.get("q","").lower()
    env  = request.args.get("env","ALL")
    fw   = request.args.get("fw","ALL")
    st   = request.args.get("state","ALL")
    with lock:
        results = {}
        for aid, a in state["registry"].items():
            if env  != "ALL" and a.get("env") != env:   continue
            if fw   != "ALL" and a.get("framework") != fw: continue
            if st   != "ALL" and a.get("state") != st:  continue
            if q and not any(q in str(v).lower() for v in [aid, a.get("name",""), a.get("description",""), " ".join(a.get("tags",[]))]):
                continue
            results[aid] = {k: v for k, v in a.items() if k != "sub_key"}
    return jsonify({"ok":True,"results":results,"count":len(results)})

# ── OpenAPI → MCP Tool Generator ───────────────────────────────────────────────
OPENAPI_SAMPLES = {
    "Salesforce Accounts API": {
        "paths": {"/accounts":{"get":{"operationId":"listAccounts","summary":"List accounts","parameters":[{"name":"limit","in":"query","type":"integer"}]}},
                  "/accounts/{id}":{"get":{"operationId":"getAccount","summary":"Get account by ID","parameters":[{"name":"id","in":"path","required":True,"type":"string"}]}}}
    },
    "ServiceNow Incidents API": {
        "paths": {"/incidents":{"post":{"operationId":"createIncident","summary":"Create incident","requestBody":{"required":["short_description","urgency"]}}},
                  "/incidents/{id}":{"patch":{"operationId":"updateIncident","summary":"Update incident"}}}
    },
    "Internal Inventory API": {
        "paths": {"/inventory/items":{"get":{"operationId":"listItems","summary":"List inventory items"}},
                  "/inventory/items/{sku}":{"get":{"operationId":"getItem","summary":"Get item by SKU"}},
                  "/inventory/reorder":{"post":{"operationId":"triggerReorder","summary":"Trigger reorder"}}}
    },
}

@app.route("/api/openapi/generate_tool", methods=["POST"])
def openapi_generate():
    data     = request.get_json()
    api_name = data.get("api_name","Salesforce Accounts API")
    agent_id = data.get("agent_id","AGT-POL-001")
    spec     = OPENAPI_SAMPLES.get(api_name, list(OPENAPI_SAMPLES.values())[0])
    with lock:
        tools = []
        for path, methods in spec["paths"].items():
            for method, op in methods.items():
                tool_id = f"MCP-GEN-{uuid.uuid4().hex[:6].upper()}"
                tool_def = {
                    "tool_id": tool_id,
                    "name": op.get("operationId", f"{method}_{path.replace('/','_')}"),
                    "description": op.get("summary","Auto-generated tool"),
                    "http_method": method.upper(),
                    "path": path,
                    "source_api": api_name,
                    "generated_at": ts(),
                    "agent_scope": agent_id,
                    "mcp_endpoint": f"mcp://auto-gen.internal/{tool_id.lower()}",
                    "auth": "Bearer (inherited from gateway)",
                    "schema_validated": True,
                    "input_schema": {"type":"object","properties":{"params":{"type":"object"}}},
                    "output_schema": {"type":"object","properties":{"result":{"type":"object"}}},
                }
                tools.append(tool_def)
                state["openapi_gen"]["generated"].append(tool_def)
        state["openapi_gen"]["total_generated"] += len(tools)
        state["openapi_gen"]["generated"] = state["openapi_gen"]["generated"][-20:]
        add_event(f"OpenAPI→Tool: Generated {len(tools)} MCP tools from '{api_name}'","ok")
        add_audit(f"OPENAPI_GEN  {agent_id}  {api_name}  {len(tools)}_tools")
    return jsonify({"ok":True,"api_name":api_name,"tools":tools,"count":len(tools)})

# ── Vulnerability Scanner ──────────────────────────────────────────────────────
VULN_DB = [
    {"id":"CVE-2024-1234","severity":"HIGH",   "pkg":"langchain==0.1.0",    "desc":"Prompt injection via tool output"},
    {"id":"CVE-2024-5678","severity":"MEDIUM", "pkg":"requests==2.28.0",    "desc":"SSRF in redirect handling"},
    {"id":"CVE-2024-9012","severity":"LOW",    "pkg":"pydantic==1.10.0",    "desc":"DoS via deeply nested models"},
    {"id":"CVE-2024-3456","severity":"CRITICAL","pkg":"openai==0.28.0",     "desc":"API key leakage in error logs"},
    {"id":"CVE-2024-7890","severity":"HIGH",   "pkg":"transformers==4.30.0","desc":"Arbitrary code via pickle"},
    {"id":"CVE-2024-2345","severity":"MEDIUM", "pkg":"numpy==1.24.0",       "desc":"Buffer overflow in operations"},
    {"id":"CVE-2024-6789","severity":"LOW",    "pkg":"flask==2.3.0",        "desc":"Debug mode info disclosure"},
]
DEPS = {
    "custom-py":  ["requests==2.28.0","pydantic==1.10.0","openai==0.28.0","flask==2.3.0"],
    "LangGraph":  ["langchain==0.1.0","pydantic==1.10.0","requests==2.28.0"],
    "LangChain":  ["langchain==0.1.0","requests==2.28.0","numpy==1.24.0"],
    "Google ADK": ["requests==2.28.0","pydantic==1.10.0","transformers==4.30.0"],
    "Salesforce": ["requests==2.28.0","pydantic==1.10.0"],
    "ServiceNow": ["requests==2.28.0","flask==2.3.0"],
}

@app.route("/api/security/scan/<aid>", methods=["POST"])
def vuln_scan(aid):
    with lock:
        a = state["registry"].get(aid)
        if not a:
            return jsonify({"ok":False,"error":"Agent not found"}),404
        fw   = a.get("framework","custom-py")
        deps = DEPS.get(fw, ["requests==2.28.0"])
        # Find matching vulns
        found = [v for v in VULN_DB if any(v["pkg"].split("==")[0] == d.split("==")[0] for d in deps)]
        # Random subset for demo variety
        found = random.sample(found, min(len(found), random.randint(1, len(found))))
        scan = {
            "scan_id": "SCAN-"+uuid.uuid4().hex[:8].upper(),
            "agent_id": aid,
            "agent_name": a["name"],
            "framework": fw,
            "dependencies": deps,
            "vulnerabilities": found,
            "critical": sum(1 for v in found if v["severity"]=="CRITICAL"),
            "high":     sum(1 for v in found if v["severity"]=="HIGH"),
            "medium":   sum(1 for v in found if v["severity"]=="MEDIUM"),
            "low":      sum(1 for v in found if v["severity"]=="LOW"),
            "scanned_at": ts(),
            "status": "FAIL" if any(v["severity"] in ("CRITICAL","HIGH") for v in found) else "PASS",
        }
        state["vuln"]["scans"].insert(0, scan)
        state["vuln"]["scans"] = state["vuln"]["scans"][:10]
        state["vuln"]["total_scans"] += 1
        state["vuln"]["total_vulns"] += len(found)
        state["vuln"]["last_scan_agent"] = aid
        sev = "error" if scan["status"]=="FAIL" else "ok"
        add_event(f"VULN SCAN {scan['status']}: {aid} — {len(found)} vulns ({scan['critical']} critical, {scan['high']} high)", sev)
        add_audit(f"VULN_SCAN  admin  →  {aid}  {scan['status']}  vulns={len(found)}")
    return jsonify({"ok":True,"scan":scan})

# ── Data Masking demo ──────────────────────────────────────────────────────────
@app.route("/api/masking/apply", methods=["POST"])
def apply_masking():
    import re
    data  = request.get_json()
    text  = data.get("text","")
    with lock:
        rules  = state["masking"]["rules"]
        masked = text
        applied = []
        for rule in rules:
            if not rule["active"]: continue
            try:
                matches = re.findall(rule["pattern"], masked)
                if matches:
                    masked = re.sub(rule["pattern"], rule["mask"], masked)
                    applied.append({"field": rule["field"], "occurrences": len(matches), "mask": rule["mask"]})
            except: pass
        fields_masked = sum(r["occurrences"] for r in applied)
        if applied:
            state["masking"]["events_masked"] += 1
            state["masking"]["fields_masked"] += fields_masked
            state["masking"]["log"].insert(0, {
                "ts": ts(), "agent": "MANUAL", "fields": fields_masked,
                "rule": ",".join(r["field"] for r in applied)
            })
            state["masking"]["log"] = state["masking"]["log"][:10]
            add_event(f"PII MASKED: {fields_masked} field(s) — {', '.join(r['field'] for r in applied)}", "ok")
            add_audit(f"PII_MASK  admin  manual  fields={fields_masked}")
    return jsonify({"ok":True,"original":text,"masked":masked,"rules_applied":applied,"fields_masked":fields_masked})

@app.route("/api/stream")
def stream_with_extras():
    def generate():
        while True:
            with lock:
                payload = json.dumps({
                    "tick": state["tick"],
                    "run_id": state["run_id"],
                    "registry": state["registry"],
                    "gw": state["gw"],
                    "pipeline": state["pipeline"][:8],
                    "pol": {k:v for k,v in state["pol"].items() if k!="log"},
                    "pol_log": state["pol"]["log"][:5],
                    "cost": {k:v for k,v in state["cost"].items() if k not in("log","recs")},
                    "cost_log": state["cost"]["log"][:4],
                    "cost_recs": state["cost"]["recs"][:3],
                    "gov": {k:v for k,v in state["gov"].items() if k not in("audit_log","lat_hist","err_hist")},
                    "audit_log": state["gov"]["audit_log"][:6],
                    "lat_hist": state["gov"]["lat_hist"][-30:],
                    "err_hist": state["gov"]["err_hist"][-30:],
                    "pods": state["pods"],
                    "events": state["events"][:8],
                    "rate_buckets": state["rate_buckets"],
                    "pending": state["pending"][:3],
                    "rbac": state["rbac"],
                    "mcp": state["mcp"],
                    "a2a": state["a2a"],
                    "openapi_gen": state["openapi_gen"],
                    "vuln": state["vuln"],
                    "masking": {k:v for k,v in state["masking"].items() if k!="rules"},
                    "masking_log": state["masking"]["log"][:8],
                })
            yield f"data: {payload}\n\n"
            time.sleep(0.8)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


# OLD stream replaced above
@app.route("/api/stream_old")
def stream_old():
    def generate():
        while True:
            with lock:
                payload = json.dumps({
                    "tick": state["tick"],
                    "registry": state["registry"],
                    "gw": state["gw"],
                    "pipeline": state["pipeline"][:8],
                    "pol": {k:v for k,v in state["pol"].items() if k!="log"},
                    "pol_log": state["pol"]["log"][:5],
                    "cost": {k:v for k,v in state["cost"].items() if k not in("log","recs")},
                    "cost_log": state["cost"]["log"][:4],
                    "cost_recs": state["cost"]["recs"][:3],
                    "gov": {k:v for k,v in state["gov"].items() if k not in("audit_log","lat_hist","err_hist")},
                    "audit_log": state["gov"]["audit_log"][:6],
                    "lat_hist": state["gov"]["lat_hist"][-30:],
                    "err_hist": state["gov"]["err_hist"][-30:],
                    "pods": state["pods"],
                    "events": state["events"][:8],
                    "rate_buckets": state["rate_buckets"],
                    "pending": state["pending"][:3],
                })
            yield f"data: {payload}\n\n"
            time.sleep(0.8)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── Management Actions ─────────────────────────────────────────────────────────
@app.route("/api/action/register", methods=["POST"])
def register_agent():
    data = request.get_json()
    name = data.get("name","New Agent")
    aid  = "AGT-"+uuid.uuid4().hex[:6].upper()
    with lock:
        state["registry"][aid] = {
            "name": name,
            "description": data.get("description","Custom agent"),
            "endpoint": data.get("endpoint",""),
            "version": "1.0.0", "env": data.get("env","DEV"),
            "framework": data.get("framework","custom-py"),
            "source": "on-prem", "state": "ACTIVE",
            "owner": data.get("owner","admin"),
            "registered_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "sub_key": make_key(aid),
            "tags": data.get("tags",[]),
            "policies": ["rate-limit-50","default-policy"],
            "rate_limit": int(data.get("rate_limit",50)),
            "throttle_ms": int(data.get("throttle_ms",100)),
            "health": 100, "runs": 0, "tok": 0, "errors": 0,
            "versions": ["1.0.0"],
            "colour": random.choice(["#a78bfa","#86efac","#67e8f9","#fbbf24","#fb923c"]),
            "icon": "🤖",
        }
        state["rate_buckets"][aid] = int(data.get("rate_limit",50))
        add_event(f"Agent registered: {aid} — {name}", "ok")
        add_audit(f"REGISTER  admin  →  {aid}  {name}")
    return jsonify({"ok":True,"agent_id":aid,"sub_key":state["registry"][aid]["sub_key"]})

@app.route("/api/action/rotate_key/<aid>", methods=["POST"])
def rotate_key(aid):
    with lock:
        if aid not in state["registry"]:
            return jsonify({"ok":False,"error":"Agent not found"}),404
        old = state["registry"][aid]["sub_key"]
        new_key = make_key(aid)
        state["registry"][aid]["sub_key"] = new_key
        add_event(f"Sub-key rotated: {aid}", "warn")
        add_audit(f"ROTATE_KEY  admin  →  {aid}")
    return jsonify({"ok":True,"new_key":new_key,"masked":mask(new_key)})

@app.route("/api/action/set_rate_limit/<aid>", methods=["POST"])
def set_rate_limit(aid):
    data = request.get_json()
    rl = int(data.get("rate_limit",100))
    thr= int(data.get("throttle_ms",50))
    with lock:
        if aid not in state["registry"]:
            return jsonify({"ok":False,"error":"Agent not found"}),404
        state["registry"][aid]["rate_limit"]=rl
        state["registry"][aid]["throttle_ms"]=thr
        state["rate_buckets"][aid]=rl
        add_event(f"Rate limit updated: {aid} → {rl}/min  throttle={thr}ms","ok")
        add_audit(f"SET_RATE_LIMIT  admin  →  {aid}  {rl}/min")
    return jsonify({"ok":True,"rate_limit":rl,"throttle_ms":thr})

@app.route("/api/action/set_state/<aid>", methods=["POST"])
def set_agent_state(aid):
    data = request.get_json()
    new_state_val = data.get("state","ACTIVE")
    with lock:
        if aid not in state["registry"]:
            return jsonify({"ok":False,"error":"Agent not found"}),404
        state["registry"][aid]["state"] = new_state_val
        add_event(f"Agent state changed: {aid} → {new_state_val}",
                  "ok" if new_state_val=="ACTIVE" else "error")
        add_audit(f"SET_STATE  admin  →  {aid}  {new_state_val}")
    return jsonify({"ok":True,"state":new_state_val})

@app.route("/api/action/deploy_version/<aid>", methods=["POST"])
def deploy_version(aid):
    data = request.get_json()
    env = data.get("env","UAT")
    ver = data.get("version","")
    with lock:
        if aid not in state["registry"]:
            return jsonify({"ok":False,"error":"Agent not found"}),404
        a = state["registry"][aid]
        if not ver:
            parts = a["version"].split(".")
            parts[-1] = str(int(parts[-1])+1)
            ver = ".".join(parts)
        a["versions"].append(ver)
        old_ver = a["version"]
        a["version"] = ver
        a["env"] = env
        state["gov"]["deploys"] += 1
        add_event(f"Deployed {aid} v{ver} → {env}","ok")
        add_audit(f"DEPLOY  admin  →  {aid}  v{old_ver}→v{ver}  env={env}")
    return jsonify({"ok":True,"version":ver,"env":env})

@app.route("/api/action/rollback/<aid>", methods=["POST"])
def rollback(aid):
    with lock:
        if aid not in state["registry"]:
            return jsonify({"ok":False,"error":"Agent not found"}),404
        a = state["registry"][aid]
        if len(a["versions"]) < 2:
            return jsonify({"ok":False,"error":"No previous version"}),400
        bad = a["versions"].pop()
        prev = a["versions"][-1]
        a["version"] = prev
        state["gov"]["rollbacks"] += 1
        add_event(f"ROLLBACK {aid}: {bad} → {prev}","warn")
        add_audit(f"ROLLBACK  admin  →  {aid}  {bad}→{prev}")
    return jsonify({"ok":True,"rolled_back_from":bad,"current":prev})

@app.route("/api/action/approve_pending/<name>", methods=["POST"])
def approve_pending(name):
    with lock:
        state["pending"] = [p for p in state["pending"] if p["name"]!=name]
        add_event(f"Pending registration approved: {name}","ok")
    return jsonify({"ok":True})

@app.route("/api/action/reject_pending/<name>", methods=["POST"])
def reject_pending(name):
    with lock:
        state["pending"] = [p for p in state["pending"] if p["name"]!=name]
        add_event(f"Pending registration rejected: {name}","error")
    return jsonify({"ok":True})

@app.route("/api/action/simulate_request", methods=["POST"])
def simulate_request():
    """Manually trigger a request through the gateway"""
    data = request.get_json()
    aid  = data.get("agent_id","AGT-POL-001")
    user = data.get("user","admin")
    action=data.get("action","query_contracts")
    sub_key=data.get("sub_key","")
    with lock:
        a = state["registry"].get(aid)
        if not a:
            return jsonify({"ok":False,"error":"Agent not found"}),404
        # Validate sub key
        valid_key = (sub_key == a["sub_key"])
        if not valid_key:
            state["gw"]["auth_fail"]+=1; state["gw"]["e401"]+=1
            add_event(f"MANUAL REQUEST FAILED — Invalid sub-key for {aid}","error")
            return jsonify({"ok":False,"status":"401","error":"Invalid subscription key"})
        if a["state"]!="ACTIVE":
            add_event(f"MANUAL REQUEST FAILED — Agent {aid} is {a['state']}","error")
            return jsonify({"ok":False,"status":"503","error":f"Agent is {a['state']}"})
        lat=random.randint(120,800)
        risk=RISK.get(action,40)
        allowed=action in SAFE
        verdict="ALLOW" if allowed else "BLOCK"
        state["gw"]["req_in"]+=1; state["gw"]["auth_ok"]+=1
        if aid=="AGT-POL-001": state["gw"]["routed_pol"]+=1
        else: state["gw"]["routed_cost"]+=1
        a["runs"]+=1; state["gov"]["total_runs"]+=1
        tok=random.randint(100,500); a["tok"]+=tok; state["gov"]["total_tok"]+=tok
        add_event(f"MANUAL OK  {user} → {aid}  {action}  verdict={verdict}  {lat}ms","ok")
        add_audit(f"MANUAL  {user}  →  {aid}  {action}  {verdict}  {lat}ms")
        state["pipeline"].insert(0,{"s":"OK","k":mask(sub_key),"a":aid,"act":action[:12],"ms":lat})
        state["pipeline"]=state["pipeline"][:8]
    return jsonify({"ok":True,"status":"OK","verdict":verdict,"risk":risk,"latency_ms":lat,"tokens_used":tok})

@app.route("/api/action/add_pending", methods=["POST"])
def add_pending_sim():
    data = request.get_json()
    name = data.get("name","New Agent")
    with lock:
        state["pending"].insert(0,{"name":name,"ts":ts()})
        state["pending"]=state["pending"][:5]
        add_event(f"New agent registration request: {name}","warn")
    return jsonify({"ok":True})

# ─── main page ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return HTML_PAGE, 200, {"Content-Type": "text/html; charset=utf-8"}

# ─── HTML frontend ────────────────────────────────────────────────────────────
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agentic Management Platform</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@500;600;700&family=Orbitron:wght@600;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080c0f;--bg2:#0d1117;--bg3:#111820;--bg4:#141e28;
  --border:#1e3a4a;--border2:#2a4a5a;
  --gold:#f59e0b;--gold2:#fbbf24;
  --cyan:#22d3ee;--cyan2:#67e8f9;
  --purple:#a78bfa;--purple2:#c4b5fd;
  --lime:#86efac;--lime2:#bbf7d0;
  --red:#f87171;--red2:#fca5a5;
  --orange:#fb923c;
  --blue:#60a5fa;
  --teal:#2dd4bf;
  --mute:#4a6070;--mute2:#6b8090;
  --text:#d0e8f0;--text2:#8ab0c0;
  --ok:#4ade80;--warn:#fbbf24;--err:#f87171;
  --r:4px;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;font-size:12px;height:100%;overflow-x:hidden}
::selection{background:var(--cyan);color:#000}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}

/* TOP BAR */
#topbar{background:var(--bg2);border-bottom:1px solid var(--border2);padding:10px 24px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:100;width:100%}
#logo{font-family:'Orbitron',monospace;font-size:15px;color:var(--gold);letter-spacing:3px;font-weight:900}
#logo span{color:var(--cyan)}
#run-id{color:var(--mute2);font-size:11px;margin-left:auto}
#env-badge{background:var(--bg3);border:1px solid var(--teal);color:var(--teal);padding:3px 12px;border-radius:2px;font-size:11px;letter-spacing:1px}
#tick-counter{color:var(--mute);font-size:11px}

/* TABS */
#tabs{background:var(--bg2);border-bottom:1px solid var(--border);display:flex;gap:0;padding:0 24px;overflow-x:auto;width:100%}
.tab{padding:12px 24px;cursor:pointer;color:var(--mute2);font-size:12px;letter-spacing:1.5px;border-bottom:2px solid transparent;transition:all .2s;white-space:nowrap;font-family:'Rajdhani',sans-serif;font-weight:700}
.tab:hover{color:var(--text);background:var(--bg3)}
.tab.active{color:var(--gold);border-bottom-color:var(--gold);background:var(--bg3)}

/* MAIN GRID - FULL WIDTH */
#main{display:block;padding:12px;width:100%;max-width:100vw;box-sizing:border-box}
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:6px;overflow:hidden;display:flex;flex-direction:column;width:100%;height:calc(100vh - 118px)}
.panel-header{background:var(--bg3);padding:14px 24px;border-bottom:1px solid var(--border2);display:flex;align-items:center;gap:12px;font-family:'Rajdhani',sans-serif;font-weight:700;font-size:14px;letter-spacing:2px;flex-shrink:0}
.panel-body{padding:16px 24px;flex:1;overflow-y:auto}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px;min-height:100%}
.three-col{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;min-height:100%}
.four-col{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:16px;min-height:100%}
.col-block{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:16px;overflow-y:auto}
.col-block-title{font-family:'Rajdhani',sans-serif;font-weight:700;font-size:11px;letter-spacing:2px;color:var(--mute2);text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid var(--border);margin-bottom:12px;display:flex;align-items:center;gap:6px}

/* AGENT CARDS */
.agent-card{display:block;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:10px;margin-bottom:10px;position:relative;transition:border-color .2s}
.agent-card:hover{border-color:var(--border2)}
.agent-card.active-pulse{border-color:var(--cyan);box-shadow:0 0 8px rgba(34,211,238,.15)}
.agent-header{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.agent-id{font-family:'Orbitron',monospace;font-size:11px;font-weight:700;letter-spacing:1px}
.agent-name{color:var(--text);font-size:13px;margin-bottom:4px;font-weight:600}
.agent-desc{color:var(--mute2);font-size:11px;margin-bottom:8px}
.state-badge{font-size:9px;padding:1px 6px;border-radius:2px;font-family:'Rajdhani',sans-serif;font-weight:700;letter-spacing:1px}
.state-ACTIVE{background:rgba(74,222,128,.15);color:var(--ok);border:1px solid rgba(74,222,128,.3)}
.state-BLOCKED{background:rgba(248,113,113,.15);color:var(--err);border:1px solid rgba(248,113,113,.3)}
.state-RETIRED{background:rgba(74,90,100,.3);color:var(--mute2);border:1px solid var(--border)}
.state-DEV{background:rgba(251,191,36,.15);color:var(--warn);border:1px solid rgba(251,191,36,.3)}

/* META ROW */
.meta-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:4px}
.meta-item{display:flex;gap:3px;font-size:10px}
.meta-label{color:var(--mute2)}
.meta-val{color:var(--text2)}

/* SUB KEY */
.subkey-box{background:var(--bg);border:1px solid var(--border);border-radius:2px;padding:4px 8px;font-size:10px;color:var(--teal);display:flex;align-items:center;justify-content:space-between;margin:4px 0;font-family:'Share Tech Mono',monospace}
.copy-btn{cursor:pointer;color:var(--mute2);font-size:9px;padding:1px 4px;border:1px solid var(--border);border-radius:2px;background:none;color:var(--mute2);transition:color .2s}
.copy-btn:hover{color:var(--cyan)}

/* BARS */
.bar-row{margin:4px 0}
.bar-label{display:flex;justify-content:space-between;margin-bottom:2px;font-size:10px;color:var(--mute2)}
.bar-track{background:var(--bg);border-radius:3px;height:6px;overflow:hidden}
.bar-fill{height:100%;border-radius:2px;transition:width .5s ease}
.bar-ok{background:linear-gradient(90deg,var(--ok),var(--teal))}
.bar-warn{background:linear-gradient(90deg,var(--warn),var(--orange))}
.bar-err{background:linear-gradient(90deg,var(--err),var(--red2))}
.bar-cyan{background:linear-gradient(90deg,var(--cyan),var(--blue))}
.bar-purple{background:linear-gradient(90deg,var(--purple),var(--blue))}
.bar-gold{background:linear-gradient(90deg,var(--gold),var(--orange))}
.bar-lime{background:linear-gradient(90deg,var(--lime),var(--teal))}

/* TAGS */
.tags{display:flex;gap:4px;flex-wrap:wrap;margin:4px 0}
.tag{font-size:9px;padding:1px 5px;border-radius:2px;background:rgba(96,165,250,.12);color:var(--blue);border:1px solid rgba(96,165,250,.25)}
.policy-tag{background:rgba(167,139,250,.12);color:var(--purple);border:1px solid rgba(167,139,250,.25)}

/* ACTION BUTTONS */
.actions-grid{display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-top:6px}
.btn{padding:5px 8px;border:1px solid var(--border2);border-radius:var(--r);background:var(--bg3);color:var(--text2);cursor:pointer;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:.5px;transition:all .15s;text-align:center}
.btn:hover{transform:translateY(-1px);box-shadow:0 2px 8px rgba(0,0,0,.4)}
.btn:active{transform:translateY(0)}
.btn-cyan{border-color:rgba(34,211,238,.4);color:var(--cyan)}
.btn-cyan:hover{background:rgba(34,211,238,.1);border-color:var(--cyan)}
.btn-gold{border-color:rgba(245,158,11,.4);color:var(--gold)}
.btn-gold:hover{background:rgba(245,158,11,.1);border-color:var(--gold)}
.btn-purple{border-color:rgba(167,139,250,.4);color:var(--purple)}
.btn-purple:hover{background:rgba(167,139,250,.1);border-color:var(--purple)}
.btn-err{border-color:rgba(248,113,113,.4);color:var(--err)}
.btn-err:hover{background:rgba(248,113,113,.1);border-color:var(--err)}
.btn-ok{border-color:rgba(74,222,128,.4);color:var(--ok)}
.btn-ok:hover{background:rgba(74,222,128,.1);border-color:var(--ok)}
.btn-warn{border-color:rgba(251,191,36,.4);color:var(--warn)}
.btn-warn:hover{background:rgba(251,191,36,.1);border-color:var(--warn)}
.btn-full{grid-column:1/-1}

/* STATS ROW */
.stats-row{display:flex;gap:12px;flex-wrap:wrap;margin:4px 0}
.stat{display:flex;flex-direction:column;gap:1px}
.stat-val{font-family:'Orbitron',monospace;font-size:14px;font-weight:700}
.stat-lbl{font-size:9px;color:var(--mute2)}

/* SECTION TITLE */
.section-title{font-family:'Rajdhani',sans-serif;font-weight:700;font-size:11px;letter-spacing:2px;color:var(--mute2);text-transform:uppercase;padding:10px 0 6px;border-bottom:1px solid var(--border);margin-bottom:8px}

/* PIPELINE TABLE */
.pipeline-table{width:100%;border-collapse:collapse;font-size:10px}
.pipeline-table th{color:var(--mute);font-weight:normal;padding:3px 4px;text-align:left;border-bottom:1px solid var(--border)}
.pipeline-table td{padding:3px 4px;border-bottom:1px solid rgba(30,58,74,.5)}
.s-ok{color:var(--ok)}
.s-err{color:var(--err)}
.s-warn{color:var(--warn)}

/* Q-VALUES */
.q-row{display:flex;align-items:center;gap:6px;margin:3px 0;font-size:10px}
.q-label{width:70px;color:var(--mute2)}
.q-bar{flex:1;height:6px;background:var(--bg);border-radius:3px;overflow:hidden}
.q-fill{height:100%;border-radius:3px;transition:width .4s ease;background:linear-gradient(90deg,var(--blue),var(--cyan))}
.q-val{width:50px;text-align:right;font-family:'Orbitron',monospace;font-size:9px}

/* STEP TRACE */
.step-row{display:flex;align-items:center;gap:6px;padding:2px 0;font-size:10px}
.step-icon{width:12px;text-align:center;flex-shrink:0}
.step-text{color:var(--mute2)}
.step-text.active{color:var(--text);font-weight:bold}
.step-text.done{color:var(--mute)}

/* EVENT STREAM */
#event-stream{background:var(--bg2);border-top:1px solid var(--border2);padding:8px 24px;max-height:120px;overflow-y:auto;position:fixed;bottom:0;left:0;right:0;z-index:50;width:100%}
#event-stream-header{font-family:'Rajdhani',sans-serif;font-weight:700;font-size:11px;letter-spacing:2px;color:var(--mute2);margin-bottom:4px}
.event-row{display:flex;gap:8px;font-size:10px;padding:1px 0;border-bottom:1px solid rgba(30,58,74,.3)}
.event-ts{color:var(--mute);flex-shrink:0;width:70px}
.ev-ok{color:var(--ok)}
.ev-warn{color:var(--warn)}
.ev-error{color:var(--err)}
.ev-info{color:var(--text2)}

/* SPARKLINE */
.sparkline-wrap{background:var(--bg);border-radius:2px;padding:4px;margin:4px 0}
canvas.spark{display:block}

/* AUDIT LOG */
.audit-row{font-size:10px;padding:2px 0;border-bottom:1px solid rgba(30,58,74,.3);color:var(--text2)}
.audit-ts{color:var(--mute);margin-right:6px}

/* MODAL */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:200;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border2);border-radius:var(--r);padding:20px;width:400px;max-width:95vw;max-height:90vh;overflow-y:auto}
.modal-title{font-family:'Orbitron',monospace;font-size:13px;font-weight:700;color:var(--gold);margin-bottom:16px;letter-spacing:1px}
.form-group{margin-bottom:12px}
.form-label{display:block;font-size:10px;color:var(--mute2);margin-bottom:4px;font-family:'Rajdhani',sans-serif;font-weight:600;letter-spacing:1px;text-transform:uppercase}
.form-input,.form-select{width:100%;background:var(--bg);border:1px solid var(--border2);border-radius:var(--r);padding:7px 10px;color:var(--text);font-family:'Share Tech Mono',monospace;font-size:11px;outline:none}
.form-input:focus,.form-select:focus{border-color:var(--cyan)}
.modal-actions{display:flex;gap:8px;margin-top:16px}
.modal-close{position:absolute;top:12px;right:12px;background:none;border:none;color:var(--mute2);cursor:pointer;font-size:16px;line-height:1}
.modal-close:hover{color:var(--err)}

/* ALERT TOAST */
#toast{position:fixed;top:60px;right:16px;z-index:300;display:flex;flex-direction:column;gap:4px}
.toast-item{background:var(--bg2);border:1px solid var(--border2);padding:8px 12px;border-radius:var(--r);font-size:11px;min-width:240px;animation:slideIn .2s ease;max-width:320px}
.toast-ok{border-color:rgba(74,222,128,.5);color:var(--ok)}
.toast-err{border-color:rgba(248,113,113,.5);color:var(--err)}
.toast-warn{border-color:rgba(251,191,36,.5);color:var(--warn)}
@keyframes slideIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}

/* SIMULATE REQUEST PANEL */
.sim-panel{background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:10px;margin-top:8px}

/* PENDING CARD */
.pending-card{background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.25);border-radius:var(--r);padding:6px 10px;display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}
.pending-name{font-size:11px;color:var(--warn)}
.pending-actions{display:flex;gap:4px}

/* SCROLLABLE SECTIONS */
.scroll-section{max-height:200px;overflow-y:auto}

/* CIRCUIT INDICATOR */
.circuit-indicator{display:flex;align-items:center;gap:6px;padding:4px 8px;border-radius:2px;font-size:10px;margin-bottom:6px}
.circuit-closed{background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.3);color:var(--ok)}
.circuit-open{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);color:var(--err)}

/* PULSE DOT */
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.pulse-dot{width:6px;height:6px;border-radius:50%;display:inline-block;animation:pulse 1.5s infinite}
.pulse-ok{background:var(--ok)}
.pulse-warn{background:var(--warn)}
.pulse-err{background:var(--err)}

/* POD GRID */
.pod-grid{display:grid;grid-template-columns:1fr 1fr;gap:4px}
.pod-card{background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:6px;font-size:10px}
.pod-id{color:var(--mute2);margin-bottom:3px}
.pod-agent{color:var(--cyan);font-weight:bold}
.pod-bars{margin-top:4px}

/* BELLMAN DISPLAY */
.bellman-box{background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:8px;margin-bottom:6px;font-size:10px}
.bellman-eq{font-size:11px;color:var(--cyan);margin-bottom:4px}
.bellman-calc{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.bv{font-family:'Orbitron',monospace;font-size:12px;font-weight:700}

/* VERSION HISTORY */
.version-pill{display:inline-block;padding:1px 6px;border-radius:10px;font-size:9px;background:var(--bg);border:1px solid var(--border);color:var(--mute2);margin-right:2px}
.version-pill.current{background:rgba(34,211,238,.1);border-color:var(--cyan);color:var(--cyan)}

/* RESPONSIVE */
@media(max-width:1200px){#main{grid-template-columns:1fr 1fr}}
@media(max-width:700px){#main{grid-template-columns:1fr}}

.header-gold{color:var(--gold)}
.header-aqua{color:var(--cyan)}
.header-purple{color:var(--purple)}
.header-lime{color:var(--lime)}
.header-blue{color:var(--blue)}
.three-col{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;min-height:100%}
.col-block{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:14px;overflow-y:auto}
.col-block-title{font-family:'Rajdhani',sans-serif;font-weight:700;font-size:11px;letter-spacing:2px;color:var(--mute2);text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid var(--border);margin-bottom:10px}
.flow-step-item{padding:6px 10px;margin:4px 0;border-radius:3px;font-size:11px;border-left:3px solid var(--border);transition:all .3s}
.flow-step-item.done{border-left-color:var(--ok);color:var(--ok);background:rgba(74,222,128,.06)}
.flow-step-item.active{border-left-color:var(--gold);color:var(--text);background:rgba(245,158,11,.1);font-weight:bold}
.flow-step-item.pending{border-left-color:var(--border);color:var(--mute2)}
.rbac-role-card{background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:8px 10px;margin-bottom:6px}
.rbac-perm{font-size:9px;padding:1px 5px;border-radius:2px;background:rgba(96,165,250,.1);color:var(--blue);border:1px solid rgba(96,165,250,.2);display:inline-block;margin:1px}
.mcp-server-card{background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:8px 10px;margin-bottom:6px}
.topology-row{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:11px}
.topo-agent{padding:4px 10px;border-radius:3px;font-size:10px;font-family:'Orbitron',monospace;font-weight:700}
.topo-arrow{color:var(--teal);font-size:14px}
.topo-blocked{color:var(--err);font-size:14px}
</style>
</head>
<body>

<!-- TOP BAR -->
<div id="topbar">
  <div id="logo">⬡ AGENTIC <span>PLATFORM</span></div>
  <div id="env-badge">PRIVATE CLOUD · OPENSHIFT</div>
  <div id="tick-counter">TICK <span id="tick">0</span></div>
  <div id="run-id">RUN <span id="run-id-val">—</span>  ·  <span id="live-time">—</span></div>
</div>

<!-- TABS -->
<div id="tabs">
  <div class="tab active" onclick="switchTab(0)">REGISTRY</div>
  <div class="tab" onclick="switchTab(1)">API GATEWAY</div>
  <div class="tab" onclick="switchTab(2)">POLICY AGENT</div>
  <div class="tab" onclick="switchTab(3)">COST ADVISOR</div>
  <div class="tab" onclick="switchTab(4)">GOVERNANCE</div>
  <div class="tab" onclick="switchTab(5)">SIMULATE REQUEST</div>
  <div class="tab" onclick="switchTab(6)" style="color:var(--err)">🔐 RBAC</div>
  <div class="tab" onclick="switchTab(7)" style="color:var(--teal)">🔌 MCP TRUST</div>
  <div class="tab" onclick="switchTab(8)" style="color:var(--lime)">🤝 A2A TRUST</div>
  <div class="tab" onclick="switchTab(9)" style="color:var(--gold)">🔧 API→TOOL</div>
  <div class="tab" onclick="switchTab(10)" style="color:var(--orange)">🛡 VULN SCAN</div>
  <div class="tab" onclick="switchTab(11)" style="color:var(--purple)">🔒 PII MASKING</div>
</div>

<!-- TOAST -->
<div id="toast"></div>

<!-- MAIN PANELS -->
<div id="main" style="padding-bottom:130px">

  <!-- PANEL 1: REGISTRY -->
  <div class="panel" id="panel-registry">
    <div class="panel-header"><span class="header-gold">◈</span>&nbsp;AGENT REGISTRY &amp; MANAGEMENT</div>
    <div class="panel-body">
      <!-- Search + Filter Bar -->
      <div style="display:flex;gap:8px;margin-bottom:10px;align-items:center;flex-wrap:wrap">
        <input class="form-input" id="reg-search" placeholder="🔍  Search by name, tag, ID…" style="flex:1;min-width:180px" oninput="filterRegistry()">
        <select class="form-select" id="reg-env-filter" style="width:90px" onchange="filterRegistry()">
          <option value="ALL">All Envs</option>
          <option value="DEV">DEV</option>
          <option value="UAT">UAT</option>
          <option value="PROD">PROD</option>
        </select>
        <select class="form-select" id="reg-state-filter" style="width:100px" onchange="filterRegistry()">
          <option value="ALL">All States</option>
          <option value="ACTIVE">ACTIVE</option>
          <option value="BLOCKED">BLOCKED</option>
          <option value="RETIRED">RETIRED</option>
        </select>
        <select class="form-select" id="reg-fw-filter" style="width:110px" onchange="filterRegistry()">
          <option value="ALL">All Frameworks</option>
          <option value="custom-py">custom-py</option>
          <option value="LangGraph">LangGraph</option>
          <option value="LangChain">LangChain</option>
          <option value="Google ADK">Google ADK</option>
          <option value="Salesforce">Salesforce</option>
          <option value="ServiceNow">ServiceNow</option>
        </select>
        <span id="reg-count" style="font-size:10px;color:var(--mute2);white-space:nowrap"></span>
      </div>
      <!-- Env Distribution Bar -->
      <div style="margin-bottom:10px">
        <div style="font-size:10px;color:var(--mute2);margin-bottom:4px">ENVIRONMENT DISTRIBUTION</div>
        <div id="env-dist-bar" style="display:flex;gap:4px;height:18px;border-radius:3px;overflow:hidden"></div>
        <div id="env-dist-labels" style="display:flex;gap:12px;margin-top:4px;font-size:10px"></div>
      </div>
      <div class="section-title">Registered Agents</div>
      <div id="registry-cards"></div>
      <div class="section-title" style="margin-top:10px">Pending Registrations</div>
      <div id="pending-list"><div style="color:var(--mute);font-size:10px">No pending registrations</div></div>
      <div class="section-title" style="margin-top:10px">Management Actions</div>
      <div class="actions-grid">
        <button class="btn btn-cyan btn-full" onclick="openModal('register')">＋ Register New Agent</button>
        <button class="btn btn-warn" onclick="openModal('add-pending')">⏳ Add Pending Request</button>
        <button class="btn btn-gold" onclick="openModal('sim-req')">⚡ Simulate Request</button>
      </div>
    </div>
  </div>

  <!-- PANEL 2: GATEWAY -->
  <div class="panel" id="panel-gateway" style="display:none">
    <div class="panel-header"><span class="header-aqua">⬡</span>&nbsp;API GATEWAY · REQUEST FLOW &nbsp;<span style="font-size:11px;color:var(--mute2);font-weight:400">Auth · Route · Rate-Limit · Throttle · Circuit Breaker</span></div>
    <div class="panel-body">
      <div id="circuit-indicator" class="circuit-indicator circuit-closed" style="margin-bottom:12px"><span class="pulse-dot pulse-ok"></span> Circuit Breaker: CLOSED (healthy)</div>
      <div class="stats-row" id="gw-stats-row" style="margin-bottom:16px;gap:24px"></div>
      <div class="three-col">
        <div class="col-block">
          <div class="col-block-title">📊 Gateway Counters</div>
          <div id="gw-counters"></div>
        </div>
        <div class="col-block">
          <div class="col-block-title">🔄 Live Request Pipeline</div>
          <table class="pipeline-table" style="font-size:11px">
            <thead><tr><th>STATUS</th><th>KEY</th><th>AGENT</th><th>ACTION</th><th>MS</th></tr></thead>
            <tbody id="pipeline-body"></tbody>
          </table>
        </div>
        <div class="col-block">
          <div class="col-block-title">🔐 Auth + Routing Flow</div>
          <div id="auth-flow"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- PANEL 3: POLICY AGENT -->
  <div class="panel" id="panel-policy" style="display:none">
    <div class="panel-header"><span class="header-purple">⚖</span>&nbsp;POLICY AGENT [AGT-POL-001]</div>
    <div class="panel-body">
      <div class="section-title">Bellman Policy Update</div>
      <div class="bellman-box">
        <div class="bellman-eq">Q(s,a) = r + γ · max<sub>a′</sub> Q(s′,a′)</div>
        <div class="bellman-calc">
          <span class="bv" id="pol-reward" style="color:var(--gold)">+0.000</span>
          <span style="color:var(--mute2)">+</span>
          <span class="bv" style="color:var(--cyan)">0.92</span>
          <span style="color:var(--mute2)">×</span>
          <span class="bv" id="pol-maxq" style="color:var(--text)">0.000</span>
          <span style="color:var(--mute2)">=</span>
          <span class="bv" id="pol-target">0.000</span>
          <span class="bv" id="pol-action" style="color:var(--ok);font-size:11px">ALLOW</span>
        </div>
        <div style="margin-top:4px;font-size:10px;color:var(--mute2)">
          ε = <span id="pol-epsilon">0.28</span> · Exploit <span id="pol-exploit">72</span>% · Explore <span id="pol-explore">28</span>%
        </div>
      </div>
      <div class="section-title">Q-Values (Policy Actions)</div>
      <div id="pol-qvals"></div>
      <div class="section-title" style="margin-top:8px">Execution Trace</div>
      <div id="pol-trace"></div>
      <div class="section-title" style="margin-top:8px">Recent Decisions</div>
      <div id="pol-log" class="scroll-section"></div>
      <div class="section-title" style="margin-top:8px">Statistics</div>
      <div class="stats-row" id="pol-stats"></div>
    </div>
  </div>

  <!-- PANEL 4: COST ADVISOR -->
  <div class="panel" id="panel-cost" style="display:none">
    <div class="panel-header"><span class="header-lime">💰</span>&nbsp;COST ADVISOR [AGT-COST-002]</div>
    <div class="panel-body">
      <div class="section-title">Budget Utilisation</div>
      <div id="cost-budget-bar"></div>
      <div class="section-title" style="margin-top:8px">Spend by Model</div>
      <div id="cost-models"></div>
      <div class="section-title" style="margin-top:8px">Execution Trace</div>
      <div id="cost-trace"></div>
      <div class="section-title" style="margin-top:8px">Cost Recommendations</div>
      <div id="cost-recs"></div>
      <div class="section-title" style="margin-top:8px">Recent Cost Events</div>
      <div id="cost-log" class="scroll-section"></div>
      <div class="section-title" style="margin-top:8px">Statistics</div>
      <div class="stats-row" id="cost-stats"></div>
    </div>
  </div>

  <!-- PANEL 5: GOVERNANCE -->
  <div class="panel" id="panel-gov" style="display:none">
    <div class="panel-header"><span class="header-blue">✦</span>&nbsp;GOVERNANCE &amp; OBSERVABILITY &nbsp;<span style="font-size:11px;color:var(--mute2);font-weight:400">Audit · Metrics · Alerts · Pods · Compliance</span></div>
    <div class="panel-body">
      <div class="four-col" style="margin-bottom:16px">
        <div class="col-block" style="grid-column:1/3">
          <div class="col-block-title">📊 Platform KPIs</div>
          <div id="gov-kpis"></div>
        </div>
        <div class="col-block">
          <div class="col-block-title">⏱ Latency p50/p95</div>
          <canvas id="lat-spark" class="spark" width="100%" height="60" style="width:100%"></canvas>
          <div id="lat-vals" style="font-size:11px;color:var(--mute2);margin-top:6px"></div>
          <div class="col-block-title" style="margin-top:12px">⚡ Error Rate</div>
          <canvas id="err-spark" class="spark" width="100%" height="40" style="width:100%"></canvas>
        </div>
        <div class="col-block">
          <div class="col-block-title">🐳 OpenShift Pods</div>
          <div id="pod-grid"></div>
        </div>
      </div>
      <div class="col-block">
        <div class="col-block-title">📋 Audit Trail</div>
        <div id="audit-log" style="max-height:200px;overflow-y:auto"></div>
      </div>
    </div>
  </div>

  <!-- PANEL 6: SIMULATE REQUEST -->
  <div class="panel" id="panel-simulate" style="display:none">
    <div class="panel-header"><span style="color:var(--orange)">⚡</span>&nbsp;SIMULATE REQUEST · END USER FLOW</div>
    <div class="panel-body">
      <div style="font-size:10px;color:var(--mute2);margin-bottom:12px;line-height:1.6">
        Enter your subscription key and agent ID to simulate how an end-user consumer authenticates and routes a request through the platform.
      </div>

      <div class="section-title">Consumer Authentication</div>
      <div class="form-group">
        <label class="form-label">Target Agent ID</label>
        <select class="form-select" id="sim-agent-id">
          <option value="AGT-POL-001">AGT-POL-001 — Policy Agent</option>
          <option value="AGT-COST-002">AGT-COST-002 — Cost Advisor Agent</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Subscription Key</label>
        <input class="form-input" id="sim-sub-key" placeholder="sk-xxxxxxxx…  (paste your key)">
        <div style="font-size:9px;color:var(--mute2);margin-top:3px">Find your key in the Registry panel → agent card</div>
      </div>
      <div class="form-group">
        <label class="form-label">Username</label>
        <input class="form-input" id="sim-user" value="dev.chen" placeholder="username">
      </div>
      <div class="form-group">
        <label class="form-label">Action / Request Type</label>
        <select class="form-select" id="sim-action">
          <option>query_contracts</option><option>run_risk_check</option>
          <option>analyse_spend</option><option>export_report</option>
          <option>read_audit</option><option>approve_workflow</option>
          <option>trigger_batch</option><option>delete_data</option>
        </select>
      </div>
      <button class="btn btn-gold btn-full" style="margin-bottom:12px;padding:10px" onclick="runSimRequest()">⚡ Send Request via Gateway</button>

      <div id="sim-result" style="display:none"></div>

      <div class="section-title" style="margin-top:12px">Request Flow Diagram</div>
      <div id="sim-flow-diagram" style="padding:8px;background:var(--bg);border-radius:4px;font-size:10px;line-height:2">
        <div id="flow-step-1" class="flow-step" style="color:var(--mute2)">① Consumer sends subscription key + agent ID</div>
        <div id="flow-step-2" class="flow-step" style="color:var(--mute2)">② Gateway extracts &amp; validates key (SHA-256)</div>
        <div id="flow-step-3" class="flow-step" style="color:var(--mute2)">③ RBAC scope check</div>
        <div id="flow-step-4" class="flow-step" style="color:var(--mute2)">④ Rate limit check (token bucket)</div>
        <div id="flow-step-5" class="flow-step" style="color:var(--mute2)">⑤ Throttle check</div>
        <div id="flow-step-6" class="flow-step" style="color:var(--mute2)">⑥ Route to correct agent</div>
        <div id="flow-step-7" class="flow-step" style="color:var(--mute2)">⑦ Agent processes &amp; returns response</div>
        <div id="flow-step-8" class="flow-step" style="color:var(--mute2)">⑧ Audit log + token accounting</div>
      </div>

      <div class="section-title" style="margin-top:12px">Agent Key Lookup</div>
      <div id="key-lookup"></div>
    </div>
  </div>


  <!-- PANEL 7: RBAC -->
  <div class="panel" id="panel-rbac" style="display:none">
    <div class="panel-header" style="border-bottom-color:rgba(248,113,113,.4)">
      <span style="color:var(--err)">🔐</span>&nbsp;
      <span style="color:var(--err)">ROLE-BASED ACCESS CONTROL (RBAC)</span>&nbsp;
      <span style="font-size:11px;color:var(--mute2);font-weight:400">3 Levels · User→Agent · Agent→Tool · Agent→Agent</span>
    </div>
    <div class="panel-body">
      <div class="three-col">

        <!-- LEFT: Roles & Users -->
        <div class="col-block">
          <div class="col-block-title" style="color:var(--err)">Platform Roles</div>
          <div id="rbac-roles"></div>
          <div class="col-block-title" style="margin-top:16px;color:var(--err)">Registered Users</div>
          <div id="rbac-users"></div>
        </div>

        <!-- MIDDLE: Interactive Check -->
        <div class="col-block">
          <div class="col-block-title" style="color:var(--err)">Interactive RBAC Check</div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">User</label>
            <select class="form-select" id="rbac-user-sel">
              <option value="U-001">alex.admin (admin)</option>
              <option value="U-002" selected>dev.chen (developer)</option>
              <option value="U-003">approver.jan (approver)</option>
              <option value="U-004">viewer.bob (viewer)</option>
              <option value="U-005">svc.pipeline (service account)</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Action Requested</label>
            <select class="form-select" id="rbac-action-sel">
              <option>read</option><option>execute</option><option>write</option>
              <option>approve</option><option>govern</option>
              <option>query_contracts</option><option>delete_data</option>
              <option>export_report</option><option>update_model</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:12px">
            <label class="form-label">Target Agent</label>
            <select class="form-select" id="rbac-agent-sel">
              <option value="AGT-POL-001">AGT-POL-001 Policy Agent</option>
              <option value="AGT-COST-002">AGT-COST-002 Cost Advisor</option>
            </select>
          </div>
          <button class="btn btn-err" style="width:100%;padding:10px;font-size:12px" onclick="runRbacCheck()">
            🔐 Check Permission
          </button>
          <div id="rbac-result" style="margin-top:12px;display:none"></div>
          <div class="section-title" style="margin-top:16px">Risk Routing Matrix</div>
          <div style="font-size:11px;line-height:2">
            <div><span style="color:var(--ok)">■</span> Risk 0–29  → ALLOW direct</div>
            <div><span style="color:var(--warn)">■</span> Risk 30–69 → ALLOW + alert logged</div>
            <div><span style="color:var(--orange)">■</span> Risk 70–84 → ESCALATE to approver</div>
            <div><span style="color:var(--err)">■</span> Risk 85+  → MANDATORY approval</div>
          </div>
        </div>

        <!-- RIGHT: RBAC Decision Log -->
        <div class="col-block">
          <div class="col-block-title" style="color:var(--err)">RBAC Decision Log</div>
          <div style="font-size:11px;margin-bottom:8px;color:var(--mute2)">
            Checks: <span id="rbac-check-count" style="color:var(--cyan)">0</span> &nbsp;
            Allowed: <span id="rbac-allow-count" style="color:var(--ok)">0</span> &nbsp;
            Blocked: <span id="rbac-block-count" style="color:var(--err)">0</span>
          </div>
          <div id="rbac-log" style="max-height:400px;overflow-y:auto"></div>
          <div class="section-title" style="margin-top:12px">3 Enforcement Levels</div>
          <div style="font-size:11px;line-height:1.8;color:var(--mute2)">
            <div style="color:var(--cyan)">Level 1 — User → Agent</div>
            <div>Who can call which agent via subscription key</div>
            <div style="color:var(--cyan);margin-top:6px">Level 2 — Agent → Tool/MCP</div>
            <div>Which MCP servers each agent is allowed to call</div>
            <div style="color:var(--cyan);margin-top:6px">Level 3 — Agent → Agent (A2A)</div>
            <div>Which agents can orchestrate which sub-agents</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- PANEL 8: MCP TRUST -->
  <div class="panel" id="panel-mcp" style="display:none">
    <div class="panel-header" style="border-bottom-color:rgba(45,212,191,.4)">
      <span style="color:var(--teal)">🔌</span>&nbsp;
      <span style="color:var(--teal)">MCP TRUST — MODEL CONTEXT PROTOCOL</span>&nbsp;
      <span style="font-size:11px;color:var(--mute2);font-weight:400">Registry · Scope · HMAC · Validation · mTLS · Audit</span>
    </div>
    <div class="panel-body">
      <div class="three-col">

        <!-- LEFT: MCP Servers -->
        <div class="col-block">
          <div class="col-block-title" style="color:var(--teal)">Registered MCP Servers</div>
          <div id="mcp-servers"></div>
          <div class="col-block-title" style="margin-top:12px;color:var(--teal)">Trust Controls</div>
          <div style="font-size:11px;line-height:2;color:var(--mute2)">
            <div>✅ MCP Server Registry</div>
            <div>✅ Scope-based authorisation</div>
            <div>✅ Allow / Deny list</div>
            <div>✅ HMAC request signing</div>
            <div>✅ Response schema validation</div>
            <div>✅ Mutual TLS (mTLS)</div>
            <div>✅ Tool call audit trail</div>
          </div>
        </div>

        <!-- MIDDLE: Interactive MCP Call -->
        <div class="col-block">
          <div class="col-block-title" style="color:var(--teal)">Simulate MCP Tool Call</div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Calling Agent</label>
            <select class="form-select" id="mcp-agent-sel">
              <option value="AGT-POL-001">AGT-POL-001 Policy Agent</option>
              <option value="AGT-COST-002">AGT-COST-002 Cost Advisor</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Target MCP Server</label>
            <select class="form-select" id="mcp-server-sel" onchange="updateMcpTools()">
              <option value="MCP-AUDIT-001">MCP-AUDIT-001 Audit DB</option>
              <option value="MCP-FINOPS-002">MCP-FINOPS-002 FinOps Data</option>
              <option value="MCP-BILLING-003">MCP-BILLING-003 Billing API (no scope)</option>
              <option value="MCP-UNKNOWN-EXT">MCP-UNKNOWN-EXT External (unregistered)</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Tool to Call</label>
            <select class="form-select" id="mcp-tool-sel">
              <option>read_audit_log</option>
              <option>query_violations</option>
              <option>get_user_history</option>
            </select>
          </div>
          <div style="margin-bottom:12px;display:flex;align-items:center;gap:8px">
            <input type="checkbox" id="mcp-inject" style="width:14px;height:14px">
            <label style="font-size:11px;color:var(--warn);cursor:pointer" for="mcp-inject">
              ⚠ Simulate prompt injection payload
            </label>
          </div>
          <button class="btn btn-cyan" style="width:100%;padding:10px;font-size:12px;margin-bottom:4px" onclick="runMcpCall()">
            🔌 Send MCP Tool Call
          </button>
          <div id="mcp-result" style="margin-top:12px;display:none"></div>
        </div>

        <!-- RIGHT: MCP Call Log -->
        <div class="col-block">
          <div class="col-block-title" style="color:var(--teal)">MCP Call Log</div>
          <div style="font-size:11px;margin-bottom:8px;color:var(--mute2)">
            Total: <span id="mcp-total" style="color:var(--cyan)">0</span> &nbsp;
            Blocked: <span id="mcp-blocked" style="color:var(--err)">0</span> &nbsp;
            Injections: <span id="mcp-inject-count" style="color:var(--warn)">0</span>
          </div>
          <div id="mcp-call-log" style="max-height:280px;overflow-y:auto"></div>
          <div class="section-title" style="margin-top:12px">Call Flow</div>
          <div style="font-size:11px;line-height:2;color:var(--mute2)">
            <div>1. Is server registered?</div>
            <div>2. Does agent have scope?</div>
            <div>3. Is tool in contract?</div>
            <div>4. Sign request (HMAC)</div>
            <div>5. Validate response schema</div>
            <div>6. Log the tool call</div>
            <div>7. Return to agent</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- PANEL 9: A2A TRUST -->
  <div class="panel" id="panel-a2a" style="display:none">
    <div class="panel-header" style="border-bottom-color:rgba(134,239,172,.4)">
      <span style="color:var(--lime)">🤝</span>&nbsp;
      <span style="color:var(--lime)">A2A TRUST — AGENT TO AGENT</span>&nbsp;
      <span style="font-size:11px;color:var(--mute2);font-weight:400">Agent Cards · Delegation · Short-lived Tokens · Least Privilege · HITL</span>
    </div>
    <div class="panel-body">
      <div class="three-col">

        <!-- LEFT: Agent topology + controls -->
        <div class="col-block">
          <div class="col-block-title" style="color:var(--lime)">Agent Delegation Topology</div>
          <div id="a2a-topology"></div>
          <div class="col-block-title" style="margin-top:12px;color:var(--lime)">Simulate A2A Call</div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Calling Agent (Orchestrator)</label>
            <select class="form-select" id="a2a-caller-sel">
              <option value="AGT-HUB-000">AGT-HUB-000 Orchestration Hub</option>
              <option value="AGT-POL-001">AGT-POL-001 Policy Agent (no scope)</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Target Agent (Sub-agent)</label>
            <select class="form-select" id="a2a-callee-sel">
              <option value="AGT-POL-001">AGT-POL-001 Policy Agent</option>
              <option value="AGT-COST-002">AGT-COST-002 Cost Advisor</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Task</label>
            <select class="form-select" id="a2a-task-sel">
              <option>evaluate_policy_risk</option>
              <option>analyse_token_spend</option>
              <option>run_compliance_check</option>
            </select>
          </div>
          <div style="margin-bottom:12px;display:flex;align-items:center;gap:8px">
            <input type="checkbox" id="a2a-attack" style="width:14px;height:14px">
            <label style="font-size:11px;color:var(--warn);cursor:pointer" for="a2a-attack">
              ⚠ Simulate prompt injection attack
            </label>
          </div>
          <button class="btn btn-ok" style="width:100%;padding:10px;font-size:12px;margin-bottom:4px" onclick="runA2AFlow()">
            🤝 Initiate A2A Call
          </button>
          <div id="a2a-result" style="margin-top:10px;display:none"></div>
        </div>

        <!-- MIDDLE: Animated flow stepper -->
        <div class="col-block">
          <div class="col-block-title" style="color:var(--lime)">A2A Trust Flow — Live Animation</div>
          <div id="a2a-flow-steps"></div>
          <button class="btn btn-lime" style="width:100%;padding:8px;margin-top:10px;font-size:11px;border-color:rgba(134,239,172,.4);color:var(--lime)" onclick="stepA2AFlow()" id="a2a-next-btn" disabled>
            ▶ Step Through Flow
          </button>
          <div class="section-title" style="margin-top:12px">Token Info</div>
          <div id="a2a-token-info" style="font-size:11px;color:var(--mute2)">No active flow</div>
        </div>

        <!-- RIGHT: A2A call log + trust controls -->
        <div class="col-block">
          <div class="col-block-title" style="color:var(--lime)">A2A Call Log</div>
          <div style="font-size:11px;margin-bottom:8px;color:var(--mute2)">
            Flows: <span id="a2a-total" style="color:var(--cyan)">0</span> &nbsp;
            Blocked: <span id="a2a-blocked" style="color:var(--err)">0</span> &nbsp;
            Tokens: <span id="a2a-tokens" style="color:var(--purple)">0</span>
          </div>
          <div id="a2a-call-log" style="max-height:220px;overflow-y:auto"></div>
          <div class="section-title" style="margin-top:12px">A2A Trust Controls</div>
          <div style="font-size:11px;line-height:2;color:var(--mute2)">
            <div>✅ Agent Card verification</div>
            <div>✅ Delegation chain validation</div>
            <div>✅ Short-lived scoped tokens (10 min TTL)</div>
            <div>✅ Least privilege enforcement</div>
            <div>✅ Human-in-the-loop gate (high risk)</div>
            <div>✅ Bidirectional audit logging</div>
            <div>✅ Prompt injection prevention</div>
          </div>
          <div class="section-title" style="margin-top:12px">Golden Rule</div>
          <div style="font-size:11px;color:var(--mute2);font-style:italic;line-height:1.6">
            Every agent is treated as untrusted until it presents valid credentials — even internal agents. Trust is verified at the gateway on every hop. Never assumed.
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- PANEL 10: OpenAPI → MCP Tool Generator -->
  <div class="panel" id="panel-apitool" style="display:none">
    <div class="panel-header" style="border-bottom-color:rgba(245,158,11,.4)">
      <span style="color:var(--gold)">🔧</span>&nbsp;
      <span style="color:var(--gold)">OPENAPI → MCP TOOL GENERATOR</span>&nbsp;
      <span style="font-size:11px;color:var(--mute2);font-weight:400">Auto-generate MCP endpoints from existing API specs</span>
    </div>
    <div class="panel-body">
      <div class="three-col">
        <div class="col-block">
          <div class="col-block-title" style="color:var(--gold)">Input — API Specification</div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Source API</label>
            <select class="form-select" id="oapi-api-sel">
              <option>Salesforce Accounts API</option>
              <option>ServiceNow Incidents API</option>
              <option>Internal Inventory API</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Register MCP tools for Agent</label>
            <select class="form-select" id="oapi-agent-sel">
              <option value="AGT-POL-001">AGT-POL-001 — Policy Agent</option>
              <option value="AGT-COST-002">AGT-COST-002 — Cost Advisor</option>
            </select>
          </div>
          <div style="background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:8px;font-size:10px;color:var(--mute2);margin-bottom:12px;line-height:1.7">
            <div style="color:var(--gold);font-size:11px;margin-bottom:4px">What this does:</div>
            1. Parses the OpenAPI path definitions<br>
            2. Generates an MCP tool definition per endpoint<br>
            3. Creates input/output JSON schemas<br>
            4. Issues an MCP endpoint URL<br>
            5. Registers the tool with a governance scope<br>
            6. Logs to audit trail
          </div>
          <button class="btn" style="width:100%;padding:10px;background:rgba(245,158,11,.15);border-color:var(--gold);color:var(--gold);font-size:12px" onclick="runOpenApiGen()">
            🔧 Generate MCP Tool Definitions
          </button>
          <div id="oapi-result" style="margin-top:12px;display:none"></div>
        </div>
        <div class="col-block" style="grid-column:span 2">
          <div class="col-block-title" style="color:var(--gold)">Generated Tool Definitions</div>
          <div style="margin-bottom:8px;font-size:10px;color:var(--mute2)">
            Total generated this session: <span id="oapi-total" style="color:var(--gold)">0</span>
          </div>
          <div id="oapi-tools-list" style="max-height:480px;overflow-y:auto"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- PANEL 11: Vulnerability Scanner -->
  <div class="panel" id="panel-vuln" style="display:none">
    <div class="panel-header" style="border-bottom-color:rgba(251,146,60,.4)">
      <span style="color:var(--orange)">🛡</span>&nbsp;
      <span style="color:var(--orange)">DEPENDENCY &amp; VULNERABILITY SCANNER</span>&nbsp;
      <span style="font-size:11px;color:var(--mute2);font-weight:400">Automated CVE scanning for agent packages</span>
    </div>
    <div class="panel-body">
      <div class="three-col">
        <div class="col-block">
          <div class="col-block-title" style="color:var(--orange)">Run Scan</div>
          <div class="form-group" style="margin-bottom:10px">
            <label class="form-label">Target Agent</label>
            <select class="form-select" id="vuln-agent-sel">
              <option value="AGT-POL-001">AGT-POL-001 — Policy Agent</option>
              <option value="AGT-COST-002">AGT-COST-002 — Cost Advisor</option>
            </select>
          </div>
          <div style="background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:8px;font-size:10px;color:var(--mute2);margin-bottom:12px;line-height:1.7">
            <div style="color:var(--orange);font-size:11px;margin-bottom:4px">Scanner checks:</div>
            ◉ Known CVEs in dependency packages<br>
            ◉ Severity ratings (CRITICAL/HIGH/MEDIUM/LOW)<br>
            ◉ Affected package versions<br>
            ◉ Pass/Fail gate for deployment
          </div>
          <button class="btn" style="width:100%;padding:10px;background:rgba(251,146,60,.15);border-color:var(--orange);color:var(--orange);font-size:12px" onclick="runVulnScan()">
            🛡 Scan Agent Dependencies
          </button>
          <div id="vuln-result" style="margin-top:12px;display:none"></div>
          <div class="section-title" style="margin-top:16px">Platform Scan Stats</div>
          <div id="vuln-stats" style="font-size:11px;line-height:2.2"></div>
        </div>
        <div class="col-block" style="grid-column:span 2">
          <div class="col-block-title" style="color:var(--orange)">Scan History</div>
          <div id="vuln-history" style="max-height:500px;overflow-y:auto"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- PANEL 12: PII / Data Masking -->
  <div class="panel" id="panel-masking" style="display:none">
    <div class="panel-header" style="border-bottom-color:rgba(167,139,250,.4)">
      <span style="color:var(--purple)">🔒</span>&nbsp;
      <span style="color:var(--purple)">PII &amp; DATA MASKING · GDPR ARTICLE 30</span>&nbsp;
      <span style="font-size:11px;color:var(--mute2);font-weight:400">Policy-enforced field masking before audit logging</span>
    </div>
    <div class="panel-body">
      <div class="three-col">
        <div class="col-block">
          <div class="col-block-title" style="color:var(--purple)">Active Masking Rules</div>
          <div id="mask-rules" style="margin-bottom:12px"></div>
          <div class="col-block-title" style="color:var(--purple)">Live Masking Demo</div>
          <div style="font-size:10px;color:var(--mute2);margin-bottom:8px;line-height:1.6">
            Paste text containing PII below — the platform applies all active masking rules before the data reaches audit logs or LLM context.
          </div>
          <textarea class="form-input" id="mask-input" rows="6" style="width:100%;resize:vertical;font-family:monospace;font-size:11px" placeholder="e.g. Contact john.doe@acme.com or call +1-415-555-0172, API key: sk-abc123def456789012345678, IP: 192.168.1.100"></textarea>
          <button class="btn" style="width:100%;padding:10px;margin-top:8px;background:rgba(167,139,250,.15);border-color:var(--purple);color:var(--purple);font-size:12px" onclick="runMasking()">
            🔒 Apply PII Masking
          </button>
          <div id="mask-result" style="margin-top:12px;display:none"></div>
        </div>
        <div class="col-block" style="grid-column:span 2">
          <div class="col-block-title" style="color:var(--purple)">Masking Statistics &amp; Event Log</div>
          <div class="stats-row" id="mask-stats" style="margin-bottom:12px"></div>
          <div class="col-block-title" style="color:var(--purple);margin-top:8px">Recent Masking Events</div>
          <div id="mask-log" style="max-height:340px;overflow-y:auto"></div>
          <div class="col-block-title" style="color:var(--purple);margin-top:16px">GDPR Compliance Statement</div>
          <div style="font-size:11px;color:var(--mute2);line-height:1.8;background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:10px">
            <div style="color:var(--purple);margin-bottom:6px">Article 30 — Records of Processing Activities</div>
            ✓ All PII fields masked before storage in audit trail<br>
            ✓ Masking rules version-controlled and auditable<br>
            ✓ No raw PII enters LLM context windows<br>
            ✓ Configurable retention: 30/90/365 days<br>
            ✓ Right to erasure: masked fields cannot be re-identified<br>
            ✓ Data lineage tracked per agent run
          </div>
        </div>
      </div>
    </div>
  </div>

</div><!-- #main -->

<!-- EVENT STREAM -->
<div id="event-stream">
  <div id="event-stream-header">EVENT STREAM · LIVE</div>
  <div id="events-body"></div>
</div>

<!-- MODALS -->
<div class="modal-overlay" id="modal-register">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('register')">✕</button>
    <div class="modal-title">Register New Agent</div>
    <div class="form-group"><label class="form-label">Agent Name</label><input class="form-input" id="reg-name" placeholder="e.g. Supplier Intel Agent"></div>
    <div class="form-group"><label class="form-label">Description</label><input class="form-input" id="reg-desc" placeholder="Agent description"></div>
    <div class="form-group"><label class="form-label">Agent Endpoint URL</label><input class="form-input" id="reg-endpoint" placeholder="e.g. https://your-service.internal/api/v1"><div style="font-size:9px;color:var(--mute2);margin-top:3px">Base URL the gateway routes requests to (optional — can be set later)</div></div>
    <div class="form-group"><label class="form-label">Owner</label><input class="form-input" id="reg-owner" value="platform-team"></div>
    <div class="form-group"><label class="form-label">Framework</label>
      <select class="form-select" id="reg-framework"><option>custom-py</option><option>LangGraph</option><option>LangChain</option><option>Google ADK</option><option>Salesforce</option><option>ServiceNow</option></select>
    </div>
    <div class="form-group"><label class="form-label">Environment</label>
      <select class="form-select" id="reg-env"><option>DEV</option><option>UAT</option><option>PROD</option></select>
    </div>
    <div class="form-group"><label class="form-label">Rate Limit (req/min)</label><input class="form-input" id="reg-rl" type="number" value="50"></div>
    <div class="form-group"><label class="form-label">Throttle (ms)</label><input class="form-input" id="reg-thr" type="number" value="100"></div>
    <div class="form-group"><label class="form-label">Tags (comma-separated)</label><input class="form-input" id="reg-tags" placeholder="e.g. nlp,rag,internal"></div>
    <div class="modal-actions">
      <button class="btn btn-cyan" style="flex:1;padding:10px" onclick="submitRegister()">Register &amp; Generate Key</button>
      <button class="btn" onclick="closeModal('register')">Cancel</button>
    </div>
    <div id="reg-result" style="margin-top:12px;display:none"></div>
  </div>
</div>

<div class="modal-overlay" id="modal-rate-limit">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('rate-limit')">✕</button>
    <div class="modal-title">Update Rate Limit</div>
    <div id="rl-agent-display" style="margin-bottom:12px;color:var(--mute2);font-size:11px"></div>
    <input type="hidden" id="rl-aid">
    <div class="form-group"><label class="form-label">Rate Limit (req/min)</label><input class="form-input" id="rl-val" type="number"></div>
    <div class="form-group"><label class="form-label">Throttle (ms)</label><input class="form-input" id="rl-thr" type="number"></div>
    <div class="modal-actions">
      <button class="btn btn-gold" style="flex:1;padding:10px" onclick="submitRateLimit()">Update</button>
      <button class="btn" onclick="closeModal('rate-limit')">Cancel</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="modal-deploy">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('deploy')">✕</button>
    <div class="modal-title">Deploy New Version</div>
    <input type="hidden" id="deploy-aid">
    <div id="deploy-agent-display" style="margin-bottom:12px;color:var(--mute2);font-size:11px"></div>
    <div class="form-group"><label class="form-label">Version (leave blank to auto-increment)</label><input class="form-input" id="deploy-ver" placeholder="e.g. 2.0.0"></div>
    <div class="form-group"><label class="form-label">Target Environment</label>
      <select class="form-select" id="deploy-env"><option>UAT</option><option>PROD</option><option>DEV</option></select>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ok" style="flex:1;padding:10px" onclick="submitDeploy()">Deploy</button>
      <button class="btn" onclick="closeModal('deploy')">Cancel</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="modal-add-pending">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('add-pending')">✕</button>
    <div class="modal-title">Add Pending Registration Request</div>
    <div class="form-group"><label class="form-label">Agent Name</label><input class="form-input" id="pending-name" placeholder="e.g. Inventory Forecast Agent"></div>
    <div class="modal-actions">
      <button class="btn btn-warn" style="flex:1;padding:10px" onclick="submitAddPending()">Submit Request</button>
      <button class="btn" onclick="closeModal('add-pending')">Cancel</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="modal-sim-req">
  <div class="modal-overlay" id="modal-sim-req-inner" style="display:none"></div>
</div>

<script>
// ── state ─────────────────────────────────────────────────────────────────
let latestData = {};
let currentTab = 0;
let spinStep = 0;

function switchTab(n) {
  currentTab = n;
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active',i===n));
  document.querySelectorAll('#main .panel').forEach((p)=>{p.style.display='none'});
  const ids=['panel-registry','panel-gateway','panel-policy','panel-cost','panel-gov','panel-simulate','panel-rbac','panel-mcp','panel-a2a','panel-apitool','panel-vuln','panel-masking'];
  const el = document.getElementById(ids[n]);
  if(el) el.style.display='flex';
}

// ── SSE ───────────────────────────────────────────────────────────────────
const es = new EventSource('/api/stream');
es.onmessage = e => {
  const d = JSON.parse(e.data);
  latestData = d;
  updateAll(d);
};
es.onerror = () => {
  setTimeout(() => { window.location.reload(); }, 3000);
};

// Fetch state immediately on load — don't wait for first SSE tick
(async () => {
  try {
    const r = await fetch('/api/state');
    const d = await r.json();
    latestData = d;
    updateAll(d);
  } catch(e) { console.warn('Initial state fetch failed', e); }
})();

function updateAll(d) {
  document.getElementById('tick').textContent = d.tick;
  document.getElementById('run-id-val').textContent = d.run_id || d.tick;
  document.getElementById('live-time').textContent = new Date().toLocaleTimeString();
  updateRegistry(d);
  updateGateway(d);
  updatePolicy(d);
  updateCost(d);
  updateGovernance(d);
  updateEvents(d);
  updateKeyLookup(d);
  updateRbac(d);
  updateMcp(d);
  updateA2a(d);
  updateOpenApiGen(d);
  updateVulnPanel(d);
  updateMaskingPanel(d);
}

// ── REGISTRY ──────────────────────────────────────────────────────────────
function updateRegistry(d) {
  const reg = d.registry || {};
  let html = '';
  for (const [aid, a] of Object.entries(reg)) {
    const bkt = (d.rate_buckets||{})[aid] || 0;
    const rl  = a.rate_limit || 1;
    const bktPct = Math.round(bkt/rl*100);
    const bktClass = bktPct>50?'bar-ok':bktPct>20?'bar-warn':'bar-err';
    const healthClass = a.health>80?'bar-ok':a.health>50?'bar-warn':'bar-err';
    const versions = (a.versions||[]).map(v=>
      `<span class="version-pill ${v===a.version?'current':''}">${v}</span>`).join('');
    const tags=(a.tags||[]).map(t=>`<span class="tag">${t}</span>`).join('');
    const policies=(a.policies||[]).map(p=>`<span class="tag policy-tag">‣ ${p}</span>`).join('');

    html += `
    <div class="agent-card ${a.state==='ACTIVE'?'active-pulse':''}" id="card-${aid}">
      <div class="agent-header">
        <span class="pulse-dot ${a.state==='ACTIVE'?'pulse-ok':a.state==='BLOCKED'?'pulse-err':'pulse-warn'}"></span>
        <span class="agent-id" style="color:${a.colour}">${aid}</span>
        <span class="state-badge state-${a.state}">${a.state}</span>
        <span style="font-size:16px">${a.icon}</span>
      </div>
      <div class="agent-name">${a.name}</div>
      <div class="agent-desc">${a.description}</div>
      ${a.endpoint ? `<div style="font-size:10px;color:var(--mute2);margin-bottom:6px;word-break:break-all;padding:4px 6px;background:var(--bg);border-radius:2px;border:1px solid var(--border)"><span style="color:var(--mute)">endpoint: </span><span style="color:var(--teal)">${a.endpoint}</span></div>` : ''}
      <div class="meta-row">
        <div class="meta-item"><span class="meta-label">owner:</span><span class="meta-val">${a.owner}</span></div>
        <div class="meta-item"><span class="meta-label">env:</span><span class="meta-val" style="color:var(--cyan)">${a.env}</span></div>
        <div class="meta-item"><span class="meta-label">fw:</span><span class="meta-val">${a.framework}</span></div>
      </div>
      <div class="subkey-box">
        <span id="key-${aid}">${maskKey(a.sub_key)}</span>
        <div style="display:flex;gap:4px">
          <button class="copy-btn" onclick="copyKey('${aid}','${a.sub_key}')">📋 copy</button>
          <button class="copy-btn" onclick="revealKey('${aid}','${a.sub_key}')">👁</button>
        </div>
      </div>
      <div class="bar-row">
        <div class="bar-label"><span>Rate limit bucket: ${bkt}/${rl}/min</span><span>${bktPct}%</span></div>
        <div class="bar-track"><div class="bar-fill ${bktClass}" style="width:${bktPct}%"></div></div>
      </div>
      <div class="bar-row">
        <div class="bar-label"><span>Health</span><span>${a.health}%</span></div>
        <div class="bar-track"><div class="bar-fill ${healthClass}" style="width:${a.health}%"></div></div>
      </div>
      <div class="meta-row" style="margin-top:4px">
        <div class="meta-item"><span class="meta-label">throttle:</span><span class="meta-val">${a.throttle_ms}ms</span></div>
        <div class="meta-item"><span class="meta-label">runs:</span><span class="meta-val" style="color:var(--cyan)">${a.runs}</span></div>
        <div class="meta-item"><span class="meta-label">tok:</span><span class="meta-val" style="color:var(--purple)">${a.tok.toLocaleString()}</span></div>
        <div class="meta-item"><span class="meta-label">err:</span><span class="meta-val" style="color:var(--err)">${a.errors}</span></div>
      </div>
      <div class="tags">${tags}</div>
      <div class="tags">${policies}</div>
      <div style="margin:4px 0;font-size:10px;color:var(--mute2)">Versions: ${versions}</div>
      <div class="actions-grid" style="margin-top:8px">
        <button class="btn btn-warn" onclick="openRateModal('${aid}',${rl},${a.throttle_ms})">⚙ Rate Limit</button>
        <button class="btn btn-purple" onclick="openDeployModal('${aid}','${a.version}')">🚀 Deploy</button>
        <button class="btn btn-cyan" onclick="rotateKey('${aid}')">🔑 Rotate Key</button>
        <button class="btn btn-err" onclick="rollbackAgent('${aid}')">↺ Rollback</button>
        ${a.state==='ACTIVE'
          ?`<button class="btn btn-err" onclick="setAgentState('${aid}','BLOCKED')">🚫 Block</button>`
          :`<button class="btn btn-ok" onclick="setAgentState('${aid}','ACTIVE')">▶ Activate</button>`
        }
        <button class="btn" onclick="setAgentState('${aid}','RETIRED')">⊘ Retire</button>
      </div>
    </div>`;
  }
  document.getElementById('registry-cards').innerHTML = html;

  // Env distribution bar + agent count
  updateEnvDistBar(reg);
  const cnt = document.getElementById('reg-count');
  if(cnt) cnt.textContent = Object.keys(reg).length + ' agents';

  // Quick stats
  const qs = document.getElementById('quick-stats');
  if (qs) {
    const total = Object.keys(reg).length;
    const active = Object.values(reg).filter(a=>a.state==='ACTIVE').length;
    const totalRuns = Object.values(reg).reduce((s,a)=>s+a.runs,0);
    const totalTok = Object.values(reg).reduce((s,a)=>s+a.tok,0);
    qs.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:4px">
        <div class="stat"><span class="stat-val" style="color:var(--ok);font-size:16px">${active}</span><span class="stat-lbl">Active</span></div>
        <div class="stat"><span class="stat-val" style="color:var(--cyan);font-size:16px">${total}</span><span class="stat-lbl">Total</span></div>
        <div class="stat"><span class="stat-val" style="color:var(--gold);font-size:16px">${totalRuns}</span><span class="stat-lbl">Total Runs</span></div>
        <div class="stat"><span class="stat-val" style="color:var(--purple);font-size:16px">${(totalTok/1000).toFixed(1)}k</span><span class="stat-lbl">Tokens</span></div>
      </div>`;
  }

  // pending
  const pending = d.pending || [];
  if (pending.length === 0) {
    document.getElementById('pending-list').innerHTML = '<div style="color:var(--mute);font-size:10px">No pending registrations</div>';
  } else {
    document.getElementById('pending-list').innerHTML = pending.map(p=>`
      <div class="pending-card">
        <div class="pending-name">⏳ ${p.name}</div>
        <div class="pending-actions">
          <button class="btn btn-ok" style="padding:2px 8px" onclick="approvePending('${p.name}')">✓</button>
          <button class="btn btn-err" style="padding:2px 8px" onclick="rejectPending('${p.name}')">✕</button>
        </div>
      </div>`).join('');
  }
}

// ── GATEWAY ───────────────────────────────────────────────────────────────
function updateGateway(d) {
  const gw = d.gw || {};
  const cb = gw.circuit_open;
  const cbEl = document.getElementById('circuit-indicator');
  if (cbEl) {
    cbEl.className = 'circuit-indicator ' + (cb?'circuit-open':'circuit-closed');
    cbEl.innerHTML = `<span class="pulse-dot ${cb?'pulse-err':'pulse-ok'}"></span> Circuit Breaker: ${cb?'OPEN (blocking)':'CLOSED (healthy)'}  ×${gw.circuit_trips||0}`;
  }
  const sr = document.getElementById('gw-stats-row');
  if (sr) sr.innerHTML = `
    <div class="stat"><span class="stat-val" style="color:var(--cyan)">${gw.req_in||0}</span><span class="stat-lbl">REQUESTS</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--ok)">${gw.auth_ok||0}</span><span class="stat-lbl">AUTH OK</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--err)">${gw.auth_fail||0}</span><span class="stat-lbl">AUTH FAIL</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--warn)">${gw.rate_limited||0}</span><span class="stat-lbl">RATE LTD</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--mute2)">${(gw.p50||0).toFixed(0)}ms</span><span class="stat-lbl">P50</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--warn)">${(gw.p95||0).toFixed(0)}ms</span><span class="stat-lbl">P95</span></div>`;

  const counters = [
    ['Requests in',  gw.req_in||0,   5000, 'bar-cyan'],
    ['Auth OK',      gw.auth_ok||0,  5000, 'bar-ok'],
    ['Auth FAIL',    gw.auth_fail||0, 200, 'bar-err'],
    ['→ Policy Agt', gw.routed_pol||0,2000,'bar-purple'],
    ['→ Cost Agt',   gw.routed_cost||0,2000,'bar-lime'],
    ['Rate Limited', gw.rate_limited||0,200,'bar-warn'],
    ['Throttled',    gw.throttled||0, 100,'bar-warn'],
    ['401 Unauth',   gw.e401||0,     100, 'bar-err'],
    ['429 Limit',    gw.e429||0,     100, 'bar-warn'],
    ['502 Error',    gw.e502||0,      50, 'bar-err'],
  ];
  document.getElementById('gw-counters').innerHTML = counters.map(([l,v,mx,cl])=>{
    const pct=Math.min(100,Math.round(v/mx*100));
    return `<div class="bar-row">
      <div class="bar-label"><span>${l}</span><span>${v}</span></div>
      <div class="bar-track"><div class="bar-fill ${cl}" style="width:${pct}%"></div></div>
    </div>`;
  }).join('');

  const tbody = document.getElementById('pipeline-body');
  if (tbody) tbody.innerHTML = (d.pipeline||[]).map(r=>{
    const sc = r.s==='OK'?'s-ok':r.s==='401'||r.s==='502'?'s-err':'s-warn';
    const reg = (d.registry||{})[r.a]||{};
    return `<tr>
      <td class="${sc}">${r.s}</td>
      <td style="color:var(--teal);font-size:9px">${r.k}</td>
      <td style="color:${reg.colour||'#888'}">${r.a}</td>
      <td style="color:var(--mute2)">${r.act}</td>
      <td style="color:var(--mute)">${r.ms}</td>
    </tr>`;
  }).join('');

  const AUTH_STEPS = [
    'Receive request','Extract sub-key','Validate signature',
    'Check RBAC scope','Rate-limit check','Throttle check',
    'Route → Agent','Stream response'
  ];
  spinStep = Math.floor(Date.now()/600) % AUTH_STEPS.length;
  document.getElementById('auth-flow').innerHTML = AUTH_STEPS.map((s,i)=>{
    const done=i<spinStep; const active=i===spinStep;
    return `<div class="step-row">
      <span class="step-icon">${done?'✔':active?'⠿':'·'}</span>
      <span class="step-text ${done?'done':active?'active':''}">${i+1}. ${s}</span>
    </div>`;
  }).join('');
}

// ── POLICY AGENT ──────────────────────────────────────────────────────────
function updatePolicy(d) {
  const pol = d.pol || {}; const qv = pol.qvals||{};
  const maxQ = Math.max(...Object.values(qv),0);
  const r_ = pol.reward||0; const g = 0.92;
  const tgt = r_ + g*maxQ;
  const act = pol.action||'ALLOW';
  const acol = act==='ALLOW'?'var(--ok)':act==='BLOCK'?'var(--err)':'var(--warn)';
  const tcol = tgt>=0?'var(--ok)':'var(--err)';
  const eps = pol.epsilon||0.28;

  const el = (id,val) => { const e=document.getElementById(id); if(e) e.textContent=val; };
  el('pol-reward', (r_>=0?'+':'')+r_.toFixed(3));
  el('pol-maxq', maxQ.toFixed(3));
  el('pol-target', tgt.toFixed(3));
  el('pol-action', act);
  el('pol-epsilon', eps.toFixed(2));
  el('pol-exploit', Math.round((1-eps)*100));
  el('pol-explore', Math.round(eps*100));
  const ta = document.getElementById('pol-target');
  if (ta) ta.style.color=tcol;
  const aa = document.getElementById('pol-action');
  if (aa) aa.style.color=acol;

  document.getElementById('pol-qvals').innerHTML = Object.entries(qv).map(([k,v])=>{
    const pct = Math.max(0,Math.min(100,Math.round((v+1)/2*100)));
    const vc = v>0?'var(--ok)':v<-0.5?'var(--err)':'var(--mute2)';
    return `<div class="q-row">
      <span class="q-label">${k}</span>
      <div class="q-bar"><div class="q-fill" style="width:${pct}%"></div></div>
      <span class="q-val" style="color:${vc}">${(v>=0?'+':'')+v.toFixed(3)}</span>
    </div>`;
  }).join('');

  const steps = pol.steps||[];
  const cur = pol.step||0;
  document.getElementById('pol-trace').innerHTML = steps.map((s,i)=>`
    <div class="step-row">
      <span class="step-icon">${i<cur?'✔':i===cur?'⠿':'·'}</span>
      <span class="step-text ${i<cur?'done':i===cur?'active':''}">${s}</span>
    </div>`).join('');

  document.getElementById('pol-log').innerHTML = (d.pol_log||[]).map(e=>{
    const vc=e.v==='ALLOW'?'var(--ok)':'var(--err)';
    return `<div style="font-size:10px;padding:2px 0;border-bottom:1px solid var(--border);display:flex;gap:6px">
      <span style="color:${vc};width:44px;flex-shrink:0">${e.v}</span>
      <span style="color:var(--mute2)">${e.u}</span>
      <span style="color:var(--mute)">→ ${e.a}</span>
      <span style="color:var(--warn);margin-left:auto">risk=${e.r}</span>
    </div>`;
  }).join('');

  const vc = pol.verdict==='ALLOW'?'var(--ok)':pol.verdict==='BLOCK'?'var(--err)':'var(--warn)';
  document.getElementById('pol-stats').innerHTML = `
    <div class="stat"><span class="stat-val" style="color:${vc}">${pol.verdict||'—'}</span><span class="stat-lbl">VERDICT</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--warn)">${pol.risk||0}</span><span class="stat-lbl">RISK</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--ok)">${pol.allowed||0}</span><span class="stat-lbl">ALLOWED</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--err)">${pol.blocked||0}</span><span class="stat-lbl">BLOCKED</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--cyan)">${pol.runs||0}</span><span class="stat-lbl">RUNS</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--purple)">${(pol.tok||0).toLocaleString()}</span><span class="stat-lbl">TOKENS</span></div>`;
}

// ── COST ADVISOR ──────────────────────────────────────────────────────────
function updateCost(d) {
  const c = d.cost||{};
  const tot=c.total_usd||0; const bgt=c.budget||500; const pct=Math.min(100,(tot/bgt*100));
  const bcl=pct<70?'bar-ok':pct<90?'bar-warn':'bar-err';
  document.getElementById('cost-budget-bar').innerHTML = `
    <div class="bar-label"><span>${tot.toFixed(3)} / ${bgt}</span><span style="color:${pct<70?'var(--ok)':pct<90?'var(--warn)':'var(--err)'}">${pct.toFixed(1)}%</span></div>
    <div class="bar-track"><div class="bar-fill ${bcl}" style="width:${pct}%"></div></div>
    <div style="font-size:10px;color:var(--lime);margin-top:3px">💰 Saved: $${(c.saved_usd||0).toFixed(3)}</div>`;

  const by = c.by_model||{}; const maxS = Math.max(...Object.values(by),0.001);
  document.getElementById('cost-models').innerHTML = Object.entries(by).map(([m,s])=>{
    const p=Math.min(100,Math.round(s/maxS*100));
    return `<div class="bar-row">
      <div class="bar-label"><span>${m}</span><span style="color:var(--gold)">$${s.toFixed(4)}</span></div>
      <div class="bar-track"><div class="bar-fill bar-gold" style="width:${p}%"></div></div>
    </div>`;
  }).join('');

  const steps=c.steps||[]; const cur=c.step||0;
  document.getElementById('cost-trace').innerHTML = steps.map((s,i)=>`
    <div class="step-row">
      <span class="step-icon">${i<cur?'✔':i===cur?'⠿':'·'}</span>
      <span class="step-text ${i<cur?'done':i===cur?'active':''}">${s}</span>
    </div>`).join('');

  document.getElementById('cost-recs').innerHTML = (d.cost_recs||[]).map(r=>
    `<div style="font-size:10px;padding:3px 0;color:var(--lime);border-bottom:1px solid var(--border)">▸ ${r}</div>`
  ).join('');

  document.getElementById('cost-log').innerHTML = (d.cost_log||[]).map(e=>`
    <div style="font-size:10px;padding:2px 0;border-bottom:1px solid var(--border);display:flex;gap:6px">
      ${e.alert?`<span style="color:var(--warn)">⚠</span>`:'<span style="color:var(--mute)">·</span>'}
      <span style="color:var(--mute2)">${e.m}</span>
      <span style="color:var(--gold)">$${e.spend.toFixed(5)}</span>
      <span style="color:var(--mute)">${e.tok}tok</span>
    </div>`).join('');

  document.getElementById('cost-stats').innerHTML = `
    <div class="stat"><span class="stat-val" style="color:var(--gold)">$${tot.toFixed(3)}</span><span class="stat-lbl">TOTAL</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--lime)">$${(c.saved_usd||0).toFixed(3)}</span><span class="stat-lbl">SAVED</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--warn)">${c.alerts||0}</span><span class="stat-lbl">ALERTS</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--cyan)">${c.runs||0}</span><span class="stat-lbl">RUNS</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--purple)">${(c.tok||0).toLocaleString()}</span><span class="stat-lbl">TOKENS</span></div>`;
}

// ── GOVERNANCE ────────────────────────────────────────────────────────────
function updateGovernance(d) {
  const gov = d.gov||{};
  const kpis=[
    ['Total Runs',     gov.total_runs||0,  10000,'var(--cyan)'],
    ['Total Errors',   gov.total_errors||0, 300, 'var(--err)'],
    ['Tokens Used',    gov.total_tok||0, gov.tok_budget||5000000,'var(--purple)'],
    ['Policy Violatn', gov.policy_viol||0,  100, 'var(--warn)'],
    ['GDPR Flags',     gov.gdpr_flags||0,   50,  'var(--rose,#fb7185)'],
    ['Deployments',    gov.deploys||0,      50,  'var(--ok)'],
    ['Rollbacks',      gov.rollbacks||0,    20,  'var(--orange)'],
  ];
  document.getElementById('gov-kpis').innerHTML = kpis.map(([l,v,mx,col])=>{
    const pct=Math.min(100,Math.round(v/mx*100));
    return `<div class="bar-row">
      <div class="bar-label"><span>${l}</span><span style="color:${col}">${typeof v==='number'&&v>9999?v.toLocaleString():v}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${col}"></div></div>
    </div>`;
  }).join('');

  // sparklines
  drawSpark('lat-spark', d.lat_hist||[], 'var(--cyan)', 40);
  drawSpark('err-spark', d.err_hist||[], 'var(--err)', 30);

  const lats=(d.lat_hist||[]).filter(x=>x>0).sort((a,b)=>a-b);
  const p50=lats[Math.floor(lats.length*.5)]||0;
  const p95=lats[Math.floor(lats.length*.95)]||0;
  document.getElementById('lat-vals').textContent=`p50: ${p50.toFixed(0)}ms  ·  p95: ${p95.toFixed(0)}ms`;

  document.getElementById('audit-log').innerHTML=(d.audit_log||[]).map(e=>
    `<div class="audit-row"><span class="audit-ts">${e.ts}</span>${e.msg}</div>`
  ).join('');

  document.getElementById('pod-grid').innerHTML=(d.pods||[]).map(p=>{
    const cpuPct=p.cpu||0; const memPct=p.mem||0;
    const scol=p.status==='Running'?'var(--ok)':'var(--err)';
    return `<div class="pod-card">
      <div class="pod-id">${p.id}</div>
      <div class="pod-agent" style="color:var(--cyan)">${p.agent}</div>
      <div style="font-size:9px;color:var(--mute2)">${p.env} · ×${p.rep} replicas · <span style="color:${scol}">${p.status}</span></div>
      <div class="pod-bars">
        <div class="bar-row"><div class="bar-label"><span>CPU</span><span>${cpuPct}%</span></div><div class="bar-track"><div class="bar-fill bar-cyan" style="width:${cpuPct}%"></div></div></div>
        <div class="bar-row"><div class="bar-label"><span>MEM</span><span>${memPct}%</span></div><div class="bar-track"><div class="bar-fill bar-purple" style="width:${memPct}%"></div></div></div>
      </div>
    </div>`;
  }).join('');
}

// ── EVENTS ────────────────────────────────────────────────────────────────
function updateEvents(d) {
  document.getElementById('events-body').innerHTML=(d.events||[]).map(e=>`
    <div class="event-row">
      <span class="event-ts">${e.ts}</span>
      <span class="ev-${e.level||'info'}">${e.msg}</span>
    </div>`).join('');
}

// ── KEY LOOKUP ────────────────────────────────────────────────────────────
function updateKeyLookup(d) {
  const el = document.getElementById('key-lookup');
  if (!el) return;
  el.innerHTML = Object.entries(d.registry||{}).map(([aid,a])=>`
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:8px;margin-bottom:6px">
      <div style="color:${a.colour};font-family:'Orbitron',monospace;font-size:10px;margin-bottom:4px">${aid} — ${a.name}</div>
      <div style="font-size:10px;color:var(--mute2);margin-bottom:4px">Your subscription key:</div>
      <div class="subkey-box">
        <span id="sim-key-${aid}" style="font-size:10px">${maskKey(a.sub_key)}</span>
        <div style="display:flex;gap:4px">
          <button class="copy-btn" onclick="revealKey('${aid}','${a.sub_key}','sim-key-${aid}')">👁 reveal</button>
          <button class="copy-btn" onclick="copyAndFill('${aid}','${a.sub_key}')">📋 use</button>
        </div>
      </div>
    </div>`).join('');
}

// ── SPARKLINE CANVAS ──────────────────────────────────────────────────────
function drawSpark(canvasId, data, colour, height) {
  const c = document.getElementById(canvasId);
  if (!c) return;
  const ctx = c.getContext('2d');
  const w = c.width, h = height||40;
  ctx.clearRect(0,0,w,h);
  ctx.fillStyle='rgba(8,12,15,0.4)';
  ctx.fillRect(0,0,w,h);
  if (!data||data.length<2) return;
  const mx=Math.max(...data,1);
  ctx.beginPath();
  ctx.strokeStyle=colour||'#22d3ee';
  ctx.lineWidth=1.5;
  data.forEach((v,i)=>{
    const x=i/(data.length-1)*w;
    const y=h-(v/mx*(h-4))-2;
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  });
  ctx.stroke();
  // fill
  ctx.lineTo(w,h); ctx.lineTo(0,h); ctx.closePath();
  ctx.fillStyle=colour?.replace(')',',0.1)')||'rgba(34,211,238,0.1)';
  ctx.fill();
}

// ── HELPERS ───────────────────────────────────────────────────────────────
function maskKey(k) { return k.slice(0,7)+'…'+k.slice(-5); }

function copyKey(aid, key) {
  navigator.clipboard.writeText(key);
  toast(`Key copied for ${aid}`, 'ok');
}

function revealKey(aid, key, elemId) {
  const id = elemId || `key-${aid}`;
  const el = document.getElementById(id);
  if (el) {
    const showing = el.textContent === key;
    el.textContent = showing ? maskKey(key) : key;
  }
}

function copyAndFill(aid, key) {
  document.getElementById('sim-sub-key').value = key;
  document.getElementById('sim-agent-id').value = aid;
  switchTab(5);
  toast(`Key filled in Simulate Request panel`, 'ok');
}

function toast(msg, level='ok') {
  const t = document.getElementById('toast');
  const div = document.createElement('div');
  div.className = `toast-item toast-${level}`;
  div.textContent = msg;
  t.prepend(div);
  setTimeout(()=>div.remove(), 4000);
}

async function api(url, method='POST', body=null) {
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(url, opts);
  return r.json();
}

// ── MANAGEMENT ACTIONS ────────────────────────────────────────────────────
function openModal(name) {
  document.getElementById(`modal-${name}`).classList.add('open');
}
function closeModal(name) {
  document.getElementById(`modal-${name}`).classList.remove('open');
}

function openRateModal(aid, rl, thr) {
  document.getElementById('rl-aid').value = aid;
  document.getElementById('rl-agent-display').textContent = `Agent: ${aid}`;
  document.getElementById('rl-val').value = rl;
  document.getElementById('rl-thr').value = thr;
  openModal('rate-limit');
}

function openDeployModal(aid, ver) {
  document.getElementById('deploy-aid').value = aid;
  document.getElementById('deploy-agent-display').textContent = `Agent: ${aid}  Current: v${ver}`;
  document.getElementById('deploy-ver').value = '';
  openModal('deploy');
}

async function submitRegister() {
  const name=document.getElementById('reg-name').value.trim();
  if (!name) { toast('Please enter an agent name','err'); return; }
  const tags=document.getElementById('reg-tags').value.split(',').map(t=>t.trim()).filter(Boolean);
  const endpoint=document.getElementById('reg-endpoint').value.trim();
  const res = await api('/api/action/register', 'POST', {
    name, description:document.getElementById('reg-desc').value,
    owner:document.getElementById('reg-owner').value,
    framework:document.getElementById('reg-framework').value,
    env:document.getElementById('reg-env').value,
    rate_limit:document.getElementById('reg-rl').value,
    throttle_ms:document.getElementById('reg-thr').value, tags,
    endpoint,
  });
  if (res.ok) {
    const el=document.getElementById('reg-result');
    el.style.display='block';
    el.innerHTML=`<div style="background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.3);border-radius:4px;padding:10px">
      <div style="color:var(--ok);margin-bottom:6px">✓ Agent registered: <b>${res.agent_id}</b></div>
      <div style="font-size:10px;color:var(--mute2);margin-bottom:4px">Subscription Key:</div>
      <div style="background:var(--bg);padding:6px;border-radius:2px;color:var(--teal);font-size:11px;word-break:break-all">${res.sub_key}</div>
      <button class="btn btn-cyan" style="margin-top:8px;width:100%" onclick="navigator.clipboard.writeText('${res.sub_key}');toast('Key copied','ok')">📋 Copy Key</button>
    </div>`;
    toast(`Agent ${res.agent_id} registered!`, 'ok');
  }
}

async function rotateKey(aid) {
  const res = await api(`/api/action/rotate_key/${aid}`);
  if (res.ok) {
    toast(`Sub-key rotated for ${aid}: ${res.masked}`, 'warn');
  }
}

async function submitRateLimit() {
  const aid=document.getElementById('rl-aid').value;
  const res = await api(`/api/action/set_rate_limit/${aid}`, 'POST', {
    rate_limit:document.getElementById('rl-val').value,
    throttle_ms:document.getElementById('rl-thr').value,
  });
  if (res.ok) { toast(`Rate limit updated for ${aid}`, 'ok'); closeModal('rate-limit'); }
}

async function submitDeploy() {
  const aid=document.getElementById('deploy-aid').value;
  const res = await api(`/api/action/deploy_version/${aid}`, 'POST', {
    version:document.getElementById('deploy-ver').value,
    env:document.getElementById('deploy-env').value,
  });
  if (res.ok) { toast(`Deployed ${aid} v${res.version} → ${res.env}`, 'ok'); closeModal('deploy'); }
}

async function rollbackAgent(aid) {
  const res = await api(`/api/action/rollback/${aid}`);
  if (res.ok) toast(`Rolled back ${aid}: ${res.rolled_back_from} → ${res.current}`, 'warn');
  else toast(`Rollback failed: ${res.error}`, 'err');
}

async function setAgentState(aid, st) {
  const res = await api(`/api/action/set_state/${aid}`, 'POST', {state:st});
  if (res.ok) toast(`${aid} → ${st}`, st==='ACTIVE'?'ok':'warn');
}

async function approvePending(name) {
  const res = await api(`/api/action/approve_pending/${encodeURIComponent(name)}`);
  if (res.ok) toast(`Approved: ${name}`, 'ok');
}
async function rejectPending(name) {
  const res = await api(`/api/action/reject_pending/${encodeURIComponent(name)}`);
  if (res.ok) toast(`Rejected: ${name}`, 'err');
}

async function submitAddPending() {
  const name=document.getElementById('pending-name').value.trim();
  if (!name) return;
  const res = await api('/api/action/add_pending', 'POST', {name});
  if (res.ok) { toast(`Pending request added: ${name}`, 'warn'); closeModal('add-pending'); }
}

async function runSimRequest() {
  const aid=document.getElementById('sim-agent-id').value;
  const key=document.getElementById('sim-sub-key').value.trim();
  const user=document.getElementById('sim-user').value.trim()||'admin';
  const action=document.getElementById('sim-action').value;

  if (!key) { toast('Enter your subscription key first','err'); return; }

  // Animate flow steps
  const steps = document.querySelectorAll('.flow-step');
  steps.forEach(s=>s.style.color='var(--mute2)');

  for (let i=0;i<steps.length;i++) {
    await new Promise(r=>setTimeout(r,200));
    steps[i].style.color='var(--gold)';
    steps[i].style.fontWeight='bold';
  }

  const res = await api('/api/action/simulate_request', 'POST', {
    agent_id:aid, sub_key:key, user, action
  });

  const el = document.getElementById('sim-result');
  el.style.display='block';
  if (res.ok) {
    el.innerHTML=`<div style="background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.3);border-radius:4px;padding:10px;font-size:11px">
      <div style="color:var(--ok);font-size:13px;margin-bottom:8px">✓ REQUEST SUCCESSFUL</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px">
        <div><span style="color:var(--mute2)">Status:</span> <span style="color:var(--ok)">${res.status}</span></div>
        <div><span style="color:var(--mute2)">Verdict:</span> <span style="color:${res.verdict==='ALLOW'?'var(--ok)':'var(--err)'}">${res.verdict}</span></div>
        <div><span style="color:var(--mute2)">Risk:</span> <span style="color:var(--warn)">${res.risk}</span></div>
        <div><span style="color:var(--mute2)">Latency:</span> <span style="color:var(--cyan)">${res.latency_ms}ms</span></div>
        <div><span style="color:var(--mute2)">Tokens:</span> <span style="color:var(--purple)">${res.tokens_used}</span></div>
        <div><span style="color:var(--mute2)">Agent:</span> <span style="color:var(--teal)">${aid}</span></div>
      </div>
    </div>`;
    steps.forEach(s=>{s.style.color='var(--ok)';s.style.fontWeight='normal'});
    toast(`Request OK — ${aid}  ${res.latency_ms}ms`, 'ok');
  } else {
    el.innerHTML=`<div style="background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);border-radius:4px;padding:10px;font-size:11px">
      <div style="color:var(--err);font-size:13px;margin-bottom:6px">✗ REQUEST FAILED</div>
      <div style="color:var(--err)">Status: ${res.status} — ${res.error}</div>
    </div>`;
    steps.forEach(s=>{s.style.color='var(--mute2)';s.style.fontWeight='normal'});
    toast(`Request failed: ${res.error}`, 'err');
  }
}

// Close modals on overlay click
document.querySelectorAll('.modal-overlay').forEach(o=>{
  o.addEventListener('click', e=>{ if(e.target===o) o.classList.remove('open'); });
});


// ── RBAC ─────────────────────────────────────────────────────────────────────
function updateRbac(d) {
  const rbac = d.rbac||{};
  // Roles
  const roles = rbac.roles||{};
  const roleColours = {admin:'var(--err)',approver:'var(--orange)',developer:'var(--cyan)',viewer:'var(--mute2)',svc_acct:'var(--purple)'};
  document.getElementById('rbac-roles').innerHTML = Object.entries(roles).map(([role,info])=>`
    <div class="rbac-role-card">
      <div style="color:${roleColours[role]||'var(--text)'};font-weight:bold;font-size:11px;margin-bottom:4px">${role.toUpperCase()}</div>
      <div>${(info.permissions||[]).map(p=>`<span class="rbac-perm">${p}</span>`).join('')}</div>
    </div>`).join('');
  // Users
  const users = rbac.users||[];
  document.getElementById('rbac-users').innerHTML = users.map(u=>{
    const rc = roleColours[u.role]||'var(--text)';
    return `<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid var(--border);font-size:11px">
      <span style="color:var(--cyan)">${u.name}</span>
      <span style="color:${rc};font-size:9px;padding:1px 6px;border:1px solid ${rc};border-radius:2px">${u.role}</span>
    </div>`;
  }).join('');
  // Counters
  const el=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
  el('rbac-check-count', rbac.check_count||0);
  el('rbac-allow-count', rbac.allow_count||0);
  el('rbac-block-count', rbac.block_count||0);
  // Log
  document.getElementById('rbac-log').innerHTML = (rbac.demo_log||[]).map(e=>{
    const vc=e.verdict==='ALLOW'?'var(--ok)':'var(--err)';
    const rc=e.risk>84?'var(--err)':e.risk>69?'var(--orange)':e.risk>29?'var(--warn)':'var(--ok)';
    return `<div style="font-size:10px;padding:3px 0;border-bottom:1px solid var(--border);display:flex;gap:6px;flex-wrap:wrap">
      <span style="color:var(--mute);flex-shrink:0">${e.ts}</span>
      <span style="color:${vc};font-weight:bold;width:44px;flex-shrink:0">${e.verdict}</span>
      <span style="color:var(--cyan)">${e.user}</span>
      <span style="color:var(--mute2)">→ ${e.action}</span>
      <span style="color:${rc};margin-left:auto">risk=${e.risk}</span>
    </div>`;
  }).join('');
}

async function runRbacCheck() {
  const user_id  = document.getElementById('rbac-user-sel').value;
  const action   = document.getElementById('rbac-action-sel').value;
  const agent_id = document.getElementById('rbac-agent-sel').value;
  const res = await api('/api/rbac/check','POST',{user_id,action,agent_id});
  const el  = document.getElementById('rbac-result'); el.style.display='block';
  const vc  = res.verdict==='ALLOW'?'var(--ok)':'var(--err)';
  const rc  = res.risk>84?'var(--err)':res.risk>69?'var(--orange)':res.risk>29?'var(--warn)':'var(--ok)';
  const routeLabel = {'allow_direct':'ALLOW DIRECT','log_alert':'ALLOW + ALERT','escalate':'ESCALATE','mandatory_approval':'MANDATORY APPROVAL'}[res.routing]||res.routing;
  el.innerHTML=`<div style="background:${res.verdict==='ALLOW'?'rgba(74,222,128,.1)':'rgba(248,113,113,.1)'};border:1px solid ${vc};border-radius:4px;padding:10px;font-size:11px">
    <div style="color:${vc};font-size:15px;font-weight:bold;margin-bottom:8px">${res.verdict==='ALLOW'?'✓ ALLOWED':'✗ BLOCKED'}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px">
      <div><span style="color:var(--mute2)">Role:</span> <span style="color:var(--cyan)">${res.role||'—'}</span></div>
      <div><span style="color:var(--mute2)">Risk:</span> <span style="color:${rc}">${res.risk}</span></div>
      <div style="grid-column:1/-1"><span style="color:var(--mute2)">Routing:</span> <span style="color:${rc};font-weight:bold"> ${routeLabel}</span></div>
      <div style="grid-column:1/-1"><span style="color:var(--mute2)">Permissions:</span> ${(res.permissions||[]).map(p=>`<span style="font-size:9px;padding:1px 4px;background:rgba(96,165,250,.1);color:var(--blue);border-radius:2px;margin:1px;display:inline-block">${p}</span>`).join('')}</div>
    </div>
  </div>`;
  toast(`RBAC ${res.verdict}: ${action} — risk=${res.risk} → ${routeLabel}`, res.verdict==='ALLOW'?'ok':'err');
}

// ── MCP ───────────────────────────────────────────────────────────────────────
function updateMcp(d) {
  const mcp = d.mcp||{};
  const srvs = mcp.servers||{};
  document.getElementById('mcp-servers').innerHTML = Object.entries(srvs).map(([id,s])=>{
    const registered = s.status==='REGISTERED';
    const sc = registered?'var(--ok)':'var(--err)';
    return `<div class="mcp-server-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
        <span style="font-family:'Orbitron',monospace;font-size:9px;color:var(--teal)">${id}</span>
        <span style="font-size:9px;padding:1px 6px;border:1px solid ${sc};color:${sc};border-radius:2px">${s.status}</span>
      </div>
      <div style="font-size:11px;color:var(--text2);margin-bottom:3px">${s.name}</div>
      <div style="font-size:10px;color:var(--mute2);margin-bottom:4px">${s.endpoint}</div>
      <div style="font-size:10px;color:var(--mute2)">
        Calls: <span style="color:var(--cyan)">${s.calls}</span> &nbsp;
        Blocked: <span style="color:var(--err)">${s.blocked}</span> &nbsp;
        Scope: <span style="color:var(--purple)">${s.allowed_agents.length?s.allowed_agents.join(', '):'none'}</span>
      </div>
    </div>`;
  }).join('');
  const el=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
  el('mcp-total', mcp.total_calls||0);
  el('mcp-blocked', mcp.blocked_calls||0);
  el('mcp-inject-count', mcp.injections_blocked||0);
  document.getElementById('mcp-call-log').innerHTML = (mcp.call_log||[]).map(e=>{
    const ok=e.status==='OK'; const vc=ok?'var(--ok)':'var(--err)';
    return `<div style="font-size:10px;padding:3px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--mute)">${e.ts}</span>
      <span style="color:${vc};font-weight:bold;margin:0 4px">${e.status}</span>
      <span style="color:var(--teal)">${e.agent}</span>
      <span style="color:var(--mute2)"> → ${e.server}.${e.tool}</span>
      ${ok?'<span style="color:var(--ok);margin-left:4px;font-size:9px">HMAC✓ schema✓</span>':''}
    </div>`;
  }).join('');
}

function updateMcpTools() {
  const server = document.getElementById('mcp-server-sel').value;
  const toolMap = {
    'MCP-AUDIT-001':  ['read_audit_log','query_violations','get_user_history'],
    'MCP-FINOPS-002': ['get_token_usage','get_model_pricing','update_ledger'],
    'MCP-BILLING-003':['get_invoice','charge_account'],
    'MCP-UNKNOWN-EXT':['unknown_tool'],
  };
  const sel = document.getElementById('mcp-tool-sel');
  sel.innerHTML = (toolMap[server]||['unknown']).map(t=>`<option>${t}</option>`).join('');
}

async function runMcpCall() {
  const agent_id  = document.getElementById('mcp-agent-sel').value;
  const server_id = document.getElementById('mcp-server-sel').value;
  const tool      = document.getElementById('mcp-tool-sel').value;
  const inject    = document.getElementById('mcp-inject').checked;
  const res = await api('/api/mcp/call','POST',{agent_id,server_id,tool,inject_payload:inject});
  const el=document.getElementById('mcp-result'); el.style.display='block';
  const ok=res.status==='OK'; const vc=ok?'var(--ok)':'var(--err)';
  el.innerHTML=`<div style="background:${ok?'rgba(74,222,128,.08)':'rgba(248,113,113,.08)'};border:1px solid ${vc};border-radius:4px;padding:10px;font-size:11px">
    <div style="color:${vc};font-size:13px;font-weight:bold;margin-bottom:6px">${ok?'✓ MCP CALL ALLOWED':'✗ MCP CALL BLOCKED'}</div>
    ${ok?`<div style="color:var(--mute2)">HMAC signed ✓ &nbsp; Schema validated ✓ &nbsp; Audit logged ✓</div>
          <div style="color:var(--text2);margin-top:4px">${res.result}</div>`
        :`<div style="color:var(--err)">Reason: ${res.reason}</div>
          <div style="color:var(--mute2);margin-top:4px">Check failed: ${res.check}</div>`}
  </div>`;
  toast(`MCP ${res.status}: ${agent_id} → ${server_id}.${tool}`, ok?'ok':'err');
}

// ── A2A ───────────────────────────────────────────────────────────────────────
let a2aActive = false;

function updateA2a(d) {
  const a2a = d.a2a||{};
  // Topology
  const agents = a2a.agents||{};
  const topo = Object.entries(agents).map(([id,a])=>{
    const canCall = a.can_call||[];
    return `<div class="topology-row">
      <span class="topo-agent" style="background:rgba(0,0,0,.3);border:1px solid ${a.colour||'#666'};color:${a.colour||'#fff'}">${id}</span>
      ${canCall.length?`<span class="topo-arrow">──▶</span><span style="font-size:10px;color:var(--mute2)">${canCall.join(', ')}</span>`
                      :`<span class="topo-blocked">✗</span><span style="font-size:10px;color:var(--mute2)">no delegation scope</span>`}
    </div>`;
  }).join('');
  document.getElementById('a2a-topology').innerHTML = topo;
  // Stats
  const el=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
  el('a2a-total',   a2a.total_flows||0);
  el('a2a-blocked', a2a.blocked_flows||0);
  el('a2a-tokens',  a2a.tokens_issued||0);
  // Call log
  document.getElementById('a2a-call-log').innerHTML = (a2a.call_log||[]).map(e=>{
    const ok=e.status==='OK'; const vc=ok?'var(--ok)':'var(--err)';
    return `<div style="font-size:10px;padding:3px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--mute)">${e.ts}</span>
      <span style="color:${vc};font-weight:bold;margin:0 4px">${e.status}</span>
      <span style="color:var(--gold)">${e.caller}</span>
      <span style="color:var(--mute2)">→ ${e.callee}</span>
      ${ok?`<span style="color:var(--purple);margin-left:4px;font-size:9px">${e.token} ttl=${e.ttl}</span>`:''}
    </div>`;
  }).join('');
  // Flow steps
  const steps = (d.a2a||{}).flow_steps||[];
  const curStep = (d.a2a||{}).flow_step||0;
  document.getElementById('a2a-flow-steps').innerHTML = steps.map((s,i)=>{
    const cls = i<curStep?'done':i===curStep&&a2aActive?'active':'pending';
    const typeIcon = {request:'📨',verify:'🔍',rbac:'🔐',token:'🎫',dispatch:'📤',exec:'⚙',response:'📬',audit:'📋'}[s.type]||'·';
    return `<div class="flow-step-item ${cls}">${typeIcon} ${s.from} → ${s.to}: ${s.label}</div>`;
  }).join('');
}

async function runA2AFlow() {
  const caller = document.getElementById('a2a-caller-sel').value;
  const callee = document.getElementById('a2a-callee-sel').value;
  const task   = document.getElementById('a2a-task-sel').value;
  const attack = document.getElementById('a2a-attack').checked;
  const res = await api('/api/a2a/start_flow','POST',{caller,callee,task,attack});
  const el=document.getElementById('a2a-result'); el.style.display='block';
  const ok=res.status==='OK'; const vc=ok?'var(--ok)':'var(--err)';
  if(ok) {
    a2aActive=true;
    document.getElementById('a2a-next-btn').disabled=false;
    document.getElementById('a2a-token-info').innerHTML=`
      <div style="color:var(--purple)">Token: ${res.token}</div>
      <div style="color:var(--mute2)">TTL: ${res.ttl_minutes} min &nbsp; Scope: ${callee} only</div>
      <div style="color:var(--ok);margin-top:4px">Checks: ${(res.checks_passed||[]).join(' · ')}</div>`;
  } else {
    a2aActive=false;
    document.getElementById('a2a-next-btn').disabled=true;
    document.getElementById('a2a-token-info').innerHTML=`<span style="color:var(--err)">Flow blocked — no token issued</span>`;
  }
  el.innerHTML=`<div style="background:${ok?'rgba(74,222,128,.08)':'rgba(248,113,113,.08)'};border:1px solid ${vc};border-radius:4px;padding:10px;font-size:11px">
    <div style="color:${vc};font-size:13px;font-weight:bold;margin-bottom:6px">${ok?'✓ A2A FLOW AUTHORISED':'✗ A2A FLOW BLOCKED'}</div>
    ${ok?`<div style="color:var(--mute2)">${caller} → ${callee}</div>
          <div style="color:var(--purple);margin-top:4px">Token: ${(res.token||'').slice(0,16)}…  TTL=10min</div>`
        :`<div style="color:var(--err)">${res.reason}</div>
          <div style="color:var(--mute2)">Check: ${res.check||'delegation_scope'}</div>`}
  </div>`;
  toast(`A2A ${res.status}: ${caller} → ${callee} ${task}`, ok?'ok':'err');
}

async function stepA2AFlow() {
  const res = await api('/api/a2a/flow_step','POST',{});
  if(res.complete) {
    a2aActive=false;
    document.getElementById('a2a-next-btn').disabled=true;
    toast('A2A flow complete — both hops audit-logged','ok');
  }
}

// ── Registry Search & Filter ──────────────────────────────────────────────────
function filterRegistry() {
  const q   = (document.getElementById('reg-search')?.value || '').toLowerCase().trim();
  const env = document.getElementById('reg-env-filter')?.value   || 'ALL';
  const st  = document.getElementById('reg-state-filter')?.value || 'ALL';
  const fw  = document.getElementById('reg-fw-filter')?.value    || 'ALL';
  const reg = latestData.registry || {};
  let visible = 0;
  const total = Object.keys(reg).length;

  // Query all rendered cards directly from DOM (avoids stale reference issues)
  document.querySelectorAll('.agent-card').forEach(card => {
    const aid = card.id.replace('card-', '');
    const a   = reg[aid];
    if (!a) { card.style.display = 'none'; return; }

    const matchQ   = !q || [aid, a.name||'', a.description||'', ...(a.tags||[])].some(v => (v||'').toLowerCase().includes(q));
    const matchEnv = env === 'ALL' || a.env === env;
    const matchSt  = st  === 'ALL' || a.state === st;
    const matchFw  = fw  === 'ALL' || a.framework === fw;
    const show     = matchQ && matchEnv && matchSt && matchFw;

    card.style.display = show ? 'block' : 'none';
    if (show) visible++;
  });

  const cnt = document.getElementById('reg-count');
  if (cnt) cnt.textContent = `${visible} of ${total} agents`;
}

function updateEnvDistBar(reg) {
  const bar=document.getElementById('env-dist-bar');
  const lbl=document.getElementById('env-dist-labels');
  if(!bar||!lbl) return;
  const counts={DEV:0,UAT:0,PROD:0,OTHER:0};
  Object.values(reg).forEach(a=>{
    const k=counts[a.env]!==undefined?a.env:'OTHER';
    counts[k]++;
  });
  const total=Object.values(counts).reduce((s,v)=>s+v,0)||1;
  const cols={DEV:'#60a5fa',UAT:'#fbbf24',PROD:'#4ade80',OTHER:'#6b8090'};
  bar.innerHTML=Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>
    `<div style="flex:${v};background:${cols[k]};transition:flex .4s" title="${k}: ${v}"></div>`).join('');
  lbl.innerHTML=Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>
    `<span style="color:${cols[k]}">■ ${k}: ${v}</span>`).join('');
}

// ── OpenAPI → Tool Generator UI ───────────────────────────────────────────────
function updateOpenApiGen(d) {
  const gen = d.openapi_gen||{};
  const el=document.getElementById('oapi-total');
  if(el) el.textContent=gen.total_generated||0;
  const list=document.getElementById('oapi-tools-list');
  if(!list) return;
  const tools=(gen.generated||[]).slice(0,20);
  if(!tools.length){list.innerHTML='<div style="color:var(--mute);font-size:10px">No tools generated yet — select an API and click Generate.</div>';return;}
  list.innerHTML=tools.map(t=>`
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:10px;margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
        <span style="font-family:'Orbitron',monospace;font-size:9px;color:var(--gold)">${t.tool_id}</span>
        <span style="font-size:9px;padding:1px 6px;border:1px solid var(--ok);color:var(--ok);border-radius:2px">REGISTERED</span>
      </div>
      <div style="font-size:12px;font-weight:bold;color:var(--text);margin-bottom:2px">${t.name}</div>
      <div style="font-size:10px;color:var(--mute2);margin-bottom:4px">${t.description}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:10px">
        <div><span style="color:var(--mute2)">Method:</span> <span style="color:var(--cyan)">${t.http_method}</span> <span style="color:var(--mute2)">${t.path}</span></div>
        <div><span style="color:var(--mute2)">Source:</span> <span style="color:var(--text2)">${t.source_api}</span></div>
        <div><span style="color:var(--mute2)">Scope:</span> <span style="color:var(--purple)">${t.agent_scope}</span></div>
        <div><span style="color:var(--mute2)">Auth:</span> <span style="color:var(--lime)">Bearer ✓</span></div>
      </div>
      <div style="margin-top:6px;font-size:9px;color:var(--mute2);word-break:break-all">${t.mcp_endpoint}</div>
      <div style="margin-top:4px;font-size:9px">
        <span style="color:var(--ok)">Schema validated ✓</span> &nbsp;
        <span style="color:var(--ok)">I/O contract ✓</span> &nbsp;
        <span style="color:var(--ok)">Governance hooks ✓</span>
      </div>
    </div>`).join('');
}

async function runOpenApiGen() {
  const api_name  = document.getElementById('oapi-api-sel').value;
  const agent_id  = document.getElementById('oapi-agent-sel').value;
  const res = await api('/api/openapi/generate_tool','POST',{api_name,agent_id});
  const el=document.getElementById('oapi-result'); el.style.display='block';
  if(res.ok){
    el.innerHTML=`<div style="background:rgba(74,222,128,.08);border:1px solid var(--ok);border-radius:4px;padding:10px;font-size:11px">
      <div style="color:var(--ok);font-weight:bold;margin-bottom:4px">✓ Generated ${res.count} MCP tool definition(s)</div>
      <div style="color:var(--mute2)">Source: ${res.api_name}</div>
      <div style="color:var(--gold);margin-top:4px">Tools registered → see list on the right</div>
    </div>`;
    toast(`Generated ${res.count} MCP tools from ${api_name}`,'ok');
  }
}

// ── Vulnerability Scanner UI ──────────────────────────────────────────────────
function updateVulnPanel(d) {
  const vuln=d.vuln||{};
  const stats=document.getElementById('vuln-stats');
  if(stats) stats.innerHTML=`
    <div style="color:var(--mute2)">Total scans run: <span style="color:var(--orange)">${vuln.total_scans||0}</span></div>
    <div style="color:var(--mute2)">Total vulns found: <span style="color:var(--err)">${vuln.total_vulns||0}</span></div>
    <div style="color:var(--mute2)">Last scanned: <span style="color:var(--cyan)">${vuln.last_scan_agent||'—'}</span></div>`;
  const hist=document.getElementById('vuln-history');
  if(!hist) return;
  const scans=vuln.scans||[];
  if(!scans.length){hist.innerHTML='<div style="color:var(--mute);font-size:10px">No scans run yet.</div>';return;}
  hist.innerHTML=scans.map(s=>{
    const pass=s.status==='PASS';
    const sc=pass?'var(--ok)':'var(--err)';
    const vulnRows=(s.vulnerabilities||[]).map(v=>{
      const sevCol={CRITICAL:'var(--err)',HIGH:'var(--orange)',MEDIUM:'var(--warn)',LOW:'var(--teal)'}[v.severity]||'var(--mute2)';
      return `<div style="display:grid;grid-template-columns:90px 80px 1fr;gap:6px;font-size:10px;padding:3px 0;border-bottom:1px solid var(--border)">
        <span style="color:var(--mute2)">${v.id}</span>
        <span style="color:${sevCol};font-weight:bold">${v.severity}</span>
        <span style="color:var(--text2)">${v.pkg} — ${v.desc}</span>
      </div>`;
    }).join('');
    return `<div style="background:var(--bg);border:1px solid ${s.status==='FAIL'?'rgba(248,113,113,.3)':'rgba(74,222,128,.2)'};border-radius:3px;padding:10px;margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <div>
          <span style="font-family:'Orbitron',monospace;font-size:9px;color:var(--mute2)">${s.scan_id}</span>
          <span style="font-size:12px;font-weight:bold;color:var(--text);margin-left:8px">${s.agent_name}</span>
          <span style="font-size:10px;color:var(--mute2);margin-left:6px">${s.agent_id}</span>
        </div>
        <span style="font-size:10px;padding:2px 8px;border:1px solid ${sc};color:${sc};border-radius:2px;font-weight:bold">${s.status}</span>
      </div>
      <div style="display:flex;gap:12px;font-size:10px;margin-bottom:8px">
        <span style="color:var(--mute2)">Framework: <span style="color:var(--cyan)">${s.framework}</span></span>
        <span style="color:var(--mute2)">Deps: <span style="color:var(--text2)">${s.dependencies?.length||0}</span></span>
        <span style="color:var(--err)">CRITICAL: ${s.critical}</span>
        <span style="color:var(--orange)">HIGH: ${s.high}</span>
        <span style="color:var(--warn)">MEDIUM: ${s.medium}</span>
        <span style="color:var(--teal)">LOW: ${s.low}</span>
        <span style="color:var(--mute2)">@ ${s.scanned_at}</span>
      </div>
      ${vulnRows||'<div style="color:var(--ok);font-size:10px">No vulnerabilities found</div>'}
    </div>`;
  }).join('');
}

async function runVulnScan() {
  const aid=document.getElementById('vuln-agent-sel').value;
  const res=await api(`/api/security/scan/${aid}`,'POST',{});
  const el=document.getElementById('vuln-result'); el.style.display='block';
  const pass=res.scan?.status==='PASS';
  const sc=pass?'var(--ok)':'var(--err)';
  el.innerHTML=`<div style="background:${pass?'rgba(74,222,128,.08)':'rgba(248,113,113,.08)'};border:1px solid ${sc};border-radius:4px;padding:10px;font-size:11px">
    <div style="color:${sc};font-weight:bold;margin-bottom:4px">${pass?'✓ SCAN PASSED':'✗ SCAN FAILED — Action required'}</div>
    <div style="color:var(--mute2)">${res.scan?.agent_name} · ${res.scan?.vulnerabilities?.length||0} vulnerabilities</div>
    ${res.scan?.critical>0?`<div style="color:var(--err);margin-top:4px">⚠ ${res.scan.critical} CRITICAL finding(s) — deployment blocked</div>`:''}
    ${res.scan?.high>0?`<div style="color:var(--orange)">⚠ ${res.scan.high} HIGH finding(s) — review required</div>`:''}
  </div>`;
  toast(`Vuln scan ${res.scan?.status}: ${aid} — ${res.scan?.vulnerabilities?.length||0} vulns`,pass?'ok':'err');
}

// ── PII / Data Masking UI ─────────────────────────────────────────────────────
function updateMaskingPanel(d) {
  const masking=d.masking||{};
  const maskLog=d.masking_log||[];
  const stats=document.getElementById('mask-stats');
  if(stats) stats.innerHTML=`
    <div class="stat"><span class="stat-val" style="color:var(--purple)">${masking.events_masked||0}</span><span class="stat-lbl">Events Masked</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--cyan)">${masking.fields_masked||0}</span><span class="stat-lbl">Fields Masked</span></div>`;
  const rules=document.getElementById('mask-rules');
  if(rules){
    const ruleData=[
      {field:'email',   pattern:'\\b[\\w.+-]+@[\\w-]+\\.\\w+\\b', mask:'***@***.***',  active:true},
      {field:'phone',   pattern:'\\+?\\d[\\d\\s\\-]{7,}\\d',       mask:'***-***-****', active:true},
      {field:'api_key', pattern:'sk-[a-f0-9]{20,}',                 mask:'sk-***…***',  active:true},
      {field:'ip_addr', pattern:'\\b\\d{1,3}\\.\\d{1,3}\\...',      mask:'*.*.*.*',     active:true},
    ];
    rules.innerHTML=ruleData.map(r=>`
      <div style="background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:8px;margin-bottom:6px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px">
          <span style="color:var(--purple);font-size:11px;font-weight:bold">${r.field}</span>
          <span style="font-size:9px;padding:1px 6px;border:1px solid var(--ok);color:var(--ok);border-radius:2px">ACTIVE</span>
        </div>
        <div style="font-size:10px;color:var(--mute2);margin-bottom:2px">Pattern: <code style="color:var(--cyan)">${r.pattern.slice(0,30)}…</code></div>
        <div style="font-size:10px;color:var(--mute2)">Mask: <span style="color:var(--warn)">${r.mask}</span></div>
      </div>`).join('');
  }
  const log=document.getElementById('mask-log');
  if(log){
    if(!maskLog.length){log.innerHTML='<div style="color:var(--mute);font-size:10px">No masking events yet.</div>';return;}
    log.innerHTML=maskLog.map(e=>`
      <div style="font-size:10px;padding:4px 0;border-bottom:1px solid var(--border)">
        <span style="color:var(--mute)">${e.ts}</span>
        <span style="color:var(--purple);margin:0 6px">MASKED</span>
        <span style="color:var(--cyan)">${e.agent}</span>
        <span style="color:var(--mute2)"> · ${e.fields} field(s) · rule: ${e.rule}</span>
      </div>`).join('');
  }
}

async function runMasking() {
  const text=document.getElementById('mask-input').value;
  if(!text.trim()){toast('Enter some text to mask','err');return;}
  const res=await api('/api/masking/apply','POST',{text});
  const el=document.getElementById('mask-result'); el.style.display='block';
  if(res.ok){
    const applied=(res.rules_applied||[]).map(r=>`<span style="color:var(--purple);margin-right:8px">■ ${r.field} (${r.occurrences}×)</span>`).join('');
    el.innerHTML=`<div style="background:rgba(167,139,250,.08);border:1px solid var(--purple);border-radius:4px;padding:10px;font-size:11px">
      <div style="color:var(--purple);font-weight:bold;margin-bottom:6px">🔒 ${res.fields_masked} field(s) masked</div>
      <div style="font-size:10px;color:var(--mute2);margin-bottom:4px">Rules applied: ${applied||'none'}</div>
      <div style="background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:8px;margin-top:6px">
        <div style="color:var(--mute2);font-size:10px;margin-bottom:4px">MASKED OUTPUT (safe for logs &amp; LLM context):</div>
        <div style="color:var(--ok);font-size:11px;word-break:break-all;font-family:monospace">${res.masked}</div>
      </div>
    </div>`;
    toast(`PII masked: ${res.fields_masked} field(s)`,'ok');
  }
}

// init
switchTab(0);
setInterval(()=>{
  document.getElementById('live-time').textContent=new Date().toLocaleTimeString();
},1000);
</script>
</body>
</html>"""

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
