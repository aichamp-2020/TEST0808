/**
 * ServiceNow Business Rule — "Trigger Jira on Assignment"
 * =========================================================
 * Table  : sc_request  (or 'incident' / 'sc_task' as needed)
 * When   : after  insert or update
 * Advanced: true
 *
 * Condition (set in the Business Rule "Condition" field):
 *   (current.assigned_to.changes() || current.assignment_group.changes())
 *   && !current.assigned_to.nil()
 *
 * SETUP IN SERVICENOW:
 * ─────────────────────────────────────────────────────────────────────────
 *  1. System Definition → Business Rules → New
 *  2. Name       : Trigger Jira Story on Assignment
 *  3. Table      : Service Request [sc_request]
 *  4. Active     : ✓
 *  5. Advanced   : ✓
 *  6. When       : after    Insert: ✓    Update: ✓
 *  7. Condition  :
 *       (current.assigned_to.changes() || current.assignment_group.changes())
 *       && !current.assigned_to.nil()
 *  8. Script tab : paste this file
 *  9. Save
 *
 * OUTBOUND REST MESSAGE SETUP (required):
 * ─────────────────────────────────────────────────────────────────────────
 *  1. System Web Services → Outbound → REST Messages → New
 *     Name     : Jira Webhook Trigger
 *     Endpoint : https://<your-webhook-host>/webhook/snow-assigned
 *     Auth     : No authentication
 *  2. HTTP Methods → New
 *     Method name : triggerJira
 *     HTTP method : POST
 *  3. HTTP Request tab → Add Headers:
 *     Content-Type  : application/json
 *     X-Snow-Secret : <value of 'webhook-hmac-secret' from Key Vault>
 *  4. Save
 */

(function executeRule(current, previous) {

    var REST_MESSAGE_NAME = "Jira Webhook Trigger";
    var REST_METHOD_NAME  = "triggerJira";

    // Optional: restrict to specific groups only.
    // Leave empty [] to trigger for ALL groups.
    var ALLOWED_GROUPS = [
        "Cloud Platform Engineering",
        "AI Platform Team"
    ];

    // Guard: only fire when actually assigned
    if (current.assigned_to.nil()) {
        gs.info("JIRA TRIGGER: skipped — no assigned_to on " + current.number);
        return;
    }

    // Guard: group filter
    if (ALLOWED_GROUPS.length > 0) {
        var groupName    = current.assignment_group.getDisplayValue();
        var groupMatched = false;
        for (var i = 0; i < ALLOWED_GROUPS.length; i++) {
            if (groupName === ALLOWED_GROUPS[i]) {
                groupMatched = true;
                break;
            }
        }
        if (!groupMatched) {
            gs.info(
                "JIRA TRIGGER: skipped — group '" + groupName +
                "' not in ALLOWED_GROUPS for " + current.number
            );
            return;
        }
    }

    // Build minimal payload — webhook fetches the full record itself
    var payload = JSON.stringify({
        sys_id:           current.sys_id.toString(),
        table:            current.getTableName(),
        number:           current.number.toString(),
        event:            "assigned",
        triggered_by:     "business_rule",
        assigned_to:      current.assigned_to.getDisplayValue(),
        assignment_group: current.assignment_group.getDisplayValue(),
        timestamp:        new GlideDateTime().toString()
    });

    try {
        var sm           = new sn_ws.RESTMessageV2(REST_MESSAGE_NAME, REST_METHOD_NAME);
        sm.setRequestBody(payload);

        var response   = sm.execute();
        var statusCode = response.getStatusCode();
        var body       = response.getBody();

        if (statusCode === 200) {
            gs.info(
                "JIRA TRIGGER: SUCCESS for " + current.number +
                " | Response: " + body
            );
        } else {
            gs.warn(
                "JIRA TRIGGER: Non-200 for " + current.number +
                " | HTTP " + statusCode + " | " + body
            );
        }
    } catch (ex) {
        gs.error(
            "JIRA TRIGGER: REST call FAILED for " + current.number +
            " | Error: " + ex.getMessage()
        );
    }

})(current, previous);
