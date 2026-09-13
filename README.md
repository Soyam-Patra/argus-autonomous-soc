# ARGUS — Autonomous Evidence-Driven SOC

> **An alert is a hypothesis, not a conclusion.**

ARGUS is an autonomous SOC investigation and response system designed to investigate security alerts, collect and correlate evidence, determine whether an attack actually succeeded, take a controlled response, and verify whether that response worked.

The main idea is simple: instead of treating every security alert as a confirmed attack, ARGUS investigates the evidence and makes a decision based on what it finds.


---

# 🌐 Live Demo

### Dashboard

https://argus-autonomous-soc.vercel.app

### Backend API

https://argus-autonomous-soc.onrender.com

### GitHub

https://github.com/Soyam-Patra/argus-autonomous-soc

---

The core loop is:

```text
ALERT
  ↓
INVESTIGATE
  ↓
CORRELATE EVIDENCE
  ↓
ASSESS
  ↓
RESPOND
  ↓
VERIFY
  ↓
ADAPT IF NEEDED
```

---

## 💡 The Idea

A normal automated security workflow can look like:

```text
Alert → Block IP → Done
```

The problem is that this assumes:

1. The alert proves that the attack succeeded.
2. Blocking the attacker means the threat is contained.

Neither is necessarily true.

ARGUS uses a feedback-driven investigation where the environment can change the next decision.

```text
Alert → Investigate → Assess → Act → Verify
                                      ↓
                               Did it work?
                                ↙          ↘
                              YES           NO
                               ↓             ↓
                             Close         Adapt
                                             ↓
                                      New Evidence
                                             ↓
                                      New Response
```

The system operates inside a simulated SOC environment containing alerts, assets, vulnerabilities, network activity, server logs, firewall state, and attacker behavior.

---

# 🎯 What We Solved

We focused on two common problems in SOC automation.

### 1. False conclusions from alerts

A SQL injection alert does not automatically mean the application was compromised.

ARGUS checks multiple sources of evidence before declaring an attack successful:

```text
NIDS Alert
     +
Target Asset
     +
Relevant Vulnerability
     +
Exploit Traffic
     +
Process Execution
     +
Outbound Connection
     ↓
Confirmed Attack
```

This helps distinguish a real compromise from a blocked or unsuccessful attack attempt.

### 2. Responses that appear successful but aren't

Blocking an IP may succeed technically while the attacker continues through another address.

ARGUS therefore verifies the environment after a response.

If the threat is still active, the agent gathers new evidence, revises its assessment, and chooses another bounded response.

---

# 🏗️ Architecture

```text
┌─────────────────────────────┐
│       React Dashboard       │
│  Incidents • Evidence       │
│  Timeline • Agent Decisions │
└──────────────┬──────────────┘
               │ HTTP / JSON
               ▼
┌─────────────────────────────┐
│          FastAPI            │
│       REST API Layer        │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│     ARGUS Orchestrator      │
│                             │
│ Planner                     │
│ Investigation State         │
│ Tool Runner                 │
│ Policy Guard                │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│       SOC Tools             │
│ Alerts • Network • Logs     │
│ Assets • Vulnerabilities    │
│ Firewall • Quarantine       │
│ Verification                │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│    Simulated SOC World      │
│ Alerts • Hosts • Traffic    │
│ Logs • Vulnerabilities      │
│ Firewall • Attacker State   │
└─────────────────────────────┘
```

### Deployment

```text
Browser
   │
   ▼
Vercel
React + Vite Dashboard
   │
   │ HTTPS
   ▼
Render
FastAPI + Uvicorn
   │
   ▼
ARGUS Agent
   │
   ▼
Simulated SOC
```

---

# 🔄 Investigation Workflow

ARGUS does not receive the entire simulated environment at once. It starts with an alert and retrieves additional evidence as needed.

A typical investigation is:

```text
1. Alert received
       ↓
2. Get alert details
       ↓
3. Identify target asset
       ↓
4. Check vulnerabilities
       ↓
5. Gather network evidence
       ↓
6. Search server logs
       ↓
7. Correlate evidence
       ↓
8. Assess attack outcome
       ↓
9. Choose response
       ↓
10. Execute response
       ↓
11. Verify environment
       ↓
12. Close OR reconsider
```

The exact sequence can change depending on what the agent observes.

---

# 🔥 Example: Failed Containment and Adaptation

The main demonstration uses a successful SQL injection attack against `payments-api`.

```text
Alert:       ALERT-1042
Target:      payments-api
Target IP:   10.0.1.25
Initial IP:  185.22.91.14
Severity:    Critical
```

ARGUS investigates the alert and finds:

- an exploitable vulnerability
- exploit traffic
- malicious process execution
- malicious outbound communication

It concludes:

```text
Attack Outcome = SUCCESS
```

ARGUS then blocks the initial attacker:

```text
BLOCK 185.22.91.14
```

It does not assume that the incident is over. It verifies the simulated environment.

The attacker has changed its source to:

```text
185.22.91.17
```

and malicious traffic is still active.

ARGUS detects:

```text
Containment = FAILED
Active Threat = TRUE
```

It then:

```text
Gather new evidence
       ↓
Revise hypothesis
       ↓
Select stronger response
       ↓
Quarantine compromised host
       ↓
Verify again
```

Final result:

```text
Attack Outcome     = SUCCESS
Containment Status = SUCCESS
Active Threat      = FALSE
```

This is the key demonstration of ARGUS: **it does not stop at taking an action; it checks the environment and adapts when the first response is insufficient.**

---

# 🧠 Agent Architecture

The agent is divided into several components.

### Orchestrator

Owns the investigation loop and maintains the current investigation state.

### Planner

Determines what type of step should happen next.

Possible decisions include:

```text
GATHER_EVIDENCE
ASSESS
RESPOND
VERIFY
RECONSIDER
ESCALATE
CLOSE
```

### Runner

Executes the selected step and interacts with registered tools.

### Policy Guard

Controls which response actions are allowed in the current investigation state.

For example, ARGUS should not immediately quarantine a host simply because a NIDS alert exists. Stronger actions require stronger evidence and, in the adaptive case, failed containment.

---

# 🧰 Tools Available to ARGUS

ARGUS interacts with the simulated SOC through explicit, bounded tools.

### Investigation

```text
get_alert
get_asset
get_vulnerabilities
get_network_evidence
search_server_logs
get_firewall_state
```

### Response

```text
firewall_block_ip
quarantine_host
```

### Verification

```text
verify_environment
```

### Human interaction

```text
human_override
```

The agent is not given unrestricted shell or network access.

---

# 🔁 Failure Recovery

The primary scenario intentionally makes the first response fail.

The event flow is:

```text
RESPONSE_ATTEMPTED
        ↓
VERIFICATION_FAILED
        ↓
CONTAINMENT_FAILURE_DETECTED
        ↓
NEW_EVIDENCE_FOUND
        ↓
HYPOTHESIS_REVISED
        ↓
ADAPTIVE_RESPONSE_SELECTED
        ↓
HOST_QUARANTINED
        ↓
RESPONSE_VERIFIED
        ↓
INCIDENT CLOSED
```

This creates a feedback loop rather than a fixed playbook.

---

# 👤 Human Override

ARGUS includes a human override mechanism for situations where an analyst wants to approve or deny a response.

An override records:

```text
Action
Target
Decision
Reason
```

Supported decisions:

```text
APPROVE
DENY
```

The override is also recorded in the investigation event history.

---

# 🛡️ Safety

All response actions are simulated.

ARGUS does not have access to:

- real firewall credentials
- production networks
- real endpoints
- unrestricted shell commands
- destructive external actions

For example:

```text
firewall_block_ip()
quarantine_host()
verify_environment()
```

modify only the simulated SOC state.

This keeps the project safe and reproducible while still allowing the agent to interact with an environment.

---

# ✅ Benefits

### Evidence-driven decisions

Multiple evidence sources are correlated instead of relying on a single alert.

### Reduced false positives

A suspicious request alone does not automatically trigger an aggressive response.

### Closed-loop response

A response is followed by verification instead of being treated as successful simply because the action executed.

### Adaptive containment

If the first response fails, ARGUS can reconsider the incident and select a stronger bounded response.

### Better visibility

The dashboard shows the investigation timeline, evidence, decisions, actions, and environment state.

### Safe and reproducible

The simulator makes the project safe to demonstrate and allows the same scenarios to be tested repeatedly.

---

# 🛠️ Problems We Faced and How We Solved Them

## 1. Making the system genuinely agentic

A fixed sequence of tool calls would look automated but would not really adapt.

### Solution

We introduced explicit investigation state and structured decisions:

```text
GATHER_EVIDENCE
ASSESS
RESPOND
VERIFY
RECONSIDER
ESCALATE
CLOSE
```

The next step depends on the current state and tool results.

---

## 2. Assuming a successful action means successful containment

A firewall block can execute successfully while the attacker continues through another IP.

### Solution

We separated response execution from verification:

```text
Response executed
       ↓
Verify environment
       ↓
Actual containment result
```

This allowed ARGUS to detect source-IP rotation.

---

## 3. Confusing attack success with response success

A successful attack and a successful defense are different outcomes.

### Solution

We track them independently:

```text
attack_outcome
response_status
containment_status
active_threat
```

This makes the final assessment much clearer.

---

## 4. Making the demo reproducible

Random attacker behavior would make the demonstration unreliable.

### Solution

The simulator uses deterministic scenarios, including a predefined attacker IP rotation:

```text
185.22.91.14
       ↓
185.22.91.17
```

This also makes automated evaluation possible.

---

## 5. Frontend TypeScript issues

During frontend development, the production build exposed TypeScript errors, including an unused import and an incorrectly inferred reducer type.

### Solution

We cleaned up the unused import and explicitly typed the reducer used for evidence scoring. The production Vite build then completed successfully.

---

## 6. Local dependency installation issue

During frontend setup, npm initially reported an `ENOSPC` error because the machine ran out of available disk space.

### Solution

After freeing disk space, the dependencies installed successfully and the frontend could be built normally.

---

## 7. Connecting the deployed frontend and backend

The frontend originally used:

```text
http://127.0.0.1:8000
```

which obviously could not be used by the deployed dashboard.

### Solution

The frontend uses:

```text
VITE_API_BASE_URL
```

with the production value:

```text
https://argus-autonomous-soc.onrender.com
```

The backend CORS configuration was also updated to allow the deployed Vercel domain.

---

## 8. Keeping response actions safe

Giving an autonomous agent unrestricted access to a real system would be unnecessary and unsafe for a hackathon prototype.

### Solution

We created explicit simulated tools for blocking and quarantine. These change only the simulator state and are followed by verification.

---

# 📊 Evaluation and Testing

ARGUS includes a deterministic evaluation suite in:

```text
evaluation/
```

Current evaluation result:

```text
18 / 18 evaluation checks passed
100.0% check pass rate
```

The checks cover:

```text
Attack classification
False-positive handling
Response
Response precision
Adaptation
Verification
Safety
Final assessment
Observability
```

The 18 checks are distributed across the currently implemented scenarios. They are **not 18 independent incidents**.

The evaluation can be run with:

```bash
python evaluation/evaluate.py
```

The backend test suite currently has:

```text
28 / 28 tests passing
```

The frontend production build also passes successfully.

---

# 🚀 Why ARGUS Is Better

ARGUS is not simply:

```text
Alert → LLM → Answer
```

and it is not just:

```text
Alert → Fixed Playbook → Response
```

Instead:

```text
Observe
   ↓
Investigate
   ↓
Reason
   ↓
Act
   ↓
Observe again
   ↓
Verify
   ↓
Adapt if necessary
```

The environment can therefore influence the next action.

The most important difference is that ARGUS can recognize:

> **"The response was executed, but it did not solve the problem."**

That allows it to move from a simple IP block to host-level containment when required.


---

# 🔮 Future Scope

The current implementation uses a simulated SOC, but the architecture can be extended to real security environments.

Possible future work includes:

- SIEM integration
- NIDS and EDR log ingestion
- Threat intelligence enrichment
- Real vulnerability management systems
- Persistent incident storage
- More attack scenarios
- Malware and ransomware investigations
- Lateral movement detection
- Cloud workload containment
- Stronger human approval workflows
- Multi-agent SOC investigation
- Larger evaluation datasets
- Production-grade authentication and authorization

The same core loop can remain:

```text
EVIDENCE
   ↓
ASSESSMENT
   ↓
ACTION
   ↓
VERIFICATION
   ↓
ADAPTATION
```

---

# 📁 Project Structure

```text
argus-autonomous-soc/
│
├── backend/
│   ├── agent/
│   │   ├── orchestrator.py
│   │   ├── planner.py
│   │   ├── policy_guard.py
│   │   ├── runner.py
│   │   ├── schemas.py
│   │   ├── state.py
│   │   └── tool_registry.py
│   │
│   ├── api/
│   │   ├── app.py
│   │   ├── routes.py
│   │   └── schemas.py
│   │
│   ├── environment/
│   │   ├── scenarios.py
│   │   ├── seed.py
│   │   └── simulator.py
│   │
│   └── tools/
│       ├── alerts.py
│       ├── assets.py
│       ├── firewall.py
│       ├── human_override.py
│       ├── logs.py
│       ├── network.py
│       ├── runtime.py
│       ├── verification.py
│       └── vulnerabilities.py
│
├── frontend/
│   ├── src/
│   ├── package.json
│   └── ...
│
├── evaluation/
│   ├── evaluate.py
│   ├── test_cases.json
│   ├── README.md
│   ├── results.json
│   └── report.md
│
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

# 💻 Running Locally

## Backend

```bash
git clone https://github.com/Soyam-Patra/argus-autonomous-soc.git
cd argus-autonomous-soc
pip install -r requirements.txt
python -m uvicorn backend.api.app:app --reload --port 8000
```

API:

```text
http://127.0.0.1:8000
```

Health check:

```text
http://127.0.0.1:8000/health
```

## Frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

The dashboard will normally be available at:

```text
http://localhost:5173
```

For local development the frontend defaults to:

```text
http://127.0.0.1:8000
```

---

# 🎬 Recommended Demo

For the strongest demonstration, use **Scenario 003 — Successful attack with failed first response**.

1. Open the ARGUS dashboard.
2. Select the primary incident.
3. Click **Run Investigation**.
4. Use **Next Step** to show evidence gathering.
5. Show the attack being classified as successful.
6. Show the first IP block.
7. Show verification failing.
8. Show the attacker source changing.
9. Show ARGUS gathering new evidence.
10. Show the hypothesis being revised.
11. Show host quarantine being selected.
12. Show successful verification.
13. Show the incident closing.

The key story is:

```text
Detect
  ↓
Investigate
  ↓
Act
  ↓
Verify
  ↓
Failure detected
  ↓
Adapt
  ↓
Act again
  ↓
Verify
```

---

# Final Takeaway

ARGUS is built around one principle:

> **Don't treat an alert as a conclusion, and don't treat an action as proof of containment.**

Investigate the evidence.  
Take the appropriate action.  
Verify what actually happened.  
Adapt when necessary.

**ARGUS — Autonomous Evidence-Driven SOC**
