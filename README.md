# ARGUS - Autonomous Evidence-Driven SOC

ARGUS is a hackathon project for demonstrating that an alert is a hypothesis, not a conclusion. Milestone 1 implements the deterministic sandbox environment and bounded tools that later milestones will use for autonomous investigation.

## Milestone 1 Contents

- Repository structure for backend, tools, environment, data, evaluation, and tests.
- Synthetic alerts, assets, vulnerabilities, network events, server logs, and scenarios.
- Stateful scenario engine in `backend/environment/simulator.py`.
- Bounded sandbox tools for alerts, network, assets, vulnerabilities, logs, firewall, verification, and human override recording.
- Simulated firewall actions only. No real firewall, network scanning, cloud account, or destructive external action is used.
- Unit tests for environment state changes and verification behavior.

## Primary Scenario

`scenario-003` demonstrates the Milestone 1 foundation for adaptation:

1. A critical SQL injection alert targets `payments-api`.
2. Evidence shows relevant vulnerability, exploit traffic, process creation, and outbound connection.
3. A simulated IP block is applied to `185.22.91.14`.
4. The attacker rotates to `185.22.91.17`.
5. Verification correctly reports that containment failed.
6. A simulated host quarantine is applied.
7. Verification passes.

## Run Tests

```powershell
cd D:\argus
python -m unittest discover -s tests
```

## Run Milestone 1 Demo

```powershell
cd D:\argus
python -m backend.main
```

## Safety Statement

All response actions are simulated and remain inside the provided sandbox.

## Next Milestones

- Milestone 2: autonomous agent and terminal investigation loop.
- Milestone 3: failed containment adaptation inside the agent loop.
- Milestone 4: FastAPI.
- Milestone 5: frontend SOC dashboard.
- Milestone 6: evaluation dashboard and final demo mode.
