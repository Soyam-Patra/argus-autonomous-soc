# ARGUS Synthetic SOC Evaluation

Generated from the deterministic ARGUS simulator and actual InvestigationOrchestrator runs.

## Results

- Evaluation checks: **18**
- Passed: **18**
- Failed: **0**
- Overall pass rate: **100.0%**
- Attack outcome accuracy: **100.0%**
- False-positive response precision: **100.0%**
- Verification success: **100.0%**
- Adaptation success: **100.0%**
- Observed policy/safety violations: **0**

## Primary adaptive scenario

The primary scenario is expected to demonstrate failed first containment followed by evidence gathering, hypothesis revision, adaptive response, and successful verification.

- Decision events: **11**
- Tool-result events: **10**
- Actions recorded: `{'action': 'block_ip', 'ip': '185.22.91.14', 'simulated': True, 'status': 'applied', 'side_effect': 'attacker_source_rotated', 'new_source': '185.22.91.17'}, {'action': 'quarantine_host', 'asset_id': 'asset-payments-api', 'simulated': True, 'status': 'applied'}`

## Category results

- attack_classification: **2/2**
- false_positive: **1/1**
- response: **2/2**
- response_precision: **1/1**
- adaptation: **5/5**
- verification: **2/2**
- safety: **2/2**
- final_assessment: **2/2**
- observability: **1/1**

## Methodology

The suite uses synthetic, deterministic SOC scenarios. No real network, firewall, production credentials, or external infrastructure is contacted. The metrics above are computed from the agent's actual returned state and event timeline.
