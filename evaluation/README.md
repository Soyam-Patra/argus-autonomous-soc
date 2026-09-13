# ARGUS M6 Evaluation

This directory contains the deterministic synthetic SOC evaluation suite.

## Run

From the repository root:

```powershell
python evaluation/evaluate.py
```

The runner executes the actual `InvestigationOrchestrator` against the existing simulator scenarios and writes:

- `evaluation/results.json` — machine-readable results
- `evaluation/report.md` — concise presentation/report summary

All response actions remain inside the simulated SOC environment.
