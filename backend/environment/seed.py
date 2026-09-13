from __future__ import annotations

from .scenarios import load_scenarios, load_seed_data


def load_environment_seed() -> dict:
    seed = load_seed_data()
    seed["scenarios"] = {key: scenario.__dict__ for key, scenario in load_scenarios().items()}
    return seed
