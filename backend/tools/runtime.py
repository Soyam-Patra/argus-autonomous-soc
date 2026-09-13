from __future__ import annotations

from backend.environment.simulator import ArgusSimulator


_DEFAULT_SIMULATOR = ArgusSimulator()


def get_simulator() -> ArgusSimulator:
    return _DEFAULT_SIMULATOR


def reset_simulator(scenario_id: str = "scenario-003") -> ArgusSimulator:
    global _DEFAULT_SIMULATOR
    _DEFAULT_SIMULATOR = ArgusSimulator(scenario_id)
    return _DEFAULT_SIMULATOR
