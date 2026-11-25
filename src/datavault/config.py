from __future__ import annotations

import os
from pathlib import Path

BUNDLED_MODELS = Path(__file__).with_name("models.yaml")


def vault_home() -> Path:
    return Path(os.environ.get("DATAVAULT_HOME", "~/DataVault")).expanduser()


def models_config_path() -> Path:
    """DATAVAULT_MODELS, else <vault home>/models.yaml, else the bundled default."""
    env = os.environ.get("DATAVAULT_MODELS")
    if env:
        return Path(env).expanduser()
    local = vault_home() / "models.yaml"
    return local if local.is_file() else BUNDLED_MODELS
