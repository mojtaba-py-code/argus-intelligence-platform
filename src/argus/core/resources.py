"""Locate data files that ship with the package (``configs/``, ``prompts/``, ``migrations/``).

In a wheel they live inside the package (``argus/_configs`` ...); in a source checkout they live
at the repository root. Lookups never consult the current working directory, so a file planted in
whatever directory the process starts from cannot shadow a packaged policy file.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def packaged_dir(name: str) -> Path:
    """``name`` is one of ``configs``, ``prompts``, ``migrations``, ``evals``."""
    packaged = resources.files("argus").joinpath(f"_{name}")
    if packaged.is_dir():
        return Path(str(packaged))
    return _repository_root() / name


def config_path(filename: str) -> Path:
    return packaged_dir("configs") / filename
