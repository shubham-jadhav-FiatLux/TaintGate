"""Policy Parser and Validator."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Union
import yaml

from taintgate.core.policy.schema import TaintGateConfig

logger = logging.getLogger(__name__)


def parse_policy(source: Union[str, Path, Dict[str, Any]]) -> TaintGateConfig:
    """Parses and validates a policy specification from a YAML string, file, or dictionary."""
    if isinstance(source, Path):
        content = source.read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
    elif isinstance(source, str):
        # Check if source is a file path (only if no newlines and reasonable length)
        is_file = False
        if "\n" not in source and len(source) < 4096:
            try:
                p = Path(source)
                if p.is_file():
                    is_file = True
                    content = p.read_text(encoding="utf-8")
                    data = yaml.safe_load(content) or {}
            except (OSError, ValueError):
                is_file = False
        if not is_file:
            data = yaml.safe_load(source) or {}
    elif isinstance(source, dict):
        data = source
    else:
        raise TypeError(f"Expected path, string or dict, got {type(source)}")

    config = TaintGateConfig.model_validate(data)

    return config
