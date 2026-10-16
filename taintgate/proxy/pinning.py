"""Tool description pinning and hashing to detect silent description tampering."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ToolDescriptionPinner:
    """Pins tool descriptions and parameter schemas to prevent prompt injection via MCP tools/list."""

    def __init__(self, pin_file: Optional[Path] = None):
        self.pin_file = Path(pin_file) if pin_file else None
        self.pinned_hashes: Dict[str, str] = {}
        if self.pin_file and self.pin_file.exists():
            try:
                self.pinned_hashes = json.loads(self.pin_file.read_text(encoding="utf-8"))
            except Exception:
                self.pinned_hashes = {}

    def compute_tool_hash(self, tool_def: Dict[str, Any]) -> str:
        """Computes a deterministic SHA-256 hash of a tool's name, description, and input schema."""
        canonical = {
            "name": tool_def.get("name", ""),
            "description": tool_def.get("description", ""),
            "inputSchema": tool_def.get("inputSchema", {}),
        }
        serialized = json.dumps(canonical, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def pin_tools(self, tools: List[Dict[str, Any]]) -> Dict[str, str]:
        """Pins a list of tool definitions."""
        for t in tools:
            name = t.get("name")
            if name:
                self.pinned_hashes[name] = self.compute_tool_hash(t)
        if self.pin_file:
            self.pin_file.parent.mkdir(parents=True, exist_ok=True)
            self.pin_file.write_text(json.dumps(self.pinned_hashes, indent=2, sort_keys=True), encoding="utf-8")
        return self.pinned_hashes

    def verify_tools(self, tools: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
        """Verifies tools against pinned hashes. Returns (is_valid, list_of_modified_or_new_tools)."""
        if not self.pinned_hashes:
            # First observation: automatically pin
            self.pin_tools(tools)
            return True, []

        mismatches: List[str] = []
        for t in tools:
            name = t.get("name")
            if not name:
                continue
            curr_hash = self.compute_tool_hash(t)
            pinned_hash = self.pinned_hashes.get(name)
            if pinned_hash is None:
                mismatches.append(f"New unpinned tool: {name}")
            elif curr_hash != pinned_hash:
                mismatches.append(f"Modified tool description/schema: {name}")

        return (len(mismatches) == 0, mismatches)
