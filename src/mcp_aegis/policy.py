from __future__ import annotations

import fnmatch
import os
import uuid
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-reattr]

from mcp_aegis.types import Decision, MCPRequest, PolicyDecision

_DEFAULT_TOML = Path(__file__).parent / "policy_default.toml"

_DECISION_MAP: dict[str, Decision] = {
    "ALLOW":            Decision.ALLOW,
    "BLOCK":            Decision.BLOCK,
    "LOG_ONLY":         Decision.LOG_ONLY,
    "REQUIRE_APPROVAL": Decision.REQUIRE_APPROVAL,
}

_DEFAULT_ALLOW = PolicyDecision(
    decision=Decision.ALLOW,
    rule_name="default_allow",
    reason="No rule matched — allowing by default",
)


def _matches_any(value: str | None, patterns: list[str]) -> bool:
    if value is None:
        return False
    return any(fnmatch.fnmatch(value, p) for p in patterns)


# Argument keys that may carry a filesystem path or URI on a tools/call request.
_PATH_ARG_KEYS = {
    "path", "file", "filepath", "file_path", "filename",
    "uri", "url", "command", "cmd", "source", "destination",
}


def _tool_call_resource_candidates(request: MCPRequest) -> list[str]:
    """
    Extract path/URI-like argument values from a tools/call request.

    resource_patterns rules are written against resources/read URIs, but a
    tool like read_file(path="~/.ssh/id_rsa") reaches the same credential
    material through tools/call arguments. Surface those values so they're
    checked against resource_patterns too.
    """
    if request.method != "tools/call":
        return []
    arguments = request.params.get("arguments")
    if not isinstance(arguments, dict):
        return []

    candidates: list[str] = []
    for key, value in arguments.items():
        if not isinstance(value, str) or key.lower() not in _PATH_ARG_KEYS:
            continue
        candidates.append(value)
        expanded = os.path.expanduser(value)
        if expanded.startswith("/"):
            candidates.append("file://" + expanded)
    return candidates


class PolicyEngine:
    def __init__(self, policy_path: str | Path, dry_run: bool = False) -> None:
        self._path = Path(policy_path)
        self._dry_run = dry_run
        self._rules: list[dict[str, Any]] = []
        self._load()

    @classmethod
    def from_default(cls, dry_run: bool = False) -> PolicyEngine:
        return cls(_DEFAULT_TOML, dry_run=dry_run)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def evaluate(self, request: MCPRequest, dry_run: bool | None = None) -> PolicyDecision:
        effective_dry_run = self._dry_run if dry_run is None else dry_run

        for rule in self._rules:
            if self._rule_matches(rule, request):
                raw_decision = rule.get("decision", "ALLOW").upper()
                decision = _DECISION_MAP.get(raw_decision, Decision.ALLOW)
                return PolicyDecision(
                    decision=decision,
                    rule_name=rule["name"],
                    reason=rule.get("reason", "Matched rule: " + rule["name"]),
                    dry_run=effective_dry_run,
                )

        result = _DEFAULT_ALLOW
        result = PolicyDecision(
            decision=result.decision,
            rule_name=result.rule_name,
            reason=result.reason,
            dry_run=effective_dry_run,
        )
        return result

    def reload(self) -> None:
        self._load()

    def test(self, tool_name: str, method: str = "tools/call") -> PolicyDecision:
        synthetic = MCPRequest(
            session_id="policy-test-" + str(uuid.uuid4()),
            request_id=None,
            method=method,
            params={"name": tool_name} if method == "tools/call" else {},
            raw={},
        )
        return self.evaluate(synthetic)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with open(self._path, "rb") as fh:
            data = tomllib.load(fh)
        self._rules = data.get("rules", [])

    def _rule_matches(self, rule: dict[str, Any], request: MCPRequest) -> bool:
        # Each matcher key that is present in the rule must match — AND logic.
        # If a key is absent, it is treated as a wildcard (always passes).

        methods: list[str] | None = rule.get("methods")
        if methods is not None:
            if request.method not in methods:
                return False

        tools: list[str] | None = rule.get("tools")
        if tools is not None:
            if not _matches_any(request.tool_name, tools):
                return False

        resource_patterns: list[str] | None = rule.get("resource_patterns")
        if resource_patterns is not None:
            matched = _matches_any(request.resource_uri, resource_patterns)
            if not matched:
                matched = any(
                    _matches_any(candidate, resource_patterns)
                    for candidate in _tool_call_resource_candidates(request)
                )
            if not matched:
                return False

        # If we reach here, all present matchers passed.
        return True
