"""Evidence sources: where the agent gets its facts.

The agent asks an EvidenceSource to run an SPL search and hand back rows. The
default source goes through the Veritrace MCP server, which is the path the
product uses and the one shown in the demo. A direct-SDK source exists as a
fallback for environments without the MCP server, and a fixture source lets the
test suite run the full investigation with no Splunk at all.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SearchResult:
    spl: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    @property
    def count(self) -> int:
        return len(self.rows)


class EvidenceSource(ABC):
    via: str = "unknown"

    @abstractmethod
    def search(self, spl: str, earliest: str = "-30d@d", latest: str = "now") -> SearchResult:
        ...


class McpEvidenceSource(EvidenceSource):
    """Runs searches through the Veritrace MCP server. The primary path."""

    via = "mcp"

    def __init__(self, client, search_tool: str = "splunk_search"):
        self.client = client
        self.search_tool = search_tool

    def search(self, spl: str, earliest: str = "-30d@d", latest: str = "now") -> SearchResult:
        try:
            data = self.client.call_tool(
                self.search_tool, {"spl": spl, "earliest": earliest, "latest": latest}
            )
        except Exception as exc:  # noqa: BLE001 - MCP transport hiccup must not crash a run
            return SearchResult(spl=spl, error=f"mcp call failed: {exc}")
        if "error" in data and data.get("error"):
            return SearchResult(spl=spl, error=str(data["error"]))
        return SearchResult(spl=spl, rows=data.get("results", []) or [])


class DirectSplunkEvidenceSource(EvidenceSource):
    """Runs searches with the Splunk SDK directly. Fallback when MCP is absent."""

    via = "direct"

    def __init__(self, service):
        self.service = service

    def search(self, spl: str, earliest: str = "-30d@d", latest: str = "now") -> SearchResult:
        from . import splunk_io

        try:
            rows = splunk_io.oneshot_search(self.service, spl, earliest=earliest, latest=latest)
            return SearchResult(spl=spl, rows=rows)
        except Exception as exc:  # noqa: BLE001
            return SearchResult(spl=spl, error=str(exc))


class FakeEvidenceSource(EvidenceSource):
    """Returns canned rows keyed by a substring of the SPL. For offline tests."""

    via = "fixture"

    def __init__(self, fixtures: list[tuple[str, list[dict[str, Any]]]]):
        # list of (spl_substring, rows); first match wins
        self.fixtures = fixtures

    def search(self, spl: str, earliest: str = "-30d@d", latest: str = "now") -> SearchResult:
        for needle, rows in self.fixtures:
            if needle in spl:
                return SearchResult(spl=spl, rows=rows)
        return SearchResult(spl=spl, rows=[])
