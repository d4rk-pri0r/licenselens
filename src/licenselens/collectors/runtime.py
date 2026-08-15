"""Bind registered collector factories to live/dry-run ScanCollectionContext closures."""

from __future__ import annotations

from licenselens.collectors.mde import collect_mde_machine_summary
from licenselens.collectors.runtime_envelopes import (
    EvidenceCollectorFn,
    collection_summaries_from,
    envelopes_to_evidence,
)
from licenselens.collectors.runtime_specs import (
    build_runtime_collector_specs,
    check_requirements_for,
    collect_selected_evidence,
)
from licenselens.collectors.sentinel import collect_sentinel_bundle

__all__ = [
    "EvidenceCollectorFn",
    "build_runtime_collector_specs",
    "check_requirements_for",
    "collect_mde_machine_summary",
    "collect_selected_evidence",
    "collect_sentinel_bundle",
    "collection_summaries_from",
    "envelopes_to_evidence",
]
