"""Entitlement and capability catalog loading."""

from licenselens.catalog.loader import (
    capability_summaries_for,
    load_capabilities,
    resolve_owned_capabilities,
)

__all__ = [
    "capability_summaries_for",
    "load_capabilities",
    "resolve_owned_capabilities",
]
