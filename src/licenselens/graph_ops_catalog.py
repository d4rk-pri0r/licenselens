"""Combine Graph/REST operation catalogs."""

from __future__ import annotations

from licenselens.graph_ops_catalog_endpoint import endpoint_operations
from licenselens.graph_ops_catalog_identity import identity_operations
from licenselens.graph_ops_types import GraphOperation


def build_operations() -> tuple[GraphOperation, ...]:
    return (*identity_operations(), *endpoint_operations())
