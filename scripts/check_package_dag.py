#!/usr/bin/env python3
"""Verify the declared production package DAG against Cargo metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DAG = ROOT / "architecture" / "production-dag.toml"


def load_metadata(root: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def declared_edges(spec: dict[str, Any]) -> set[tuple[str, str, str, bool]]:
    return {
        (edge["from"], edge["to"], edge["kind"], edge["optional"])
        for edge in spec.get("edge", [])
    }


def metadata_edges(metadata: dict[str, Any]) -> set[tuple[str, str, str, bool]]:
    workspace_ids = set(metadata["workspace_members"])
    packages = {package["id"]: package for package in metadata["packages"]}
    workspace_names = {packages[package_id]["name"] for package_id in workspace_ids}
    edges: set[tuple[str, str, str, bool]] = set()
    for package_id in workspace_ids:
        package = packages[package_id]
        for dependency in package["dependencies"]:
            kind = dependency["kind"] or "normal"
            if kind == "dev" or dependency["name"] not in workspace_names:
                continue
            edges.add(
                (
                    package["name"],
                    dependency["name"],
                    kind,
                    dependency["optional"],
                )
            )
    return edges


def validate(spec: dict[str, Any], metadata: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if spec.get("schema-version") != 1:
        errors.append("production DAG must use schema-version = 1")

    package_entries = spec.get("package", [])
    package_names = [package.get("name") for package in package_entries]
    if any(not name for name in package_names):
        errors.append("every declared package must have a non-empty name")
    if any(not package.get("responsibility") for package in package_entries):
        errors.append("every declared package must have a non-empty responsibility")
    if len(package_names) != len(set(package_names)):
        errors.append("production DAG declares a package more than once")

    metadata_packages = {package["id"]: package for package in metadata["packages"]}
    actual_names = {
        metadata_packages[package_id]["name"]
        for package_id in metadata["workspace_members"]
    }
    declared_names = set(package_names)
    if declared_names != actual_names:
        errors.append(
            "declared packages differ from Cargo workspace: "
            f"missing={sorted(actual_names - declared_names)}, "
            f"unexpected={sorted(declared_names - actual_names)}"
        )

    edge_entries = spec.get("edge", [])
    edges = declared_edges(spec)
    if len(edge_entries) != len(edges):
        errors.append("production DAG declares an edge more than once")
    for source, target, kind, _optional in edges:
        if source not in declared_names or target not in declared_names:
            errors.append(f"edge {source} -> {target} refers to an undeclared package")
        if source == target:
            errors.append(f"self dependency is forbidden: {source} -> {target}")
        if kind not in {"normal", "build"}:
            errors.append(f"edge {source} -> {target} has invalid production kind {kind!r}")

    actual_edges = metadata_edges(metadata)
    for edge in sorted(edges - actual_edges):
        errors.append(f"declared edge is absent from Cargo metadata: {edge}")
    for edge in sorted(actual_edges - edges):
        errors.append(f"undeclared production edge in Cargo metadata: {edge}")

    adjacency = {name: set() for name in declared_names}
    for source, target, _kind, _optional in edges:
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, path: list[str]) -> None:
        if node in visited:
            return
        if node in visiting:
            cycle_start = path.index(node)
            errors.append("production dependency cycle: " + " -> ".join(path[cycle_start:] + [node]))
            return
        visiting.add(node)
        path.append(node)
        for dependency in sorted(adjacency[node]):
            visit(dependency, path)
        path.pop()
        visiting.remove(node)
        visited.add(node)

    for package in sorted(declared_names):
        visit(package, [])

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--dag", type=Path, default=DEFAULT_DAG)
    args = parser.parse_args()
    spec = tomllib.loads(args.dag.read_text(encoding="utf-8"))
    errors = validate(spec, load_metadata(args.root))
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("production package DAG matches Cargo metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
