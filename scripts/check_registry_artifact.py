#!/usr/bin/env python3
"""Verify a local package against the authenticated crates.io artifact."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, NamedTuple


MISSING = 10
YANKED = 11
CHECKSUM_MISMATCH = 12
QUERY_FAILED = 13
INVALID_METADATA = 14
CONTENT_MISMATCH = 15


class MissingVersion(ValueError):
    pass


class YankedVersion(ValueError):
    pass


class ChecksumMismatch(ValueError):
    pass


class InvalidMetadata(ValueError):
    pass


class ContentMismatch(ValueError):
    pass


class ArchiveMember(NamedTuple):
    kind: bytes
    mode: int
    link_target: str
    content: bytes


def sha256_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def version_entry(payload: dict[str, Any], version: str) -> dict[str, Any]:
    direct = payload.get("version")
    if isinstance(direct, dict) and direct.get("num") == version:
        return direct
    versions = payload.get("versions", [])
    if not isinstance(versions, list):
        raise InvalidMetadata("crates.io response has no version list")
    for entry in versions:
        if isinstance(entry, dict) and entry.get("num") == version:
            return entry
    raise MissingVersion(f"version {version} is absent from crates.io")


def registry_checksum(payload: dict[str, Any], version: str) -> str:
    entry = version_entry(payload, version)
    if entry.get("yanked") is not False:
        raise YankedVersion(f"version {version} is yanked")
    checksum = entry.get("checksum")
    if (
        not isinstance(checksum, str)
        or len(checksum) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in checksum)
    ):
        raise InvalidMetadata(f"version {version} has an invalid registry checksum")
    return checksum.lower()


def fetch_version(crate: str, version: str) -> dict[str, Any]:
    crate_path = urllib.parse.quote(crate, safe="")
    version_path = urllib.parse.quote(version, safe="")
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{crate_path}/{version_path}",
        headers={"Accept": "application/json", "User-Agent": "sacp-cbor-release"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def fetch_archive(crate: str, version: str) -> bytes:
    crate_path = urllib.parse.quote(crate, safe="")
    version_path = urllib.parse.quote(version, safe="")
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{crate_path}/{version_path}/download",
        headers={"Accept": "application/octet-stream", "User-Agent": "sacp-cbor-release"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def archive_members(
    contents: bytes, crate: str, version: str
) -> dict[str, ArchiveMember]:
    expected_root = f"{crate}-{version}"
    vcs_info_path = f"{expected_root}/.cargo_vcs_info.json"
    result: dict[str, ArchiveMember] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(contents), mode="r:gz") as archive:
            for member in archive.getmembers():
                relative = PurePosixPath(member.name)
                parts = relative.parts
                if (
                    "\\" in member.name
                    or member.name != relative.as_posix()
                    or relative.is_absolute()
                    or not parts
                    or parts[0] != expected_root
                    or any(part in {"", ".", ".."} for part in parts)
                    or parts[0].endswith(":")
                ):
                    raise ContentMismatch(
                        f"unsafe or unexpected archive member: {member.name!r}"
                    )
                if member.name in result:
                    raise ContentMismatch(f"duplicate archive member: {member.name!r}")
                if not (
                    member.isreg()
                    or member.isdir()
                    or member.issym()
                    or member.islnk()
                ):
                    raise ContentMismatch(
                        f"unsupported archive member type: {member.name!r}"
                    )
                data = b""
                if member.isreg():
                    source = archive.extractfile(member)
                    if source is None:
                        raise ContentMismatch(
                            f"cannot read archive member: {member.name!r}"
                        )
                    data = source.read()
                # Cargo writes the source commit here. Its contents are provenance,
                # not part of an independently-versioned package's semantic artifact.
                if member.name == vcs_info_path:
                    data = b""
                result[member.name] = ArchiveMember(
                    kind=member.type,
                    mode=member.mode,
                    link_target=member.linkname,
                    content=data,
                )
    except (tarfile.TarError, EOFError) as error:
        raise ContentMismatch(f"invalid crate archive: {error}") from error
    if vcs_info_path not in result:
        raise ContentMismatch(f"archive is missing {vcs_info_path}")
    return result


def verify_registry_artifact(
    expected_checksum: str,
    version: str,
    crate: str,
    local_archive: Path,
    registry_archive: bytes,
) -> None:
    downloaded_checksum = sha256_bytes(registry_archive)
    if downloaded_checksum != expected_checksum:
        raise ChecksumMismatch(
            f"version {version} registry download checksum mismatch: "
            f"api={expected_checksum}, download={downloaded_checksum}"
        )
    local_checksum = sha256_file(local_archive)
    if local_checksum == downloaded_checksum:
        return
    local_members = archive_members(local_archive.read_bytes(), crate, version)
    registry_members = archive_members(registry_archive, crate, version)
    if local_members != registry_members:
        local_names = set(local_members)
        registry_names = set(registry_members)
        missing = sorted(registry_names - local_names)
        extra = sorted(local_names - registry_names)
        changed = sorted(
            name
            for name in local_names & registry_names
            if local_members[name] != registry_members[name]
        )
        raise ContentMismatch(
            f"version {version} package contents differ: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("crate")
    parser.add_argument("version")
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    if not args.archive.is_file():
        print(f"missing local package archive: {args.archive}", file=sys.stderr)
        return INVALID_METADATA
    try:
        payload = fetch_version(args.crate, args.version)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            print(f"{args.crate} {args.version} is absent from crates.io", file=sys.stderr)
            return MISSING
        print(f"failed to query crates.io: {error}", file=sys.stderr)
        return QUERY_FAILED
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        print(f"failed to query crates.io: {error}", file=sys.stderr)
        return QUERY_FAILED
    try:
        expected_checksum = registry_checksum(payload, args.version)
    except MissingVersion as error:
        print(error, file=sys.stderr)
        return MISSING
    except YankedVersion as error:
        print(error, file=sys.stderr)
        return YANKED
    except InvalidMetadata as error:
        print(error, file=sys.stderr)
        return INVALID_METADATA
    try:
        remote_archive = fetch_archive(args.crate, args.version)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        print(f"failed to download authenticated registry artifact: {error}", file=sys.stderr)
        return QUERY_FAILED
    try:
        verify_registry_artifact(
            expected_checksum,
            args.version,
            args.crate,
            args.archive,
            remote_archive,
        )
    except ChecksumMismatch as error:
        print(error, file=sys.stderr)
        return CHECKSUM_MISMATCH
    except ContentMismatch as error:
        print(error, file=sys.stderr)
        return CONTENT_MISMATCH
    print(f"{args.crate} {args.version} matches the authenticated registry artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
