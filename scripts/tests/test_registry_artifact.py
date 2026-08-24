import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import urllib.error


SCRIPT = Path(__file__).resolve().parents[1] / "check_registry_artifact.py"
SPEC = importlib.util.spec_from_file_location("check_registry_artifact", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


CRATE = "example"
VERSION = "1.2.3"
ROOT = f"{CRATE}-{VERSION}"


def crate_archive(
    *,
    vcs=b'{"git":{"sha1":"old"}}',
    source=b"pub fn answer() -> u8 { 42 }\n",
    manifest=b'[package]\nname = "example"\nversion = "1.2.3"\n',
    original_manifest=b'[package]\nname = "example"\nversion = "1.2.3"\n',
    source_mode=0o644,
    link_target="src/lib.rs",
    extra=False,
    raw_extra_name=None,
    omit=frozenset(),
) -> bytes:
    members = [
        (f"{ROOT}/.cargo_vcs_info.json", vcs, 0o644, tarfile.REGTYPE, ""),
        (f"{ROOT}/Cargo.toml", manifest, 0o644, tarfile.REGTYPE, ""),
        (f"{ROOT}/Cargo.toml.orig", original_manifest, 0o644, tarfile.REGTYPE, ""),
        (f"{ROOT}/src/lib.rs", source, source_mode, tarfile.REGTYPE, ""),
        (f"{ROOT}/src/current.rs", b"", 0o777, tarfile.SYMTYPE, link_target),
    ]
    if extra:
        members.append((f"{ROOT}/extra.txt", b"extra", 0o644, tarfile.REGTYPE, ""))
    if raw_extra_name is not None:
        members.append((raw_extra_name, b"raw", 0o644, tarfile.REGTYPE, ""))
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        for name, contents, mode, kind, linkname in members:
            if name in omit:
                continue
            info = tarfile.TarInfo(name)
            info.type = kind
            info.mode = mode
            info.linkname = linkname
            info.size = len(contents) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(contents) if info.isreg() else None)
    return result.getvalue()


class RegistryArtifactTests(unittest.TestCase):
    def payload(self, remote: bytes, *, checksum=None, yanked=False):
        return {
            "version": {
                "num": VERSION,
                "checksum": checksum or hashlib.sha256(remote).hexdigest(),
                "yanked": yanked,
            }
        }

    def verify(self, local: bytes, remote: bytes, *, payload=None):
        metadata = payload or self.payload(remote)
        expected_checksum = artifact.registry_checksum(metadata, VERSION)
        with tempfile.TemporaryDirectory(prefix="sacp-crate-checksum-") as temp:
            archive = Path(temp) / f"{ROOT}.crate"
            archive.write_bytes(local)
            artifact.verify_registry_artifact(
                expected_checksum, VERSION, CRATE, archive, remote
            )

    def test_identical_unyanked_artifact_is_recoverable(self):
        remote = crate_archive()
        self.verify(remote, remote)

    def test_only_vcs_provenance_content_may_differ(self):
        local = crate_archive(vcs=b'{"git":{"sha1":"new"}}')
        remote = crate_archive(vcs=b'{"git":{"sha1":"old"}}')
        self.verify(local, remote)

    def test_source_or_manifest_content_difference_is_rejected(self):
        remote = crate_archive()
        variants = (
            crate_archive(source=b"pub fn answer() -> u8 { 41 }\n"),
            crate_archive(manifest=b"changed normalized manifest\n"),
            crate_archive(original_manifest=b"changed original manifest\n"),
        )
        for local in variants:
            with self.subTest(checksum=hashlib.sha256(local).hexdigest()):
                with self.assertRaisesRegex(artifact.ContentMismatch, "contents differ"):
                    self.verify(local, remote)

    def test_member_mode_or_link_target_difference_is_rejected(self):
        remote = crate_archive()
        variants = (
            crate_archive(source_mode=0o755),
            crate_archive(link_target="Cargo.toml"),
        )
        for local in variants:
            with self.subTest(checksum=hashlib.sha256(local).hexdigest()):
                with self.assertRaisesRegex(artifact.ContentMismatch, "contents differ"):
                    self.verify(local, remote)

    def test_extra_or_missing_member_is_rejected(self):
        remote = crate_archive()
        variants = (
            crate_archive(extra=True),
            crate_archive(omit=frozenset({f"{ROOT}/src/lib.rs"})),
            crate_archive(omit=frozenset({f"{ROOT}/.cargo_vcs_info.json"})),
        )
        for local in variants:
            with self.subTest(checksum=hashlib.sha256(local).hexdigest()):
                with self.assertRaises(artifact.ContentMismatch):
                    self.verify(local, remote)

    def test_noncanonical_dot_or_empty_path_segments_are_rejected(self):
        remote = crate_archive()
        for member_name in (
            f"{ROOT}/./src/hidden.rs",
            f"{ROOT}//src/hidden.rs",
        ):
            with self.subTest(member_name=member_name):
                local = crate_archive(raw_extra_name=member_name)
                with self.assertRaisesRegex(
                    artifact.ContentMismatch, "unsafe or unexpected archive member"
                ):
                    self.verify(local, remote)

    def test_registry_download_must_match_api_checksum(self):
        remote = crate_archive()
        with self.assertRaisesRegex(artifact.ChecksumMismatch, "download checksum mismatch"):
            self.verify(remote, remote, payload=self.payload(remote, checksum="0" * 64))

    def test_yanked_version_is_rejected_before_download(self):
        remote = crate_archive()
        with tempfile.TemporaryDirectory(prefix="sacp-crate-checksum-") as temp:
            archive = Path(temp) / f"{ROOT}.crate"
            archive.write_bytes(remote)
            with mock.patch.object(
                artifact,
                "fetch_version",
                return_value=self.payload(remote, yanked=True),
            ), mock.patch.object(artifact, "fetch_archive") as download, mock.patch.object(
                artifact.sys,
                "argv",
                ["check_registry_artifact.py", CRATE, VERSION, str(archive)],
            ):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(artifact.main(), artifact.YANKED)
            download.assert_not_called()

    def test_archive_hash_is_the_sha256_of_exact_bytes(self):
        contents = crate_archive()
        with tempfile.TemporaryDirectory(prefix="sacp-crate-checksum-") as temp:
            archive = Path(temp) / f"{ROOT}.crate"
            archive.write_bytes(contents)
            self.assertEqual(
                artifact.sha256_file(archive), hashlib.sha256(contents).hexdigest()
            )

    def test_missing_registry_version_has_distinct_status(self):
        contents = crate_archive()
        with tempfile.TemporaryDirectory(prefix="sacp-crate-checksum-") as temp:
            archive = Path(temp) / f"{ROOT}.crate"
            archive.write_bytes(contents)
            with mock.patch.object(
                artifact, "fetch_version", return_value={"versions": []}
            ), mock.patch.object(artifact, "fetch_archive") as download, mock.patch.object(
                artifact.sys,
                "argv",
                ["check_registry_artifact.py", CRATE, VERSION, str(archive)],
            ):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(artifact.main(), artifact.MISSING)
            download.assert_not_called()

    def test_registry_query_failure_has_distinct_status(self):
        contents = crate_archive()
        with tempfile.TemporaryDirectory(prefix="sacp-crate-checksum-") as temp:
            archive = Path(temp) / f"{ROOT}.crate"
            archive.write_bytes(contents)
            with mock.patch.object(
                artifact,
                "fetch_version",
                side_effect=urllib.error.URLError("offline"),
            ), mock.patch.object(
                artifact.sys,
                "argv",
                ["check_registry_artifact.py", CRATE, VERSION, str(archive)],
            ):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(artifact.main(), artifact.QUERY_FAILED)
    def test_download_checksum_mismatch_has_distinct_status(self):
        remote = crate_archive()
        with tempfile.TemporaryDirectory(prefix="sacp-crate-checksum-") as temp:
            archive = Path(temp) / f"{ROOT}.crate"
            archive.write_bytes(remote)
            with mock.patch.object(
                artifact, "fetch_version", return_value=self.payload(remote, checksum="0" * 64)
            ), mock.patch.object(
                artifact, "fetch_archive", return_value=remote
            ), mock.patch.object(
                artifact.sys,
                "argv",
                ["check_registry_artifact.py", CRATE, VERSION, str(archive)],
            ):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(artifact.main(), artifact.CHECKSUM_MISMATCH)

    def test_api_success_followed_by_download_404_is_query_failure(self):
        remote = crate_archive()
        with contextlib.closing(
            urllib.error.HTTPError(
                "https://crates.io/download", 404, "not found", None, None
            )
        ) as download_404:
            with tempfile.TemporaryDirectory(prefix="sacp-crate-checksum-") as temp:
                archive = Path(temp) / f"{ROOT}.crate"
                archive.write_bytes(remote)
                with mock.patch.object(
                    artifact, "fetch_version", return_value=self.payload(remote)
                ), mock.patch.object(
                    artifact, "fetch_archive", side_effect=download_404
                ), mock.patch.object(
                    artifact.sys,
                    "argv",
                    ["check_registry_artifact.py", CRATE, VERSION, str(archive)],
                ):
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(artifact.main(), artifact.QUERY_FAILED)


if __name__ == "__main__":
    unittest.main()
