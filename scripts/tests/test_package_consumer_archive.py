import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "package_consumer_smoke.py"
SPEC = importlib.util.spec_from_file_location("package_consumer_smoke", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)


def write_archive(path: Path, members):
    with tarfile.open(path, "w:gz") as package:
        for name, data, member_type in members:
            entry = tarfile.TarInfo(name)
            entry.type = member_type
            if member_type == tarfile.REGTYPE:
                entry.size = len(data)
                package.addfile(entry, io.BytesIO(data))
            else:
                entry.linkname = data.decode()
                package.addfile(entry)


class PackageArchiveTests(unittest.TestCase):
    def test_valid_single_root_archive_is_unpacked(self):
        with tempfile.TemporaryDirectory(prefix="sacp-archive-test-") as temp:
            root = Path(temp)
            archive = root / "valid.crate"
            write_archive(
                archive,
                [("crate-1.0.0/Cargo.toml", b"[package]\n", tarfile.REGTYPE)],
            )
            extracted = consumer.unpack_crate(
                archive, root / "out", "crate-1.0.0"
            )
            self.assertEqual(
                (extracted / "Cargo.toml").read_bytes(), b"[package]\n"
            )

    def test_parent_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sacp-archive-test-") as temp:
            root = Path(temp)
            archive = root / "traversal.crate"
            write_archive(
                archive,
                [
                    ("crate-1.0.0/Cargo.toml", b"[package]\n", tarfile.REGTYPE),
                    ("crate-1.0.0/../escape", b"bad", tarfile.REGTYPE),
                ],
            )
            with self.assertRaisesRegex(ValueError, "unsafe or unexpected"):
                consumer.unpack_crate(archive, root / "out", "crate-1.0.0")

    def test_links_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sacp-archive-test-") as temp:
            root = Path(temp)
            archive = root / "link.crate"
            write_archive(
                archive,
                [
                    ("crate-1.0.0/Cargo.toml", b"[package]\n", tarfile.REGTYPE),
                    ("crate-1.0.0/link", b"../outside", tarfile.SYMTYPE),
                ],
            )
            with self.assertRaisesRegex(ValueError, "non-regular"):
                consumer.unpack_crate(archive, root / "out", "crate-1.0.0")

    def test_absolute_and_unexpected_roots_are_rejected(self):
        for member_name in ("/absolute", "another-root/Cargo.toml"):
            with self.subTest(member_name=member_name), tempfile.TemporaryDirectory(
                prefix="sacp-archive-test-"
            ) as temp:
                root = Path(temp)
                archive = root / "wrong-root.crate"
                write_archive(
                    archive,
                    [(member_name, b"bad", tarfile.REGTYPE)],
                )
                with self.assertRaisesRegex(ValueError, "unsafe or unexpected"):
                    consumer.unpack_crate(archive, root / "out", "crate-1.0.0")

    def test_corrupt_archive_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sacp-archive-test-") as temp:
            root = Path(temp)
            archive = root / "corrupt.crate"
            archive.write_bytes(b"not a gzip tar archive")
            with self.assertRaises(tarfile.ReadError):
                consumer.unpack_crate(archive, root / "out", "crate-1.0.0")


if __name__ == "__main__":
    unittest.main()
