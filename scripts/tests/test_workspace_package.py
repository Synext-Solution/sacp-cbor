from pathlib import Path
import subprocess
import tempfile
import unittest


class WorkspacePackageTests(unittest.TestCase):
    def test_workspace_package_verifies_unpublished_exact_path_dependency(self):
        with tempfile.TemporaryDirectory(prefix="sacp-workspace-package-") as temp:
            root = Path(temp)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["dep", "app"]\nresolver = "2"\n',
                encoding="utf-8",
            )
            for member in ("dep", "app"):
                (root / member / "src").mkdir(parents=True)
            (root / "dep" / "Cargo.toml").write_text(
                '''[package]
name = "sacp-package-fixture-dep"
version = "9876.0.0"
edition = "2021"
license = "MIT"
''',
                encoding="utf-8",
            )
            (root / "dep" / "src" / "lib.rs").write_text(
                "pub fn value() -> u8 { 7 }\n", encoding="utf-8"
            )
            (root / "app" / "Cargo.toml").write_text(
                '''[package]
name = "sacp-package-fixture-app"
version = "9876.0.0"
edition = "2021"
license = "MIT"

[dependencies]
sacp-package-fixture-dep = { path = "../dep", version = "=9876.0.0" }
''',
                encoding="utf-8",
            )
            (root / "app" / "src" / "lib.rs").write_text(
                "pub fn value() -> u8 { sacp_package_fixture_dep::value() }\n",
                encoding="utf-8",
            )

            subprocess.run(
                ["cargo", "generate-lockfile", "--offline"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                ["cargo", "package", "--workspace", "--locked", "--offline"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertNotIn("crates.io index", result.stderr)
            package_dir = root / "target" / "package"
            self.assertTrue(
                (package_dir / "sacp-package-fixture-dep-9876.0.0.crate").is_file()
            )
            self.assertTrue(
                (package_dir / "sacp-package-fixture-app-9876.0.0.crate").is_file()
            )


if __name__ == "__main__":
    unittest.main()
