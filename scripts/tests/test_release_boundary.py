from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
RELEASE_SCRIPT = ROOT / "scripts" / "release.sh"


def bash_path(path: Path) -> str:
    resolved = path.resolve().as_posix()
    if len(resolved) >= 3 and resolved[1:3] == ":/":
        return f"/mnt/{resolved[0].lower()}{resolved[2:]}"
    return resolved


def bash(command: str, *, cwd: Path = ROOT):
    return subprocess.run(
        ["bash", "-c", command],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


class ReleaseBoundaryTests(unittest.TestCase):
    def test_all_workflow_actions_are_pinned_to_full_commit_shas(self):
        for workflow in (CI, RELEASE):
            contents = workflow.read_text(encoding="utf-8")
            refs = re.findall(r"^\s*-?\s*uses:\s*[^@\s]+@([^\s#]+)", contents, re.MULTILINE)
            self.assertTrue(refs, workflow)
            for ref in refs:
                self.assertRegex(ref, r"^[0-9a-f]{40}$", (workflow, ref))

    def test_ordinary_ci_has_read_only_non_release_authority(self):
        ci = CI.read_text(encoding="utf-8")
        self.assertNotIn("contents: write", ci)
        self.assertNotIn("cargo publish", ci)
        self.assertNotIn("git tag", ci)
        self.assertNotIn("CARGO_REGISTRY_TOKEN", ci)

    def test_release_workflow_has_only_manual_trigger(self):
        release = RELEASE.read_text(encoding="utf-8")
        triggers = release.split("on:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("workflow_dispatch:", triggers)
        self.assertNotIn("push:", triggers)
        self.assertNotIn("pull_request:", triggers)

    def test_release_script_rejects_non_dispatch_event(self):
        script = shlex.quote(bash_path(RELEASE_SCRIPT))
        result = bash(f"GITHUB_EVENT_NAME=push {script} --metadata-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only from workflow_dispatch", result.stderr)

    def test_release_script_rejects_non_main_dispatch(self):
        script = shlex.quote(bash_path(RELEASE_SCRIPT))
        result = bash(
            "GITHUB_EVENT_NAME=workflow_dispatch "
            "GITHUB_REF=refs/heads/feature DEFAULT_BRANCH=main "
            f"{script} --metadata-only"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be dispatched from main", result.stderr)

    def test_internal_dependency_must_be_literal_exact_version(self):
        script = shlex.quote(bash_path(RELEASE_SCRIPT))
        with tempfile.TemporaryDirectory(prefix="sacp-release-dependency-") as temp:
            fixture = Path(temp)
            manifest = fixture / "Cargo.toml"
            manifest.write_text(
                '[dependencies]\ninternal = { version = "1.2.3" }\n',
                encoding="utf-8",
            )
            manifest_arg = shlex.quote(bash_path(manifest))
            result = bash(
                f"source {script}; require_exact_dependency {manifest_arg} internal 1.2.3"
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be declared as =1.2.3", result.stderr)

    def test_real_workspace_internal_dependencies_are_literal_exact_versions(self):
        manifests = {
            "sacp-cbor": ROOT / "Cargo.toml",
            "sacp-cbor-derive": ROOT / "sacp-cbor-derive" / "Cargo.toml",
            "sacp-cbor-schema": ROOT / "sacp-cbor-schema" / "Cargo.toml",
            "sacp-cbor-abi": ROOT / "sacp-cbor-abi" / "Cargo.toml",
            "sacp-cbor-abi-derive": ROOT / "sacp-cbor-abi-derive" / "Cargo.toml",
        }
        parsed = {
            name: tomllib.loads(path.read_text(encoding="utf-8"))
            for name, path in manifests.items()
        }
        internal = {
            ("sacp-cbor", "sacp-cbor-derive"),
            ("sacp-cbor-schema", "sacp-cbor"),
            ("sacp-cbor-abi", "sacp-cbor"),
            ("sacp-cbor-abi", "sacp-cbor-abi-derive"),
        }
        for owner, dependency in internal:
            declared = parsed[owner]["dependencies"][dependency]["version"]
            actual = parsed[dependency]["package"]["version"]
            self.assertEqual(declared, f"={actual}", (owner, dependency))

    def test_real_workspace_release_matrix_preflight_needs_no_github_environment(self):
        script = shlex.quote(bash_path(RELEASE_SCRIPT))
        manifests = {
            "sacp-cbor": ROOT / "Cargo.toml",
            "sacp-cbor-derive": ROOT / "sacp-cbor-derive" / "Cargo.toml",
            "sacp-cbor-schema": ROOT / "sacp-cbor-schema" / "Cargo.toml",
            "sacp-cbor-abi-derive": ROOT / "sacp-cbor-abi-derive" / "Cargo.toml",
            "sacp-cbor-abi": ROOT / "sacp-cbor-abi" / "Cargo.toml",
        }
        versions = {
            name: tomllib.loads(path.read_text(encoding="utf-8"))["package"]["version"]
            for name, path in manifests.items()
        }
        result = bash(
            f"source {script}; workspace_release_matrix {shlex.quote(versions['sacp-cbor'])}"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                f"sacp-cbor-derive {versions['sacp-cbor-derive']} sacp-cbor-derive",
                f"sacp-cbor {versions['sacp-cbor']} sacp-cbor",
                f"sacp-cbor-schema {versions['sacp-cbor-schema']} sacp-cbor-schema",
                f"sacp-cbor-abi-derive {versions['sacp-cbor-abi-derive']} sacp-cbor-abi-derive",
                f"sacp-cbor-abi {versions['sacp-cbor-abi']} sacp-cbor-abi",
            ],
        )

    def test_existing_tag_before_all_packages_is_rejected(self):
        script = shlex.quote(bash_path(RELEASE_SCRIPT))
        command = f'''source {script}
release_tag_object_type() {{ printf 'tag\\n'; }}
release_tag_commit() {{ printf 'abc\\n'; }}
verify_published_artifact() {{ return 12; }}
validate_existing_tag_state v1.2.3 abc "internal 1.2.3 internal"
'''
        result = bash(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot be recovered", result.stderr)
        self.assertIn("not confirmed published", result.stderr)

    def test_existing_tag_is_idempotent_only_when_all_packages_exist(self):
        script = shlex.quote(bash_path(RELEASE_SCRIPT))
        command = f'''source {script}
release_tag_object_type() {{ printf 'tag\\n'; }}
release_tag_commit() {{ printf 'abc\\n'; }}
verify_published_artifact() {{ return 0; }}
validate_existing_tag_state v1.2.3 abc "one 1.0.0 one" "two 2.0.0 two"
'''
        result = bash(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_publish_skips_only_an_identical_unyanked_artifact(self):
        script = shlex.quote(bash_path(RELEASE_SCRIPT))
        command = f'''source {script}
verify_published_artifact() {{ return 0; }}
cargo() {{ printf 'unexpected cargo call\\n'; return 99; }}
publish_crate one 1.0.0 one
'''
        result = bash(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already on crates.io; skipping", result.stdout)
        self.assertNotIn("unexpected cargo call", result.stdout)

    def test_publish_rejects_checksum_mismatch_before_cargo(self):
        script = shlex.quote(bash_path(RELEASE_SCRIPT))
        command = f'''source {script}
verify_published_artifact() {{ echo 'checksum mismatch' >&2; return 12; }}
cargo() {{ printf 'unexpected cargo call\\n'; return 0; }}
publish_crate one 1.0.0 one
'''
        result = bash(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertNotIn("unexpected cargo call", result.stdout)


if __name__ == "__main__":
    unittest.main()
