from pathlib import Path
import shlex
import subprocess
import tempfile
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

    def test_existing_tag_before_all_packages_is_rejected(self):
        script = shlex.quote(bash_path(RELEASE_SCRIPT))
        command = f'''source {script}
release_tag_object_type() {{ printf 'tag\\n'; }}
release_tag_commit() {{ printf 'abc\\n'; }}
is_published() {{ return 1; }}
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
is_published() {{ return 0; }}
validate_existing_tag_state v1.2.3 abc "one 1.0.0 one" "two 2.0.0 two"
'''
        result = bash(command)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
