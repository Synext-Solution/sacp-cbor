import copy
import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_package_dag.py"
SPEC = importlib.util.spec_from_file_location("check_package_dag", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
dag = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dag)


def fixture():
    spec = {
        "schema-version": 1,
        "package": [
            {"name": "api", "responsibility": "public API"},
            {"name": "derive", "responsibility": "macros"},
        ],
        "edge": [
            {"from": "api", "to": "derive", "kind": "normal", "optional": True}
        ],
    }
    metadata = {
        "workspace_members": ["api 1.0.0", "derive 1.0.0"],
        "packages": [
            {
                "id": "api 1.0.0",
                "name": "api",
                "dependencies": [
                    {
                        "name": "derive",
                        "kind": None,
                        "optional": True,
                        "source": None,
                    }
                ],
            },
            {"id": "derive 1.0.0", "name": "derive", "dependencies": []},
        ],
    }
    return spec, metadata


class ProductionDagTests(unittest.TestCase):
    def test_matching_dag_is_accepted(self):
        spec, metadata = fixture()
        self.assertEqual(dag.validate(spec, metadata), [])

    def test_undeclared_cargo_edge_is_rejected(self):
        spec, metadata = fixture()
        metadata["packages"][1]["dependencies"].append(
            {"name": "api", "kind": None, "optional": False, "source": None}
        )
        errors = dag.validate(spec, metadata)
        self.assertTrue(
            any("undeclared production edge" in error for error in errors), errors
        )

    def test_declared_edge_with_wrong_semantics_is_rejected(self):
        spec, metadata = fixture()
        spec = copy.deepcopy(spec)
        spec["edge"][0]["optional"] = False
        errors = dag.validate(spec, metadata)
        self.assertTrue(any("declared edge is absent" in error for error in errors), errors)
        self.assertTrue(any("undeclared production edge" in error for error in errors), errors)

    def test_cycle_is_rejected(self):
        spec, metadata = fixture()
        spec = copy.deepcopy(spec)
        metadata = copy.deepcopy(metadata)
        reverse = {
            "from": "derive",
            "to": "api",
            "kind": "normal",
            "optional": False,
        }
        spec["edge"].append(reverse)
        metadata["packages"][1]["dependencies"].append(
            {"name": "api", "kind": None, "optional": False, "source": None}
        )
        errors = dag.validate(spec, metadata)
        self.assertTrue(any("dependency cycle" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
