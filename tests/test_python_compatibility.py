from __future__ import annotations

import ast
import unittest
from pathlib import Path


class PythonCompatibilityTests(unittest.TestCase):
    def test_runtime_sources_parse_as_python_3_10(self) -> None:
        project_root = Path(__file__).resolve().parent.parent
        source_roots = (project_root / "app", project_root / "ops")

        for source_root in source_roots:
            for source_path in sorted(source_root.rglob("*.py")):
                with self.subTest(source=str(source_path.relative_to(project_root))):
                    ast.parse(
                        source_path.read_text(encoding="utf-8"),
                        filename=str(source_path),
                        feature_version=(3, 10),
                    )


if __name__ == "__main__":
    unittest.main()
