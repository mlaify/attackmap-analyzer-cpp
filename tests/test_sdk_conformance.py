"""SDK 1.0 conformance (mlaify/AttackMap#254): attackmap.sdk.testing.assert_conforms."""

from pathlib import Path

from attackmap.sdk.testing import assert_conforms

from attackmap_analyzer_cpp import CppAnalyzer


def _has_signals(result) -> None:
    assert any(isinstance(v, list) and v for v in result.__dict__.values()), "the analyzer emitted nothing"


SAMPLE = {'CMakeLists.txt': 'cmake_minimum_required(VERSION 3.16)\nproject(sample CXX)\nadd_executable(sample main.cpp)\n', 'main.cpp': '#include "crow.h"\n\nint main() {\n    crow::SimpleApp app;\n    CROW_ROUTE(app, "/users/<int>")([](int id) { return std::to_string(id); });\n    app.port(8080).run();\n}\n'}


def test_conforms_to_the_sdk(tmp_path: Path) -> None:
    for rel, text in SAMPLE.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    _has_signals(assert_conforms(CppAnalyzer(), tmp_path))
