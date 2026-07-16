import json
from pathlib import Path

from app.cli import main


def _entry(method: str, url: str) -> dict:
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": [
                {"name": "Cookie", "value": "session=SECRET"},
                {"name": "Authorization", "value": "Bearer SECRET"},
            ],
            "queryString": [],
        },
        "response": {
            "status": 200,
            "headers": [],
            "content": {"mimeType": "application/json", "text": '{"id":1}'},
        },
    }


def _har(entries: list[dict]) -> dict:
    return {"log": {"version": "1.2", "entries": entries}}


def _write_role_hars(tmp_path: Path) -> tuple[Path, Path]:
    har_a = tmp_path / "role_a.har"
    har_b = tmp_path / "role_b.har"
    har_a.write_text(
        json.dumps(
            _har([_entry("GET", "http://127.0.0.1/widgets/101")]),
            indent=2,
        ),
        encoding="utf-8",
    )
    har_b.write_text(
        json.dumps(
            _har([_entry("GET", "http://127.0.0.1/widgets/202")]),
            indent=2,
        ),
        encoding="utf-8",
    )
    return har_a, har_b


def test_black_box_lab_cli_bola_retains_and_writes_safe_json(tmp_path, capsys):
    har_a, har_b = _write_role_hars(tmp_path)
    out = tmp_path / "result.json"

    code = main(
        [
            "black-box-lab",
            "--har-a",
            str(har_a),
            "--har-b",
            str(har_b),
            "--mode",
            "bola",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert out.is_file()

    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["schema_version"] == "har_local_lab_pipeline_v1"
    assert result["mode"] == "local_lab_observe"
    assert result["lab_mode"] == "bola"
    assert result["local_lab"] is True
    assert result["execution_allowed"] is False
    assert result["validation_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["raw_secrets_persisted"] is False
    assert len(result["retained_candidates"]) == 1
    assert result["retained_candidates"][0]["decision"] == "retained"
    assert result["observations"][0]["decision"] == "retained"

    blob = out.read_text(encoding="utf-8")
    assert "SECRET" not in blob
    assert "Bearer" not in blob

    captured = capsys.readouterr()
    assert "retained=1/" in captured.out
    assert "execution_allowed=False" in captured.out


def test_black_box_lab_cli_guarded_suppresses(tmp_path):
    har_a, har_b = _write_role_hars(tmp_path)
    out = tmp_path / "guarded.json"

    code = main(
        [
            "black-box-lab",
            "--har-a",
            str(har_a),
            "--har-b",
            str(har_b),
            "--mode",
            "guarded",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["retained_candidates"] == []
    assert result["candidates"][0]["decision"] == "suppressed"


def test_black_box_lab_cli_shared_refutes(tmp_path):
    har_a, har_b = _write_role_hars(tmp_path)
    out = tmp_path / "shared.json"

    code = main(
        [
            "black-box-lab",
            "--har-a",
            str(har_a),
            "--har-b",
            str(har_b),
            "--mode",
            "shared",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["retained_candidates"] == []
    assert result["candidates"][0]["decision"] == "refuted"


def test_black_box_lab_cli_missing_har_exits_nonzero(tmp_path, capsys):
    out = tmp_path / "missing.json"
    code = main(
        [
            "black-box-lab",
            "--har-a",
            str(tmp_path / "nope_a.har"),
            "--har-b",
            str(tmp_path / "nope_b.har"),
            "--mode",
            "bola",
            "--out",
            str(out),
        ]
    )
    assert code == 2
    assert not out.exists()
    captured = capsys.readouterr()
    assert "black-box-lab failed" in captured.err


def test_black_box_lab_cli_help_lists_command():
    try:
        main(["black-box-lab", "--help"])
    except SystemExit as error:
        assert error.code == 0
