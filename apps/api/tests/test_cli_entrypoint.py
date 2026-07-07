import runpy
import sys


def test_python_module_app_entrypoint_shows_cli_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["python -m app", "--help"])

    try:
        runpy.run_module("app", run_name="__main__")
    except SystemExit as error:
        assert error.code == 0

    captured = capsys.readouterr()
    assert "usage: aegis" in captured.out
    assert "agent-next" in captured.out
