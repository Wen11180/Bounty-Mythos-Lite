from __future__ import annotations

from pathlib import Path
import sys
from typing import Iterable, TextIO

from app.source_audit import SourceAuditBlocked, run_source_audit


HELP_TEXT = "\n".join(
    [
        "mythos chat",
        "Commands:",
        "  repo <path>   set the authorized local repository",
        "  scope <path>  set the scope policy file",
        "  scan          run a local source audit",
        "  status        show the last run summary",
        "  help          show this help",
        "  exit          leave chat",
        "Safety: validation execution: disabled; report submission: disabled.",
    ]
)


class ChatSession:
    def __init__(self) -> None:
        self.repo_path: Path | None = None
        self.scope_path: Path | None = None
        self.last_summary: str | None = None

    def handle(self, message: str) -> str:
        text = message.strip()
        if not text:
            return "enter a command, or type help"

        lowered = text.lower()
        if lowered in {"exit", "quit", "q"}:
            return "bye"
        if lowered in {"help", "?"}:
            return HELP_TEXT
        if lowered.startswith("repo "):
            self.repo_path = Path(text[5:].strip())
            return f"repo set: {self.repo_path}"
        if lowered.startswith("scope "):
            self.scope_path = Path(text[6:].strip())
            return f"scope set: {self.scope_path}"
        if lowered == "status":
            return self.last_summary or "last run: none"
        if lowered == "scan":
            return self._scan()

        return "unknown command; type help"

    def _scan(self) -> str:
        if self.repo_path is None:
            return "repo is required before scan"
        if self.scope_path is None:
            return "scope is required before scan"

        try:
            result = run_source_audit(self.repo_path, self.scope_path)
        except SourceAuditBlocked as error:
            self.last_summary = f"last run: blocked ({error})"
            return self.last_summary

        summary = "\n".join(
            [
                "source audit complete",
                "scope: allowed",
                f"hypotheses: {len(result.hypotheses)}",
                "validation execution: disabled",
                "human review: required",
                "last run: source audit",
            ]
        )
        self.last_summary = summary
        return summary


def run_chat(messages: Iterable[str]) -> str:
    session = ChatSession()
    outputs: list[str] = []
    for message in messages:
        response = session.handle(message)
        outputs.append(response)
        if response == "bye":
            break
    return "\n".join(outputs)


def run_terminal_chat(
    *,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> int:
    input_stream = input_stream or sys.stdin
    output_stream = output_stream or sys.stdout
    session = ChatSession()

    while True:
        output_stream.write("mythos> ")
        output_stream.flush()
        message = input_stream.readline()
        if message == "":
            output_stream.write("bye\n")
            return 0

        response = session.handle(message)
        output_stream.write(f"{response}\n")
        if response == "bye":
            return 0
