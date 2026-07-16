from hashlib import sha256
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.testclient import TestClient

from app.black_box_hunter import BlackBoxStop, DifferentialTrial, TrialObservation


LOOPBACK_ORIGIN = "http://127.0.0.1"
LocalLabMode = Literal[
    "bola",
    "guarded",
    "shared",
    "expired_session",
    "unstable",
    "rate_limited",
    "server_error",
    "rollback_failure",
    "off_origin_redirect",
    "third_party_data",
]
SYNTHETIC_OBJECT_OWNERS = {
    "widget_a": "account_a",
    "widget_a2": "account_a",
    "widget_b": "account_b",
    "child_a": "account_a",
    "child_b": "account_b",
}
# Nested parent/child binding for owned_parent_child_swap lab trials.
SYNTHETIC_CHILD_PARENTS = {
    "child_a": "widget_a",
    "child_b": "widget_b",
}
SYNTHETIC_CHILD_ALTERNATE_PARENTS = {
    "child_a": "widget_a2",
    "child_b": "widget_b",
}
PRIMARY_OBJECT_BY_OWNER = {
    "account_a": "widget_a",
    "account_b": "widget_b",
}
CHILD_OBJECT_BY_OWNER = {
    "account_a": "child_a",
    "account_b": "child_b",
}


def create_local_lab_app(mode: LocalLabMode) -> FastAPI:
    app = FastAPI()

    @app.get("/widgets/{object_alias}")
    def read_widget(
        object_alias: str,
        x_lab_session: str | None = Header(default=None),
    ):
        return _local_lab_response(
            mode,
            object_alias,
            x_lab_session,
            state_change=False,
        )

    @app.get("/widgets/{parent_alias}/{object_alias}")
    def read_nested_widget(
        parent_alias: str,
        object_alias: str,
        x_lab_session: str | None = Header(default=None),
    ):
        return _local_lab_response(
            mode,
            object_alias,
            x_lab_session,
            state_change=False,
            parent_alias=parent_alias,
        )

    @app.patch("/widgets/{object_alias}/state")
    def update_widget_state(
        object_alias: str,
        x_lab_session: str | None = Header(default=None),
    ):
        return _local_lab_response(
            mode,
            object_alias,
            x_lab_session,
            state_change=True,
        )

    return app


def _local_lab_response(
    mode: LocalLabMode,
    object_alias: str,
    session_alias: str | None,
    *,
    state_change: bool,
    parent_alias: str | None = None,
):
    if object_alias not in SYNTHETIC_OBJECT_OWNERS:
        return JSONResponse(status_code=404, content={"kind": "unknown"})
    if parent_alias is not None:
        expected_parent = SYNTHETIC_CHILD_PARENTS.get(object_alias)
        if expected_parent is None or parent_alias not in SYNTHETIC_OBJECT_OWNERS:
            return JSONResponse(status_code=404, content={"kind": "unknown"})
        # Guarded/shared labs enforce parent binding; bola ignores it (TP).
        if parent_alias != expected_parent and mode != "bola":
            return JSONResponse(status_code=403, content={"kind": "denied"})
    if mode == "off_origin_redirect":
        return RedirectResponse(url="https://example.invalid/outside-lab", status_code=302)
    if mode == "third_party_data":
        return JSONResponse(
            status_code=200,
            content={"kind": "discard"},
            headers={"X-Lab-Data-Class": "third_party"},
        )
    if mode == "expired_session":
        return JSONResponse(
            status_code=401,
            content={"kind": "session"},
            headers={"X-Lab-Stop": "expired_session"},
        )
    if mode == "rate_limited":
        return JSONResponse(status_code=429, content={"kind": "limit"})
    if mode == "server_error":
        return JSONResponse(status_code=500, content={"kind": "error"})
    if mode == "rollback_failure" and state_change:
        return JSONResponse(
            status_code=409,
            content={"kind": "rollback"},
            headers={"X-Lab-Stop": "rollback_failed"},
        )
    owner_alias = SYNTHETIC_OBJECT_OWNERS[object_alias]

    # Unauthenticated trials omit the lab session header. Only broken-auth (bola)
    # labs return object content so unauthenticated_read_only_replay can retain.
    if session_alias is None:
        if mode != "bola":
            return JSONResponse(status_code=401, content={"kind": "session"})
        return JSONResponse(
            status_code=200,
            content={
                "kind": "synthetic_widget",
                "object_alias": object_alias,
                "canary": _synthetic_canary(object_alias),
                "state_effect": state_change,
                "intended_sharing": False,
            },
        )

    intended_sharing = mode == "shared" and session_alias != owner_alias
    allowed = (
        mode == "bola"
        or intended_sharing
        or session_alias == owner_alias
    )
    if not allowed:
        return JSONResponse(status_code=403, content={"kind": "denied"})

    headers = {"X-Lab-Unstable": "true"} if mode == "unstable" else None
    return JSONResponse(
        status_code=200,
        content={
            "kind": "synthetic_widget",
            "object_alias": object_alias,
            "canary": _synthetic_canary(object_alias),
            "state_effect": state_change,
            "intended_sharing": intended_sharing,
        },
        headers=headers,
    )


class LocalLabTransport:
    """Synthetic, in-process transport that never preserves raw HTTP data."""

    __slots__ = ("_client",)

    def __init__(self, *, mode: LocalLabMode = "guarded") -> None:
        self._client = TestClient(
            create_local_lab_app(mode),
            base_url=LOOPBACK_ORIGIN,
        )

    def execute(self, trial: DifferentialTrial) -> TrialObservation:
        if trial.workflow.origin != LOOPBACK_ORIGIN:
            return _stopped_observation("network_error", "loopback_origin_required")
        if not trial.test_object.test_owned:
            return _stopped_observation("network_error", "test_owned_object_required")
        path = _local_path(trial)
        if path is None:
            return _stopped_observation("network_error", "local_lab_route_required")

        headers = (
            {"X-Lab-Session": trial.session.account_alias}
            if trial.session.active
            else {}
        )
        response = self._client.request(
            trial.workflow.method,
            path,
            headers=headers,
            follow_redirects=False,
        )
        return _sanitize_response(response, trial)

    def close(self) -> None:
        self._client.close()


def _local_path(trial: DifferentialTrial) -> str | None:
    route = trial.workflow.route_template
    if "{object}" not in route or not route.startswith("/widgets/"):
        return None
    return route.replace("{object}", trial.test_object.alias)


def _sanitize_response(response, trial: DifferentialTrial) -> TrialObservation:
    status_class = _status_class(response.status_code)
    if response.headers.get("X-Lab-Data-Class") == "third_party":
        return _stopped_observation(status_class, "third_party_data_detected")
    if response.is_redirect and not _loopback_redirect(response.headers.get("location")):
        return _stopped_observation(status_class, "off_origin_redirect")
    if stop_reason := response.headers.get("X-Lab-Stop"):
        return _stopped_observation(status_class, stop_reason)
    if response.headers.get("X-Lab-Unstable") == "true":
        return _stopped_observation(status_class, "unstable_response")
    if response.status_code == 429:
        return _stopped_observation(status_class, "rate_limited")
    if response.status_code >= 500:
        return _stopped_observation(status_class, "server_error")
    if response.status_code == 404:
        return _stopped_observation(status_class, "unknown_test_object")

    payload = response.json()
    canary = payload.get("canary")
    return TrialObservation(
        status_class=status_class,
        response_schema_fingerprint=_schema_fingerprint(payload),
        timing_bucket="synthetic",
        canary_match=(
            isinstance(canary, str)
            and _digest(canary) == _digest(_synthetic_canary(trial.test_object.alias))
        ),
        structural_identity_match=(
            payload.get("object_alias") == trial.test_object.alias
        ),
        state_effect=payload.get("state_effect") is True,
        intended_sharing=payload.get("intended_sharing") is True,
        redacted=True,
    )


def _stopped_observation(
    status_class: Literal["2xx", "3xx", "4xx", "5xx", "network_error"],
    reason: str,
) -> TrialObservation:
    return TrialObservation(
        status_class=status_class,
        response_schema_fingerprint=f"sha256:{_digest(reason)}",
        timing_bucket="synthetic",
        redacted=True,
        stop=BlackBoxStop(reason=reason),
    )


def _status_class(status_code: int) -> Literal["2xx", "3xx", "4xx", "5xx", "network_error"]:
    if 200 <= status_code < 300:
        return "2xx"
    if 300 <= status_code < 400:
        return "3xx"
    if 400 <= status_code < 500:
        return "4xx"
    if 500 <= status_code < 600:
        return "5xx"
    return "network_error"


def _loopback_redirect(location: str | None) -> bool:
    if not location:
        return False
    parsed = urlsplit(location)
    return not parsed.netloc or (
        parsed.scheme == "http" and parsed.netloc == "127.0.0.1"
    )


def _schema_fingerprint(payload: dict) -> str:
    schema = ",".join(
        sorted(f"{key}:{type(value).__name__}" for key, value in payload.items())
    )
    return f"sha256:{_digest(schema)}"


def _synthetic_canary(object_alias: str) -> str:
    return f"synthetic-canary-{object_alias}"


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()
