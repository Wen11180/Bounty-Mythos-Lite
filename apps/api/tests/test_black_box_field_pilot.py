from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.black_box_hunter.field_pilot import (
    FieldPilotFeedbackEntry,
    FieldPilotFeedbackRequest,
    evaluate_field_pilot_status,
)
from app.db import Base, get_session
from app.db_models import ProgramRecord
from app.main import app
from app.repository import DatabaseRepository, seed_sample_data


@pytest.fixture
def field_pilot_client() -> Iterator[tuple[TestClient, sessionmaker[Session]]]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with testing_session() as session:
        seed_sample_data(session)

    def override_get_session() -> Iterator[Session]:
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with TestClient(app) as client:
            yield client, testing_session
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _feedback_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "program_id": "program_example",
        "engagement_alias": "engagement_01",
        "candidate_alias": "candidate_01",
        "playbook_id": "bola_idor",
        "candidate_rank": 1,
        "label": "valid",
        "researcher_minutes": 45,
        "bounty_amount": 500,
        "externally_valid_report": True,
        "safety_incident": False,
        "operator_confirmed": True,
    }
    payload.update(overrides)
    return payload


def _entry(
    index: int,
    *,
    label: str,
    externally_valid_report: bool = False,
    bounty_amount: int | None = None,
    safety_incident: bool = False,
) -> FieldPilotFeedbackEntry:
    return FieldPilotFeedbackEntry(
        learning_signal_id=f"learning_signal_{index:02d}",
        program_id=f"program_{(index // 6) % 3}",
        engagement_alias=f"engagement_{index // 6:02d}",
        candidate_alias=f"candidate_{index:02d}",
        playbook_id="bola_idor",
        candidate_rank=(index % 6) + 1,
        label=label,
        researcher_minutes=60,
        bounty_amount=bounty_amount,
        externally_valid_report=externally_valid_report,
        safety_incident=safety_incident,
        operator_confirmed=True,
    )


def test_field_pilot_feedback_records_only_redacted_advisory_metadata(
    field_pilot_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_session = field_pilot_client

    response = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json=_feedback_payload(),
    )

    assert response.status_code == 200
    feedback = response.json()
    assert feedback["label"] == "valid"
    assert feedback["learning_outcome"] == "accepted"
    assert feedback["operator_confirmed"] is True
    assert feedback["execution_allowed"] is False
    assert feedback["lease_grant_allowed"] is False
    assert feedback["scope_change_allowed"] is False
    assert feedback["review_bypass_allowed"] is False
    assert feedback["report_submission_allowed"] is False
    assert feedback["safety_notes"] == [
        "redacted_aggregate_only",
        "advisory_ranking_only",
        "no_execution_permission",
        "no_scope_change",
        "no_review_bypass",
        "no_report_submission",
    ]

    with testing_session() as session:
        signals = DatabaseRepository(session).list_learning_signals("program_example")
        assert len(signals) == 1
        signal = signals[0]
        assert signal.id == feedback["learning_signal_id"]
        assert signal.outcome == "accepted"
        assert signal.notes == "operator-reviewed field-pilot label: valid"
        assert signal.field_pilot_feedback == {
            "schema_version": "black_box_field_pilot_v1",
            "engagement_alias": "engagement_01",
            "candidate_alias": "candidate_01",
            "candidate_rank": 1,
            "label": "valid",
            "researcher_minutes": 45,
            "externally_valid_report": True,
            "safety_incident": False,
            "operator_confirmed": True,
        }
        assert "Authorization" not in str(signal.field_pilot_feedback)
        assert "Bearer" not in str(signal.field_pilot_feedback)


@pytest.mark.parametrize(
    ("label", "learning_outcome"),
    [
        ("valid", "accepted"),
        ("duplicate", "duplicate"),
        ("invalid", "rejected"),
        ("out_of_scope", "na"),
        ("needs_evidence", "informative"),
    ],
)
def test_field_pilot_feedback_maps_each_operator_label_to_advisory_learning(
    field_pilot_client: tuple[TestClient, sessionmaker[Session]],
    label: str,
    learning_outcome: str,
) -> None:
    client, _ = field_pilot_client

    response = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json=_feedback_payload(
            label=label,
            bounty_amount=None,
            externally_valid_report=False,
        ),
    )

    assert response.status_code == 200
    assert response.json()["label"] == label
    assert response.json()["learning_outcome"] == learning_outcome


def test_field_pilot_feedback_requires_operator_confirmation_and_forbids_raw_content(
    field_pilot_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_session = field_pilot_client

    not_confirmed = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json=_feedback_payload(operator_confirmed=False),
    )
    raw_content = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json={
            **_feedback_payload(),
            "report_contents": "Authorization: Bearer live-token",
        },
    )
    unsafe_alias = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json=_feedback_payload(candidate_alias="https://target.example/users/1"),
    )
    inconsistent_external_result = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json=_feedback_payload(label="duplicate"),
    )
    bounty_without_external_result = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json=_feedback_payload(externally_valid_report=False),
    )

    assert not_confirmed.status_code == 422
    assert raw_content.status_code == 422
    assert unsafe_alias.status_code == 422
    assert inconsistent_external_result.status_code == 422
    assert bounty_without_external_result.status_code == 422
    with testing_session() as session:
        assert DatabaseRepository(session).list_learning_signals("program_example") == []


def test_field_pilot_feedback_is_idempotent_and_rejects_conflicting_relabels(
    field_pilot_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_session = field_pilot_client
    payload = _feedback_payload()

    first = client.post("/mythos/black-box/field-pilot/feedback", json=payload)
    repeated = client.post("/mythos/black-box/field-pilot/feedback", json=payload)
    conflicting = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json=_feedback_payload(
            label="invalid",
            bounty_amount=None,
            externally_valid_report=False,
        ),
    )

    assert first.status_code == 200
    assert repeated.status_code == 200
    assert repeated.json()["learning_signal_id"] == first.json()["learning_signal_id"]
    assert conflicting.status_code == 409
    assert conflicting.json()["detail"] == "field_pilot_feedback_already_recorded"
    with testing_session() as session:
        assert len(DatabaseRepository(session).list_learning_signals("program_example")) == 1


def test_field_pilot_feedback_rejects_programs_outside_current_scope(
    field_pilot_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_session = field_pilot_client
    with testing_session() as session:
        program = session.get(ProgramRecord, "program_example")
        assert program is not None
        program.scope_status = "out_of_scope"
        session.commit()

    response = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json=_feedback_payload(),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "scope_not_in_scope"
    with testing_session() as session:
        assert DatabaseRepository(session).list_learning_signals("program_example") == []


def test_field_pilot_candidate_identity_prevents_conflicting_duplicate_rows(
    field_pilot_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    _, testing_session = field_pilot_client
    valid_request = FieldPilotFeedbackRequest(**_feedback_payload())
    invalid_request = FieldPilotFeedbackRequest(
        **_feedback_payload(
            label="invalid",
            bounty_amount=None,
            externally_valid_report=False,
        )
    )

    with testing_session() as session:
        repository = DatabaseRepository(session)
        first = repository.save_learning_signal(
            program_id=valid_request.program_id,
            playbook_id=valid_request.playbook_id,
            outcome="accepted",
            surface_key=valid_request.candidate_alias,
            notes="operator-reviewed field-pilot label: valid",
            bounty_amount=valid_request.bounty_amount,
            field_pilot_feedback=valid_request.metadata(),
        )
        conflicting = repository.save_learning_signal(
            program_id=invalid_request.program_id,
            playbook_id=invalid_request.playbook_id,
            outcome="rejected",
            surface_key=invalid_request.candidate_alias,
            notes="operator-reviewed field-pilot label: invalid",
            bounty_amount=invalid_request.bounty_amount,
            field_pilot_feedback=invalid_request.metadata(),
        )

        assert conflicting.id == first.id
        assert len(repository.list_learning_signals("program_example")) == 1


def test_field_pilot_status_requires_thresholds_and_zero_safety_incidents() -> None:
    entries = [
        _entry(index, label="valid" if index < 9 else "needs_evidence")
        for index in range(30)
    ]

    achieved = evaluate_field_pilot_status(entries)
    incident = evaluate_field_pilot_status(
        [entries[0].model_copy(update={"safety_incident": True}), *entries[1:]]
    )

    assert achieved.status == "field_pilot"
    assert achieved.metrics.independent_engagement_count == 5
    assert achieved.metrics.manually_reviewed_candidate_count == 30
    assert achieved.metrics.top_10_reviewed_count == 30
    assert achieved.metrics.top_10_valid_count == 9
    assert achieved.metrics.top_10_submit_worthy_precision == 0.3
    assert achieved.requirements.field_pilot is True
    assert achieved.requirements.outcome_proven is False
    assert incident.status == "collecting_evidence"
    assert incident.metrics.safety_incident_count == 1
    assert incident.requirements.field_pilot is False


def test_field_pilot_status_reserves_outcome_proven_for_external_results() -> None:
    external_indexes = {0, 1, 2, 3, 6, 7, 12, 13, 18, 24}
    bounty_indexes = {0, 1, 2, 6, 12}
    entries = [
        _entry(
            index,
            label="valid" if index in external_indexes else "needs_evidence",
            externally_valid_report=index in external_indexes,
            bounty_amount=100 if index in bounty_indexes else None,
        )
        for index in range(30)
    ]

    result = evaluate_field_pilot_status(entries)

    assert result.status == "outcome_proven"
    assert result.metrics.program_count == 3
    assert result.metrics.externally_valid_program_count == 3
    assert result.metrics.externally_valid_report_count == 10
    assert result.metrics.bounty_outcome_count == 5
    assert result.metrics.researcher_minutes == 1800
    assert result.metrics.bounty_total == 500
    assert result.metrics.bounty_per_researcher_hour == 16.67
    assert result.requirements.field_pilot is True
    assert result.requirements.outcome_proven is True
    assert result.execution_allowed is False
    assert result.lease_grant_allowed is False
    assert result.scope_change_allowed is False
    assert result.review_bypass_allowed is False
    assert result.report_submission_allowed is False


def test_outcome_proven_requires_external_reports_across_three_programs() -> None:
    entries = [
        _entry(
            index,
            label="valid" if index < 10 else "needs_evidence",
            externally_valid_report=index < 10,
            bounty_amount=100 if index < 5 else None,
        )
        for index in range(30)
    ]

    result = evaluate_field_pilot_status(entries)

    assert result.status == "field_pilot"
    assert result.metrics.program_count == 3
    assert result.metrics.externally_valid_program_count == 2
    assert result.metrics.externally_valid_report_count == 10
    assert result.metrics.bounty_outcome_count == 5
    assert result.requirements.outcome_proven is False


def test_field_pilot_status_api_reads_only_field_pilot_learning_signals(
    field_pilot_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_session = field_pilot_client
    created = client.post(
        "/mythos/black-box/field-pilot/feedback",
        json=_feedback_payload(),
    )
    assert created.status_code == 200
    with testing_session() as session:
        DatabaseRepository(session).save_learning_signal(
            program_id="program_example",
            playbook_id="bola_idor",
            outcome="accepted",
            surface_key="generic_surface",
            notes="Ordinary learning signal, not field-pilot evidence.",
        )

    response = client.get("/mythos/black-box/field-pilot/status")

    assert response.status_code == 200
    status = response.json()
    assert status["status"] == "collecting_evidence"
    assert status["metrics"]["manually_reviewed_candidate_count"] == 1
    assert status["metrics"]["independent_engagement_count"] == 1
    assert status["metrics"]["externally_valid_report_count"] == 1
    assert status["metrics"]["externally_valid_program_count"] == 1
    assert status["metrics"]["bounty_outcome_count"] == 1
    assert status["metrics"]["researcher_minutes"] == 45
    assert status["metrics"]["bounty_total"] == 500
    assert status["requirements"] == {
        "field_pilot": False,
        "outcome_proven": False,
    }
