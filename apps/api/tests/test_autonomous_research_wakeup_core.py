from datetime import UTC, datetime, timedelta
from hashlib import sha256

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.autonomous_research_wakeup as autonomous_research_wakeup
import app.worker.tasks as worker_tasks
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data


def build_repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    seed_sample_data(session)
    return DatabaseRepository(session), session


def create_running_campaign(repository, *, name):
    campaign = repository.create_campaign(
        program_id="program_example",
        name=name,
        autonomy_level="level_0_read_only",
        scope_status="in_scope",
        policy_text="Authorized local review only.",
        default_asset="local.example",
        created_by="operator",
    )
    campaign = repository.update_campaign_status(campaign.id, "running")
    assert campaign is not None
    return campaign


def test_wakeup_pages_running_campaigns_and_preserves_safety_gates(monkeypatch):
    repository, session = build_repository()
    try:
        for index in range(25):
            create_running_campaign(repository, name=f"Wakeup campaign {index}")
        first_page_ids = [
            candidate["id"]
            for candidate in repository.list_autonomous_wakeup_campaigns()
        ]
        second_page_ids = [
            candidate["id"]
            for candidate in repository.list_autonomous_wakeup_campaigns(
                after_id=first_page_ids[-1]
            )
        ]
        ticked_campaign_ids = []

        def tick(campaign_id, *, repository, dispatcher, now):
            ticked_campaign_ids.append(campaign_id)
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            tick,
        )
        now = datetime(2026, 7, 21, tzinfo=UTC)

        first = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now,
        )
        second = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now + timedelta(minutes=1),
        )

        state = repository.get_autonomous_research_wakeup_state()
        assert first["status"] == "completed"
        assert first["processed_count"] == 20
        assert second["status"] == "completed"
        assert second["processed_count"] == 5
        assert ticked_campaign_ids == [*first_page_ids, *second_page_ids]
        assert state is not None
        assert state.after_campaign_id is None
        assert state.lease_token_digest is None
        for result in (first, second):
            assert result["execution_allowed"] is False
            assert result["dispatch_allowed"] is False
            assert result["validation_allowed"] is False
            assert result["candidate_promotion_allowed"] is False
            assert result["report_submission_allowed"] is False
    finally:
        session.close()


def test_wakeup_recovers_only_after_an_existing_lease_expires(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = create_running_campaign(repository, name="Lease recovery campaign")
        now = datetime(2026, 7, 21, tzinfo=UTC)
        owner_token = sha256(b"owner").hexdigest()
        assert repository.claim_autonomous_research_wakeup(
            claim_token_digest=owner_token,
            now=now,
        ) is not None
        assert repository.renew_autonomous_research_wakeup(
            claim_token_digest=sha256(b"other").hexdigest(),
            now=now + timedelta(seconds=1),
        ) is False
        ticked_campaign_ids = []

        def tick(campaign_id, *, repository, dispatcher, now):
            ticked_campaign_ids.append(campaign_id)
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            tick,
        )

        held = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now + timedelta(seconds=1),
        )
        recovered = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now
            + timedelta(
                seconds=autonomous_research_wakeup.WAKEUP_LEASE_SECONDS + 1
            ),
        )

        assert held["status"] == "lease_held"
        assert recovered["status"] == "completed"
        assert ticked_campaign_ids == [campaign.id]
    finally:
        session.close()


def test_wakeup_releases_its_lease_after_a_candidate_query_failure(monkeypatch):
    repository, session = build_repository()
    try:
        def fail_query(*, after_id=None):
            raise RuntimeError("synthetic candidate query failure")

        monkeypatch.setattr(
            repository,
            "list_autonomous_wakeup_campaigns",
            fail_query,
        )

        result = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=datetime(2026, 7, 21, tzinfo=UTC),
        )

        state = repository.get_autonomous_research_wakeup_state()
        assert result["status"] == "failed"
        assert result["stop_reason"] == "wakeup_candidate_query_failed"
        assert state is not None
        assert state.after_campaign_id is None
        assert state.lease_token_digest is None
    finally:
        session.close()


def test_wakeup_worker_task_uses_a_worker_session_and_beat_schedule(monkeypatch):
    events = []
    repository_sentinel = object()

    class SessionContext:
        def __enter__(self):
            return object()

        def __exit__(self, *_args):
            return False

    def run_wakeup(*, repository, dispatcher):
        events.append((repository, dispatcher))
        return {"status": "completed"}

    monkeypatch.setattr(worker_tasks, "initialize_database", lambda: None)
    monkeypatch.setattr(
        worker_tasks,
        "get_session_factory",
        lambda: lambda: SessionContext(),
    )
    monkeypatch.setattr(
        worker_tasks,
        "DatabaseRepository",
        lambda _session: repository_sentinel,
    )
    monkeypatch.setattr(
        autonomous_research_wakeup,
        "run_autonomous_research_wakeup",
        run_wakeup,
    )

    result = worker_tasks.run_autonomous_research_wakeup_from_queue.run()

    assert result == {"status": "completed"}
    assert events == [(repository_sentinel, worker_tasks.dispatch_agent_task)]
    assert worker_tasks.celery_app.conf.beat_schedule[
        "autonomous-research-wakeup"
    ] == {"task": "autonomous_research.wakeup", "schedule": 60.0}
