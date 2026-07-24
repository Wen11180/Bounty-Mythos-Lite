from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Event, Thread
from time import sleep

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.autonomous_research_wakeup as autonomous_research_wakeup
import app.repository as repository_module
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


def test_wakeup_persists_a_shared_minimum_interval_across_callers(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = create_running_campaign(repository, name="Cadence campaign")
        ticked_campaign_ids = []

        def tick(campaign_id, *, repository, dispatcher, now):
            ticked_campaign_ids.append(campaign_id)
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            tick,
        )
        now = datetime(2026, 7, 22, tzinfo=UTC)

        first = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now,
        )
        same_minute = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now + timedelta(seconds=59),
        )
        next_due = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now + timedelta(seconds=60),
        )

        state = repository.get_autonomous_research_wakeup_state()
        assert first["status"] == "completed"
        assert same_minute == {
            "status": "not_due",
            "stop_reason": "wakeup_not_due",
            "processed_count": 0,
            "outcome_counts": {},
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        }
        assert next_due["status"] == "completed"
        assert ticked_campaign_ids == [campaign.id, campaign.id]
        assert state is not None
        assert state.next_due_at is not None
        assert state.next_due_at.replace(tzinfo=UTC) == now + timedelta(minutes=2)
        assert state.lease_token_digest is None
    finally:
        session.close()


def test_wakeup_renews_its_lease_while_an_inline_tick_is_running(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "wakeup-heartbeat.db"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    with session_factory() as session:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = create_running_campaign(repository, name="Slow inline campaign")

    monkeypatch.setattr(
        repository_module,
        "AUTONOMOUS_RESEARCH_WAKEUP_LEASE_SECONDS",
        0.4,
    )
    monkeypatch.setattr(
        repository_module,
        "AUTONOMOUS_RESEARCH_WAKEUP_INTERVAL_SECONDS",
        0.4,
    )
    monkeypatch.setattr(autonomous_research_wakeup, "WAKEUP_LEASE_SECONDS", 0.4)

    tick_started = Event()
    heartbeat_renewed = Event()
    release_tick = Event()
    first_results = []
    original_renew = DatabaseRepository.renew_autonomous_research_wakeup

    def observe_renewal(self, **kwargs):
        renewed = original_renew(self, **kwargs)
        if tick_started.is_set() and renewed:
            heartbeat_renewed.set()
        return renewed

    def slow_tick(campaign_id, *, repository, dispatcher, now):
        assert campaign_id == campaign.id
        tick_started.set()
        assert heartbeat_renewed.wait(timeout=1)
        assert release_tick.wait(timeout=1)
        return {"status": "dispatched", "stop_reason": None}

    monkeypatch.setattr(
        DatabaseRepository,
        "renew_autonomous_research_wakeup",
        observe_renewal,
    )
    monkeypatch.setattr(
        autonomous_research_wakeup,
        "tick_autonomous_research_campaign",
        slow_tick,
    )

    def run_first_wakeup():
        with session_factory() as session:
            first_results.append(
                autonomous_research_wakeup.run_autonomous_research_wakeup(
                    repository=DatabaseRepository(session),
                    dispatcher=lambda **_kwargs: None,
                )
            )

    worker = Thread(target=run_first_wakeup)
    worker.start()
    try:
        assert tick_started.wait(timeout=1)
        assert heartbeat_renewed.wait(timeout=1)
        sleep(0.5)
        with session_factory() as session:
            second = autonomous_research_wakeup.run_autonomous_research_wakeup(
                repository=DatabaseRepository(session),
                dispatcher=lambda **_kwargs: None,
            )

        assert second["status"] == "lease_held"
    finally:
        release_tick.set()
        worker.join(timeout=2)
        engine.dispose()

    assert not worker.is_alive()
    assert first_results[0]["status"] == "completed"


def test_in_memory_wakeup_keeps_a_slow_tick_in_one_process(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = create_running_campaign(repository, name="In-memory slow campaign")
        monkeypatch.setattr(
            repository_module,
            "AUTONOMOUS_RESEARCH_WAKEUP_LEASE_SECONDS",
            0.1,
        )
        monkeypatch.setattr(
            repository_module,
            "AUTONOMOUS_RESEARCH_WAKEUP_INTERVAL_SECONDS",
            0.1,
        )

        tick_started = Event()
        release_tick = Event()
        ticked_campaign_ids = []
        first_results = []

        def slow_tick(campaign_id, *, repository, dispatcher, now):
            ticked_campaign_ids.append(campaign_id)
            tick_started.set()
            assert release_tick.wait(timeout=1)
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            slow_tick,
        )

        worker = Thread(
            target=lambda: first_results.append(
                autonomous_research_wakeup.run_autonomous_research_wakeup(
                    repository=repository,
                    dispatcher=lambda **_kwargs: None,
                )
            )
        )
        worker.start()
        try:
            assert tick_started.wait(timeout=1)
            sleep(0.2)
            held = autonomous_research_wakeup.run_autonomous_research_wakeup(
                repository=repository,
                dispatcher=lambda **_kwargs: None,
            )

            assert held["status"] == "lease_held"
            assert held["stop_reason"] == "wakeup_lease_held"
        finally:
            release_tick.set()
            worker.join(timeout=2)

        assert not worker.is_alive()
        assert first_results[0]["status"] == "completed"
        assert ticked_campaign_ids == [campaign.id]
    finally:
        session.close()


def test_wakeup_keeps_tick_time_separate_from_its_conditional_lease_time(
    monkeypatch,
):
    repository, session = build_repository()
    try:
        campaign = create_running_campaign(repository, name="Separate wakeup clocks")
        lease_now = datetime(2026, 7, 21, tzinfo=UTC)
        tick_now = lease_now + timedelta(hours=1)
        tick_timestamps = []

        def tick(campaign_id, *, repository, dispatcher, now):
            assert campaign_id == campaign.id
            tick_timestamps.append(now)
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            tick,
        )

        result = autonomous_research_wakeup._run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=tick_now,
            lease_now=lease_now,
        )
        state = repository.get_autonomous_research_wakeup_state()

        assert result["status"] == "completed"
        assert tick_timestamps == [tick_now]
        assert state is not None
        assert state.last_cycle_completed_at is not None
        assert state.last_cycle_completed_at.replace(tzinfo=UTC) == lease_now
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


def test_wakeup_persists_a_safe_last_cycle_summary(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = create_running_campaign(repository, name="Wakeup summary campaign")
        now = datetime(2026, 7, 22, tzinfo=UTC)

        def tick(campaign_id, *, repository, dispatcher, now):
            assert campaign_id == campaign.id
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            tick,
        )

        result = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now,
        )
        state = repository.get_autonomous_research_wakeup_state()
        health = autonomous_research_wakeup.build_autonomous_research_wakeup_health(
            state,
            now=now,
        )

        assert result["status"] == "completed"
        assert state is not None
        assert state.last_cycle_completed_at is not None
        assert state.last_cycle_status == "completed"
        assert state.last_cycle_stop_reason is None
        assert state.last_cycle_processed_count == 1
        assert state.last_cycle_outcome_counts == {"dispatched": 1}
        assert health["last_cycle_status"] == "completed"
        assert health["status"] == "healthy"
        assert health["last_cycle_completed_at"] == now.isoformat()
        assert health["last_cycle_processed_count"] == 1
        assert health["last_cycle_outcome_counts"] == {"dispatched": 1}
    finally:
        session.close()


def test_wakeup_persists_only_a_fixed_summary_when_candidate_query_fails(monkeypatch):
    repository, session = build_repository()
    try:
        leaked_detail = "authorization-header=should-not-persist"

        def fail_query(*, after_id=None):
            raise RuntimeError(leaked_detail)

        monkeypatch.setattr(
            repository,
            "list_autonomous_wakeup_campaigns",
            fail_query,
        )

        result = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=datetime(2026, 7, 22, tzinfo=UTC),
        )
        state = repository.get_autonomous_research_wakeup_state()
        health = autonomous_research_wakeup.build_autonomous_research_wakeup_health(
            state,
            now=datetime(2026, 7, 22, tzinfo=UTC),
        )

        assert result["status"] == "failed"
        assert state is not None
        assert state.last_cycle_status == "failed"
        assert state.last_cycle_stop_reason == "wakeup_candidate_query_failed"
        assert state.last_cycle_processed_count == 0
        assert state.last_cycle_outcome_counts == {}
        assert health["status"] == "degraded"
        assert leaked_detail not in str(state.last_cycle_outcome_counts)
        assert leaked_detail not in str(health)
    finally:
        session.close()


def test_wakeup_degrades_health_when_an_isolated_campaign_tick_fails(monkeypatch):
    repository, session = build_repository()
    try:
        create_running_campaign(repository, name="Wakeup isolated failure campaign")

        def fail_tick(*_args, **_kwargs):
            raise RuntimeError("untrusted task failure")

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            fail_tick,
        )
        now = datetime(2026, 7, 22, tzinfo=UTC)

        result = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now,
        )
        health = autonomous_research_wakeup.build_autonomous_research_wakeup_health(
            repository.get_autonomous_research_wakeup_state(),
            now=now,
        )

        assert result["status"] == "completed"
        assert result["stop_reason"] == "wakeup_campaign_tick_failed"
        assert health["status"] == "degraded"
        assert health["last_cycle_status"] == "completed"
        assert health["last_cycle_stop_reason"] == "wakeup_campaign_tick_failed"
    finally:
        session.close()
