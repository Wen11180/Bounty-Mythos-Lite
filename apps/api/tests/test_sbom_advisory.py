from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data
from app.worker.tasks import _map_authorized_attack_surface, run_agent_task


def build_repository() -> tuple[DatabaseRepository, Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    seed_sample_data(session)
    return DatabaseRepository(session), session


def test_referenced_sbom_dependency_is_advisory_evidence_without_raw_output():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="SBOM advisory map campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        raw_marker = "sbom-body-marker"
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized SBOM dependency evidence",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": '''
from django.http import FileResponse
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return FileResponse(file_id)
''',
                    }
                ],
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "get": {"operationId": "exportFile"}
                                }
                            }
                        },
                    }
                ],
                "authorized_advisory_artifacts": [
                    {
                        "kind": "sbom",
                        "source_name": "sbom/dependencies.cdx.json",
                        "payload": {
                            "bomFormat": "CycloneDX",
                            "components": [
                                {
                                    "type": "library",
                                    "name": "django",
                                    "version": "4.2.1",
                                    "purl": "pkg:pypi/django@4.2.1",
                                    "description": raw_marker,
                                }
                            ],
                            "vulnerabilities": [
                                {
                                    "id": "CVE-2099-0001",
                                    "ratings": [{"severity": "high"}],
                                    "affects": [{"ref": "pkg:pypi/django@4.2.1"}],
                                    "description": raw_marker,
                                }
                            ],
                        },
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate SBOM-supported hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert run_agent_task(hypothesis_task.id, repository=repository)["status"] == "completed"

        facts = repository.list_campaign_codebase_facts(campaign.id)
        dependency_fact = next(
            fact
            for fact in facts
            if fact.fact_type == "dependency_signal"
            and fact.payload.get("artifact_kind") == "sbom"
        )
        pipeline_run = repository.list_pipeline_runs_for_program("program_example")[0]
        hypothesis = pipeline_run.payload["hypotheses"][0]

        assert dependency_fact.source_path == "apps/api/routes/files.py"
        assert dependency_fact.symbol_name == "django"
        assert dependency_fact.payload == {
            "artifact_kind": "sbom",
            "mapping_mode": "authorized_advisory_artifact",
            "advisory_only": True,
            "raw_payload_processed": False,
            "source_name": "sbom/dependencies.cdx.json",
            "package_name": "django",
            "package_version": "4.2.1",
            "ecosystem": "pypi",
            "vulnerability_id": "CVE-2099-0001",
            "severity": "high",
            "reachability": "direct_local_import",
            "reachable_route_sources": ["apps/api/routes/files.py"],
            "route_reachability": "direct_route_import",
        }
        assert [
            fact["artifact_kind"]
            for fact in hypothesis["source_facts"]
            if fact["fact_type"] in {"route_handler", "dependency_signal"}
        ] == ["code", "api"]
        assert "evidence_satisfied:reachable_dependency_advisory" not in hypothesis[
            "hunter_assessment"
        ]["reasons"]
        assert pipeline_run.payload["hypothesis_assessments"][0]["validation_plan"][
            "human_approval_required"
        ] is True
        assert raw_marker not in str(
            [fact.payload for fact in facts] + [pipeline_run.payload]
        )
    finally:
        session.close()


def test_service_imported_sbom_dependency_is_advisory_evidence_on_unique_static_path():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Cross-file SBOM advisory map campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map service-imported SBOM dependency evidence",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": '''
from fastapi import APIRouter
from app.services.files import export_file_for_user

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    return export_file_for_user(file_id, current_user)
''',
                    },
                    {
                        "path": "apps/api/services/files.py",
                        "content": '''
from django.http import FileResponse

def export_file_for_user(file_id: str, current_user):
    return send_file(file_id)
''',
                    },
                ],
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "get": {"operationId": "exportFile"}
                                }
                            }
                        },
                    }
                ],
                "authorized_advisory_artifacts": [
                    {
                        "kind": "sbom",
                        "source_name": "sbom/dependencies.cdx.json",
                        "payload": {
                            "bomFormat": "CycloneDX",
                            "components": [
                                {
                                    "type": "library",
                                    "name": "django",
                                    "version": "4.2.1",
                                    "purl": "pkg:pypi/django@4.2.1",
                                }
                            ],
                            "vulnerabilities": [
                                {
                                    "id": "CVE-2099-0001",
                                    "ratings": [{"severity": "high"}],
                                    "affects": [{"ref": "pkg:pypi/django@4.2.1"}],
                                }
                            ],
                        },
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate cross-file SBOM-supported hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert run_agent_task(hypothesis_task.id, repository=repository)["status"] == "completed"

        facts = repository.list_campaign_codebase_facts(campaign.id)
        dependency_fact = next(
            fact
            for fact in facts
            if fact.fact_type == "dependency_signal"
            and fact.payload.get("artifact_kind") == "sbom"
        )
        pipeline_run = repository.list_pipeline_runs_for_program("program_example")[0]
        hypothesis = pipeline_run.payload["hypotheses"][0]

        assert dependency_fact.source_path == "apps/api/services/files.py"
        assert dependency_fact.payload["reachability"] == "direct_local_import"
        assert dependency_fact.payload["reachable_route_sources"] == [
            "apps/api/routes/files.py"
        ]
        assert dependency_fact.payload["route_reachability"] == "unique_static_call_path"
        assert not any(
            fact["fact_type"] == "dependency_signal"
            for fact in hypothesis["source_facts"]
        )
        assert "evidence_satisfied:reachable_dependency_advisory" not in hypothesis[
            "hunter_assessment"
        ]["reasons"]
        assert pipeline_run.payload["hypothesis_assessments"][0]["validation_plan"][
            "human_approval_required"
        ] is True
    finally:
        session.close()


def test_ambiguous_service_path_does_not_link_sbom_advisory_to_route():
    static_map = _map_authorized_attack_surface(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": '''
from fastapi import APIRouter
from app.services.files import export_file_for_user

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    return export_file_for_user(file_id, current_user)
''',
                },
                {
                    "path": "apps/api/services/files.py",
                    "content": '''
from django.http import FileResponse

def export_file_for_user(file_id: str, current_user):
    return send_file(file_id)
''',
                },
                {
                    "path": "apps/api/services/archive.py",
                    "content": '''
def export_file_for_user(file_id: str, current_user):
    return send_file(file_id)
''',
                },
            ],
            "authorized_advisory_artifacts": [
                {
                    "kind": "sbom",
                    "source_name": "sbom/dependencies.cdx.json",
                    "payload": {
                        "bomFormat": "CycloneDX",
                        "components": [
                            {
                                "type": "library",
                                "name": "django",
                                "version": "4.2.1",
                                "purl": "pkg:pypi/django@4.2.1",
                            }
                        ],
                        "vulnerabilities": [
                            {
                                "id": "CVE-2099-0001",
                                "ratings": [{"severity": "high"}],
                                "affects": [{"ref": "pkg:pypi/django@4.2.1"}],
                            }
                        ],
                    },
                }
            ],
        }
    )

    dependency_fact = next(
        fact for fact in static_map.facts if fact.fact_type == "dependency_signal"
    )

    assert dependency_fact.source_path == "apps/api/services/files.py"
    assert dependency_fact.payload["reachability"] == "direct_local_import"
    assert "reachable_route_sources" not in dependency_fact.payload
    assert "route_reachability" not in dependency_fact.payload


def test_unreferenced_sbom_dependency_does_not_create_an_advisory_fact():
    static_map = _map_authorized_attack_surface(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return send_file(file_id)
''',
                }
            ],
            "authorized_advisory_artifacts": [
                {
                    "kind": "sbom",
                    "source_name": "sbom/dependencies.cdx.json",
                    "payload": {
                        "bomFormat": "CycloneDX",
                        "components": [
                            {
                                "type": "library",
                                "name": "django",
                                "version": "4.2.1",
                                "purl": "pkg:pypi/django@4.2.1",
                            }
                        ],
                        "vulnerabilities": [
                            {
                                "id": "CVE-2099-0001",
                                "ratings": [{"severity": "high"}],
                                "affects": [{"ref": "pkg:pypi/django@4.2.1"}],
                            }
                        ],
                    },
                }
            ],
        }
    )

    assert not any(fact.fact_type == "dependency_signal" for fact in static_map.facts)
