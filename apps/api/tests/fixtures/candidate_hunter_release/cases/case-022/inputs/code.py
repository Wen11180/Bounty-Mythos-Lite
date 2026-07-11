from fastapi import APIRouter

router = APIRouter()

@router.get("/local/tools/e9c3/{record_id}")
def run_tool(record_id: str, current_user):
    verify_tool_access(record_id, current_user)
    return execute_agent_tool(record_id)


def verify_tool_access(record_id: str, current_user):
    record = load_tool_job(record_id)
    if record.owner_id != current_user.id:
        raise AccessDenied()
    return record
