from fastapi import APIRouter

router = APIRouter()

@router.get("/local/tools/a6p2/{record_id}")
def run_tool(record_id: str):
    record = load_public_tool_job(record_id)
    return execute_agent_tool(record.path)


def load_public_tool_job(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
