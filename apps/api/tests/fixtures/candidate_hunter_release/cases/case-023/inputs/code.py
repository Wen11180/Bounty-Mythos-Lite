from fastapi import APIRouter

router = APIRouter()

@router.get("/local/tools/u1h5/{record_id}")
def run_tool(record_id: str):
    return load_tool_job(record_id)

@router.get("/local/tools/u1h5/{record_id}/summary")
def run_tool_summary(record_id: str):
    return load_tool_job(record_id)


def load_tool_job(record_id: str):
    return execute_agent_tool(record_id)
