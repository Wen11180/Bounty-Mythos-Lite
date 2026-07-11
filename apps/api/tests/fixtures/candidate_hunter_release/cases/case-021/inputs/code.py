from fastapi import APIRouter

router = APIRouter()

@router.get("/local/tools/s4j8/{record_id}")
def run_tool(record_id: str):
    return execute_agent_tool(record_id)
