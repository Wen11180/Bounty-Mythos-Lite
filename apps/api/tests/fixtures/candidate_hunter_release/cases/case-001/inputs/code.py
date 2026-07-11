from fastapi import APIRouter

router = APIRouter()

@router.get("/local/records/q7m4/{record_id}")
def read_record(record_id: str):
    return send_file(record_id)
