from fastapi import APIRouter

router = APIRouter()

@router.get("/local/records/n8v3/{record_id}")
def read_record(record_id: str):
    return load_record(record_id)

@router.get("/local/records/n8v3/{record_id}/summary")
def read_record_summary(record_id: str):
    return load_record(record_id)


def load_record(record_id: str):
    return send_file(record_id)
