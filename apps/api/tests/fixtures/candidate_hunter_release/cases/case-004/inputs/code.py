from fastapi import APIRouter

router = APIRouter()

@router.get("/local/records/f5r1/{record_id}")
def read_record(record_id: str):
    record = load_published_record(record_id)
    return send_file(record.path)


def load_published_record(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
