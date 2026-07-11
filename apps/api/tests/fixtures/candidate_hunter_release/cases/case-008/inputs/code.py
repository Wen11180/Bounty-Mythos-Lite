from fastapi import APIRouter

router = APIRouter()

@router.get("/local/exports/m6h1/{record_id}")
def export_payload(record_id: str):
    record = load_public_payload(record_id)
    return export_file(record.path)


def load_public_payload(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
