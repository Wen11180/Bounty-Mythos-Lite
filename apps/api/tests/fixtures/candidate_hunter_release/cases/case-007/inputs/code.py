from fastapi import APIRouter

router = APIRouter()

@router.get("/local/exports/d4y7/{record_id}")
def export_payload(record_id: str):
    return load_payload(record_id)

@router.get("/local/exports/d4y7/{record_id}/summary")
def export_payload_summary(record_id: str):
    return load_payload(record_id)


def load_payload(record_id: str):
    return export_file(record_id)
