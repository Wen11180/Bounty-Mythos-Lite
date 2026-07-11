from fastapi import APIRouter

router = APIRouter()

@router.get("/local/exports/w3c8/{record_id}")
def export_payload(record_id: str):
    return export_file(record_id)
