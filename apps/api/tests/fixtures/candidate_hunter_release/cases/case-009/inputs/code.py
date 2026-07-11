from fastapi import APIRouter

router = APIRouter()

@router.get("/local/archives/t2b5/{record_id}")
def export_archive(record_id: str):
    return export(record_id)
