from fastapi import APIRouter

router = APIRouter()

@router.get("/local/archives/r7f3/{record_id}")
def export_archive(record_id: str):
    record = load_public_archive(record_id)
    return export(record.path)


def load_public_archive(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
