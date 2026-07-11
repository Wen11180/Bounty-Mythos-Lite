from fastapi import APIRouter

router = APIRouter()

@router.get("/local/archives/v1n9/{record_id}")
def export_archive(record_id: str):
    return load_archive(record_id)

@router.get("/local/archives/v1n9/{record_id}/summary")
def export_archive_summary(record_id: str):
    return load_archive(record_id)


def load_archive(record_id: str):
    return export(record_id)
