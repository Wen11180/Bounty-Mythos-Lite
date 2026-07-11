from fastapi import APIRouter

router = APIRouter()

@router.get("/local/archives/k8q6/{record_id}")
def export_archive(record_id: str, current_user):
    verify_archive_access(record_id, current_user)
    return export(record_id)


def verify_archive_access(record_id: str, current_user):
    record = load_archive(record_id)
    if record.owner_id != current_user.id:
        raise AccessDenied()
    return record
