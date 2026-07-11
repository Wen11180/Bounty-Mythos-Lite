from fastapi import APIRouter

router = APIRouter()

@router.get("/local/exports/j9p2/{record_id}")
def export_payload(record_id: str, current_user):
    verify_payload_access(record_id, current_user)
    return export_file(record_id)


def verify_payload_access(record_id: str, current_user):
    record = load_payload(record_id)
    if record.owner_id != current_user.id:
        raise AccessDenied()
    return record
