from fastapi import APIRouter

router = APIRouter()

@router.get("/local/records/x2k9/{record_id}")
def read_record(record_id: str, current_user):
    verify_record_access(record_id, current_user)
    return send_file(record_id)


def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise AccessDenied()
    return record
