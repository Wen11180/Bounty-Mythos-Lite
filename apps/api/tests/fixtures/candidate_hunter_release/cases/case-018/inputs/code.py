from fastapi import APIRouter

router = APIRouter()

@router.get("/local/roles/g5k4/{record_id}")
def change_role(record_id: str, current_user):
    verify_role_access(record_id, current_user)
    return update_role(record_id)


def verify_role_access(record_id: str, current_user):
    record = load_role_change(record_id)
    if record.owner_id != current_user.id:
        raise AccessDenied()
    return record
