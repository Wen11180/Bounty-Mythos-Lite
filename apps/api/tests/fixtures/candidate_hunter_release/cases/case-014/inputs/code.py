from fastapi import APIRouter

router = APIRouter()

@router.get("/local/transfers/h9d2/{record_id}")
def transfer_funds(record_id: str, current_user):
    verify_transfer_access(record_id, current_user)
    return transfer(record_id)


def verify_transfer_access(record_id: str, current_user):
    record = load_transfer(record_id)
    if record.owner_id != current_user.id:
        raise AccessDenied()
    return record
