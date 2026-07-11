from fastapi import APIRouter

router = APIRouter()

@router.get("/local/roles/l7v6/{record_id}")
def change_role(record_id: str):
    record = load_public_role_change(record_id)
    return update_role(record.path)


def load_public_role_change(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
