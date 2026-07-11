from fastapi import APIRouter

router = APIRouter()

@router.get("/local/roles/b8t1/{record_id}")
def change_role(record_id: str):
    return update_role(record_id)
