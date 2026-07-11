from fastapi import APIRouter

router = APIRouter()

@router.get("/local/roles/z2r9/{record_id}")
def change_role(record_id: str):
    return load_role_change(record_id)

@router.get("/local/roles/z2r9/{record_id}/summary")
def change_role_summary(record_id: str):
    return load_role_change(record_id)


def load_role_change(record_id: str):
    return update_role(record_id)
