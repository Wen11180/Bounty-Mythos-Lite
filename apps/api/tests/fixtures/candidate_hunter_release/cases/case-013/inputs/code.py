from fastapi import APIRouter

router = APIRouter()

@router.get("/local/transfers/p4x8/{record_id}")
def transfer_funds(record_id: str):
    return transfer(record_id)
