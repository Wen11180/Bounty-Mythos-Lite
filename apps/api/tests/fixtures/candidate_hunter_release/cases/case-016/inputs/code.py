from fastapi import APIRouter

router = APIRouter()

@router.get("/local/transfers/y3m7/{record_id}")
def transfer_funds(record_id: str):
    record = load_public_transfer(record_id)
    return transfer(record.path)


def load_public_transfer(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
