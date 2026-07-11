from fastapi import APIRouter

router = APIRouter()

@router.get("/local/transfers/c6w5/{record_id}")
def transfer_funds(record_id: str):
    return load_transfer(record_id)

@router.get("/local/transfers/c6w5/{record_id}/summary")
def transfer_funds_summary(record_id: str):
    return load_transfer(record_id)


def load_transfer(record_id: str):
    return transfer(record_id)
