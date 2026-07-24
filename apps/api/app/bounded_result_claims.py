from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TrustedBoundedResultClaim:
    claim_id: str
    text: str
    provenance_refs: tuple[str, str, str]
