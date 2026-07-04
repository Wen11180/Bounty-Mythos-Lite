from pydantic import BaseModel


class ProvenanceEdge(BaseModel):
    ref: str
    source_type: str
    stage: str
    source_path: str
    source_method: str | None = None
    fact_type: str


def openapi_path_edge(path: str, *, fact_type: str) -> ProvenanceEdge:
    return ProvenanceEdge(
        ref=f"openapi.paths.{path}",
        source_type="openapi",
        stage="target_model",
        source_path=path,
        source_method=None,
        fact_type=fact_type,
    )


def openapi_operation_edge(path: str, method: str, *, fact_type: str) -> ProvenanceEdge:
    normalized_method = method.lower()
    return ProvenanceEdge(
        ref=f"openapi.paths.{path}.{normalized_method}",
        source_type="openapi",
        stage="target_model",
        source_path=path,
        source_method=normalized_method,
        fact_type=fact_type,
    )


__all__ = [
    "ProvenanceEdge",
    "openapi_operation_edge",
    "openapi_path_edge",
]
