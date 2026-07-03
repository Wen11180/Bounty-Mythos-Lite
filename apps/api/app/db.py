from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_initialized_engine_ids: set[int] = set()


def _engine_kwargs(database_url: str) -> dict:
    if database_url.startswith("sqlite"):
        kwargs = {"connect_args": {"check_same_thread": False}}
        if database_url.endswith(":memory:"):
            kwargs["poolclass"] = StaticPool
        return kwargs
    return {}


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(settings.database_url, **_engine_kwargs(settings.database_url))


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def create_tables(engine: Engine) -> None:
    import app.db_models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def initialize_database(engine: Engine | None = None) -> None:
    engine = engine or get_engine()
    engine_id = id(engine)
    if engine_id in _initialized_engine_ids:
        return

    create_tables(engine)
    if engine.dialect.name == "sqlite":
        SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        with SessionLocal() as session:
            from app.repository import seed_sample_data

            seed_sample_data(session)
    _initialized_engine_ids.add(engine_id)


def get_session() -> Iterator[Session]:
    initialize_database()
    with get_session_factory()() as session:
        yield session
