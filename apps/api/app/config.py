from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///:memory:"
    redis_url: str = "redis://localhost:6379/0"
    worker_dispatch_mode: str = "celery"
    studio_workspace_root: str = "./mythos-studio-workspaces"
    studio_web_origin: str = "http://127.0.0.1:3000"
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    deepseek_api_key: str | None = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
