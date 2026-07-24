from celery import Celery

from app.autonomous_research_wakeup import WAKEUP_INTERVAL_SECONDS
from app.config import get_settings


settings = get_settings()

celery_app = Celery(
    "bounty_mythos",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.worker.tasks"],
)
celery_app.conf.beat_schedule = {
    "autonomous-research-wakeup": {
        "task": "autonomous_research.wakeup",
        "schedule": float(WAKEUP_INTERVAL_SECONDS),
    },
}
