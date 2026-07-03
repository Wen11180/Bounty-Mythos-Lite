from app.worker.tasks import ping


def test_ping_task_returns_pong():
    assert ping.run() == "pong"
