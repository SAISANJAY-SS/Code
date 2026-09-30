from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import main


def test_demo_analysis_and_review_workflow(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "sentinel-test.db")
    monkeypatch.delenv("AWS_SES_SENDER", raising=False)
    monkeypatch.delenv("ALERT_EMAIL", raising=False)
    main.init_db()
    client = TestClient(main.app)

    assert client.get("/users").status_code == 401
    login = client.post("/auth/login", json={"email": "analyst@sentinel.local", "password": "sentinel-demo"})
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    generated = client.post("/demo/generate", headers=headers)
    assert generated.status_code == 200
    assert generated.json() == {"generated_users": 5, "generated_transactions": 60}

    velocity = client.post("/analysis/run/USER-003", headers=headers).json()
    amount = client.post("/analysis/run/USER-002", headers=headers).json()
    travel = client.post("/analysis/run/USER-004", headers=headers).json()
    multi = client.post("/analysis/run/USER-005", headers=headers).json()
    assert velocity["flagged_transactions"] > 0
    assert amount["flagged_transactions"] > 0
    assert travel["flagged_transactions"] > 0
    assert multi["flagged_transactions"] > 0
    assert velocity["notifications"].get("mocked", 0) > 0

    with main.connect() as db:
        mock_notifications = db.execute("SELECT COUNT(*) FROM notifications WHERE status='mocked'").fetchone()[0]
    assert mock_notifications > 0
    client.post("/analysis/run/USER-003", headers=headers)
    with main.connect() as db:
        repeated_notifications = db.execute("SELECT COUNT(*) FROM notifications WHERE status='mocked'").fetchone()[0]
    assert repeated_notifications == mock_notifications

    amount_alert = client.get("/fraud-alerts?user_id=USER-002", headers=headers).json()["data"]
    assert any("Unusual Transaction Amount" in alert["triggered_rules"] for alert in amount_alert)
    travel_alert = client.get("/fraud-alerts?user_id=USER-004", headers=headers).json()["data"]
    assert any("Impossible Geography" in alert["triggered_rules"] for alert in travel_alert)
    travel_item = next(alert for alert in travel_alert if "Impossible Geography" in alert["triggered_rules"])
    travel_detail = client.get(f"/transactions/{travel_item['transaction_id']}/analysis", headers=headers).json()
    geography = next(result for result in travel_detail["rule_results"] if result["rule_name"] == "Impossible Geography")
    assert "previous_latitude" in geography["evidence"]
    assert "current_longitude" in geography["evidence"]
    alert_rows = client.get("/fraud-alerts?user_id=USER-003", headers=headers).json()["data"]
    velocity_alert = next(alert for alert in alert_rows if alert["triggered_rules"] == ["Transaction Velocity"])
    evidence = client.get(f"/transactions/{velocity_alert['transaction_id']}/analysis", headers=headers).json()
    assert evidence["transaction"]["user_id"] == "USER-003"
    velocity_result = next(result for result in evidence["rule_results"] if result["rule_name"] == "Transaction Velocity")
    assert velocity_result["triggered"] is True
    assert velocity_result["evidence"]["transaction_count_in_window"] > velocity_result["evidence"]["configured_threshold"]
    assert evidence["notifications"]
    assert evidence["notifications"][0]["status"] == "mocked"

    review = client.post(f"/transactions/{velocity_alert['transaction_id']}/review", headers=headers, json={"status": "REVIEWED", "comment": "Reviewed in demo"})
    assert review.status_code == 200
    assert review.json()["status"] == "REVIEWED"
    updated = client.get("/fraud-alerts?user_id=USER-003", headers=headers).json()["data"]
    assert next(alert for alert in updated if alert["transaction_id"] == velocity_alert["transaction_id"])["status"] == "REVIEWED"