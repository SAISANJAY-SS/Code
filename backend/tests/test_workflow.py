from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import main


def test_demo_analysis_and_review_workflow(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "sentinel-test.db")
    monkeypatch.setenv("AWS_SES_SENDER", "verified@example.test")
    monkeypatch.setenv("ALERT_EMAIL", "alerts@example.test")
    monkeypatch.setenv("AWS_SNS_TOPIC_ARN", "arn:aws:sns:ap-south-1:123456789012:sentinel-test")
    calls: list[str] = []

    class FakeSes:
        def send_email(self, **kwargs):
            calls.append("SES")
            assert "Html" in kwargs["Message"]["Body"]
            assert "Triggered rules" in kwargs["Message"]["Body"]["Html"]["Data"]
            return {"MessageId": "ses-test-message"}

    class FakeSns:
        def publish(self, **kwargs):
            calls.append("SNS")
            assert kwargs["Subject"].startswith("[HIGH]")
            assert "Triggered evidence" in kwargs["Message"]
            return {"MessageId": "sns-test-message"}

    monkeypatch.setattr(main.boto3, "client", lambda service, **kwargs: FakeSes() if service == "ses" else FakeSns())
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
    assert velocity["notifications"]["SES"].get("sent", 0) > 0
    assert velocity["notifications"]["SNS"].get("sent", 0) > 0
    assert "SES" in calls and "SNS" in calls

    with main.connect() as db:
        sent_notifications = db.execute("SELECT COUNT(*) FROM notifications WHERE status='sent'").fetchone()[0]
    assert sent_notifications > 0
    client.post("/analysis/run/USER-003", headers=headers)
    with main.connect() as db:
        repeated_notifications = db.execute("SELECT COUNT(*) FROM notifications WHERE status='sent'").fetchone()[0]
    assert repeated_notifications == sent_notifications

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
    assert {item["channel"] for item in evidence["notifications"]} == {"SES", "SNS"}
    assert all(item["status"] == "sent" for item in evidence["notifications"])

    review = client.post(f"/transactions/{velocity_alert['transaction_id']}/review", headers=headers, json={"status": "REVIEWED", "comment": "Reviewed in demo"})
    assert review.status_code == 200
    assert review.json()["status"] == "REVIEWED"
    updated = client.get("/fraud-alerts?user_id=USER-003", headers=headers).json()["data"]
    assert next(alert for alert in updated if alert["transaction_id"] == velocity_alert["transaction_id"])["status"] == "REVIEWED"


def test_sns_is_attempted_when_ses_fails(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "sentinel-sns-test.db")
    monkeypatch.setenv("AWS_SES_SENDER", "verified@example.test")
    monkeypatch.setenv("ALERT_EMAIL", "alerts@example.test")
    monkeypatch.setenv("AWS_SNS_TOPIC_ARN", "arn:aws:sns:ap-south-1:123456789012:sentinel-test")
    calls: list[str] = []

    class FakeSes:
        def send_email(self, **kwargs):
            calls.append("SES")
            raise RuntimeError("simulated SES outage")

    class FakeSns:
        def publish(self, **kwargs):
            calls.append("SNS")
            return {"MessageId": "sns-test-message"}

    monkeypatch.setattr(main.boto3, "client", lambda service, **kwargs: FakeSes() if service == "ses" else FakeSns())
    main.init_db()
    with main.connect() as db:
        user_id = db.execute("INSERT INTO users(user_id,name,email,scenario,home_location,latitude,longitude,device_id) VALUES(?,?,?,?,?,?,?,?)", ("USER-TEST", "Test User", "test@example.test", "test", "Mumbai", 19.076, 72.8777, "DEV-TEST")).lastrowid
        transaction_id = db.execute("INSERT INTO transactions(transaction_id,user_id,amount,transaction_date,location,latitude,longitude,device_id) VALUES(?,?,?,?,?,?,?,?)", ("TXN-TEST", user_id, 10000, main.now_iso(), "Mumbai", 19.076, 72.8777, "DEV-TEST")).lastrowid
        flag_id = db.execute("INSERT INTO fraud_flags(transaction_id,risk_level,status,reason,created_at,updated_at) VALUES(?,?,?,?,?,?)", (transaction_id, "HIGH", "UNREVIEWED", "test", main.now_iso(), main.now_iso())).lastrowid
        transaction = db.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
        results = main.send_high_risk_notifications(db, flag_id, transaction, "Test User", "HIGH", [{"rule_name": "Test rule", "severity": "HIGH", "evidence": {}}])
        statuses = {row["channel"]: row["status"] for row in db.execute("SELECT channel,status FROM notifications WHERE fraud_flag_id=?", (flag_id,))}

    assert calls == ["SES", "SNS"]
    assert results["SES"]["status"] == "failed"
    assert results["SNS"]["status"] == "sent"
    assert statuses == {"SES": "failed", "SNS": "sent"}


def test_reference_environment_variable_names_are_supported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "sentinel-alias-test.db")
    monkeypatch.delenv("AWS_SES_SENDER", raising=False)
    monkeypatch.delenv("ALERT_EMAIL", raising=False)
    monkeypatch.delenv("AWS_SNS_TOPIC_ARN", raising=False)
    monkeypatch.setenv("SES_SENDER_EMAIL", "reference-sender@example.test")
    monkeypatch.setenv("SES_RECIPIENT_EMAIL", "reference-recipient@example.test")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-south-1:123456789012:reference-topic")
    sent: dict[str, dict] = {}

    class FakeSes:
        def send_email(self, **kwargs):
            sent["SES"] = kwargs
            return {"MessageId": "ses-alias-message"}

    class FakeSns:
        def publish(self, **kwargs):
            sent["SNS"] = kwargs
            return {"MessageId": "sns-alias-message"}

    monkeypatch.setattr(main.boto3, "client", lambda service, **kwargs: FakeSes() if service == "ses" else FakeSns())
    main.init_db()
    with main.connect() as db:
        user_id = db.execute("INSERT INTO users(user_id,name,email,scenario,home_location,latitude,longitude,device_id) VALUES(?,?,?,?,?,?,?,?)", ("USER-ALIAS", "Alias User", "alias@example.test", "test", "Delhi", 28.6139, 77.209, "DEV-ALIAS")).lastrowid
        transaction_id = db.execute("INSERT INTO transactions(transaction_id,user_id,amount,transaction_date,location,latitude,longitude,device_id) VALUES(?,?,?,?,?,?,?,?)", ("TXN-ALIAS", user_id, 70000, main.now_iso(), "Delhi", 28.6139, 77.209, "DEV-ALIAS")).lastrowid
        flag_id = db.execute("INSERT INTO fraud_flags(transaction_id,risk_level,status,reason,created_at,updated_at) VALUES(?,?,?,?,?,?)", (transaction_id, "CRITICAL", "UNREVIEWED", "test", main.now_iso(), main.now_iso())).lastrowid
        transaction = db.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
        result = main.send_high_risk_notifications(db, flag_id, transaction, "<Test User>", "CRITICAL", [{"rule_name": "Amount <threshold>", "severity": "CRITICAL", "evidence": {"detail": "<unsafe>"}}])

    assert result["SES"]["status"] == "sent"
    assert result["SNS"]["status"] == "sent"
    assert sent["SES"]["Source"] == "reference-sender@example.test"
    assert sent["SES"]["Destination"]["ToAddresses"] == ["reference-recipient@example.test"]
    assert "&lt;Test User&gt;" in sent["SES"]["Message"]["Body"]["Html"]["Data"]
    assert sent["SNS"]["TopicArn"].endswith(":reference-topic")


def test_mocked_notification_retries_after_configuration_is_added(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "sentinel-retry-test.db")
    monkeypatch.delenv("AWS_SES_SENDER", raising=False)
    monkeypatch.delenv("ALERT_EMAIL", raising=False)
    monkeypatch.delenv("AWS_SNS_TOPIC_ARN", raising=False)
    main.init_db()
    with main.connect() as db:
        user_id = db.execute("INSERT INTO users(user_id,name,email,scenario,home_location,latitude,longitude,device_id) VALUES(?,?,?,?,?,?,?,?)", ("USER-RETRY", "Retry User", "retry@example.test", "test", "Mumbai", 19.076, 72.8777, "DEV-RETRY")).lastrowid
        transaction_id = db.execute("INSERT INTO transactions(transaction_id,user_id,amount,transaction_date,location,latitude,longitude,device_id) VALUES(?,?,?,?,?,?,?,?)", ("TXN-RETRY", user_id, 10000, main.now_iso(), "Mumbai", 19.076, 72.8777, "DEV-RETRY")).lastrowid
        flag_id = db.execute("INSERT INTO fraud_flags(transaction_id,risk_level,status,reason,created_at,updated_at) VALUES(?,?,?,?,?,?)", (transaction_id, "HIGH", "UNREVIEWED", "test", main.now_iso(), main.now_iso())).lastrowid
        transaction = db.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
        mocked = main.send_high_risk_notifications(db, flag_id, transaction, "Retry User", "HIGH", [])
        assert mocked["SES"]["status"] == "mocked"

        monkeypatch.setenv("AWS_SES_SENDER", "verified@example.test")
        monkeypatch.setenv("ALERT_EMAIL", "alerts@example.test")
        monkeypatch.setattr(main.boto3, "client", lambda service, **kwargs: type("Ses", (), {"send_email": lambda self, **payload: {"MessageId": "retry-message"}})())
        retried = main.send_high_risk_notifications(db, flag_id, transaction, "Retry User", "HIGH", [])

    assert retried["SES"]["status"] == "sent"