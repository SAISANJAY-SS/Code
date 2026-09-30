from __future__ import annotations

import json
import math
import os
import sqlite3
import boto3
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")
DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", BASE_DIR / "sentinel.db"))
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "local-demo-secret-change-before-deployment")
if os.getenv("ENVIRONMENT", "development").lower() == "production" and JWT_SECRET == "local-demo-secret-change-before-deployment":
    raise RuntimeError("JWT_SECRET_KEY must be set to a strong value in production")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="SENTINEL Fraud Investigation API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS staff (
                id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst'
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, user_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL, scenario TEXT NOT NULL, home_location TEXT NOT NULL,
                latitude REAL NOT NULL, longitude REAL NOT NULL, device_id TEXT NOT NULL,
                account_type TEXT NOT NULL DEFAULT 'personal', status TEXT NOT NULL DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY, transaction_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                amount REAL NOT NULL, currency TEXT NOT NULL DEFAULT 'INR',
                transaction_date TEXT NOT NULL, location TEXT NOT NULL, latitude REAL NOT NULL,
                longitude REAL NOT NULL, device_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rule_results (
                id INTEGER PRIMARY KEY, transaction_id INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
                rule_name TEXT NOT NULL, triggered INTEGER NOT NULL, severity TEXT NOT NULL,
                evidence TEXT NOT NULL, evaluated_at TEXT NOT NULL,
                UNIQUE(transaction_id, rule_name)
            );
            CREATE TABLE IF NOT EXISTS fraud_flags (
                id INTEGER PRIMARY KEY, transaction_id INTEGER UNIQUE NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
                risk_level TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'UNREVIEWED',
                reason TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY, transaction_id INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
                reviewer_id INTEGER NOT NULL REFERENCES staff(id), status TEXT NOT NULL,
                comment TEXT NOT NULL DEFAULT '', reviewed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY, event_type TEXT NOT NULL, user_id INTEGER,
                transaction_id INTEGER, details TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rules (
                name TEXT PRIMARY KEY, description TEXT NOT NULL, enabled INTEGER NOT NULL,
                severity TEXT NOT NULL, config TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY, fraud_flag_id INTEGER NOT NULL REFERENCES fraud_flags(id) ON DELETE CASCADE,
                channel TEXT NOT NULL, recipient TEXT NOT NULL, status TEXT NOT NULL,
                message_id TEXT, error_message TEXT, created_at TEXT NOT NULL
            );
            """
        )
        staff = db.execute("SELECT id FROM staff WHERE email = ?", ("analyst@sentinel.local",)).fetchone()
        if staff is None:
            db.execute(
                "INSERT INTO staff(email,name,password_hash,role) VALUES(?,?,?,?)",
                ("analyst@sentinel.local", "Morgan Lee", pwd_context.hash("sentinel-demo"), "analyst"),
            )
        admin = db.execute("SELECT id FROM staff WHERE email = ?", ("admin@sentinel.local",)).fetchone()
        if admin is None:
            db.execute(
                "INSERT INTO staff(email,name,password_hash,role) VALUES(?,?,?,?)",
                ("admin@sentinel.local", "Sentinel Administrator", pwd_context.hash("sentinel-admin"), "admin"),
            )
        rule_defaults = [
            ("Transaction Velocity", "Detect unusually high transaction frequency in a rolling window", 1, "HIGH", {"time_window_minutes": 5, "max_transactions": 5}),
            ("Unusual Transaction Amount", "Compare an amount with the user's historical median", 1, "MEDIUM", {"baseline_method": "median", "deviation_multiplier": 2.0}),
            ("Impossible Geography", "Detect implausibly fast travel between transaction locations", 1, "HIGH", {"max_plausible_speed_kmh": 900}),
        ]
        for name, description, enabled, severity, config in rule_defaults:
            db.execute("INSERT OR IGNORE INTO rules VALUES(?,?,?,?,?)", (name, description, enabled, severity, json.dumps(config)))


def audit(db: sqlite3.Connection, event: str, details: dict[str, Any], transaction_id: int | None = None, user_id: int | None = None) -> None:
    db.execute(
        "INSERT INTO audit_logs(event_type,user_id,transaction_id,details,status,created_at) VALUES(?,?,?,?,?,?)",
        (event, user_id, transaction_id, json.dumps(details), "success", now_iso()),
    )


def send_high_risk_email(
    db: sqlite3.Connection,
    flag_id: int,
    transaction: sqlite3.Row,
    user_name: str,
    risk: str,
    triggered: list[dict[str, Any]],
) -> dict[str, str]:
    sender = os.getenv("AWS_SES_SENDER", "")
    recipient = os.getenv("ALERT_EMAIL", "")
    region = os.getenv("AWS_REGION", "ap-south-1")
    prior = db.execute(
        "SELECT status FROM notifications WHERE fraud_flag_id=? ORDER BY id DESC LIMIT 1",
        (flag_id,),
    ).fetchone()
    if prior and prior["status"] in {"sent", "mocked"}:
        return {"status": prior["status"]}

    rule_lines = "\n".join(
        f"- {result['rule_name']} ({result['severity']}): {json.dumps(result['evidence'], ensure_ascii=True)}"
        for result in triggered
    )
    subject = f"[{risk}] SENTINEL fraud alert: {transaction['transaction_id']}"
    body = (
        "SENTINEL detected a high-risk transaction.\n\n"
        f"Risk: {risk}\nTransaction: {transaction['transaction_id']}\n"
        f"Profile: {user_name}\nAmount: {transaction['currency']} {transaction['amount']:,.2f}\n"
        f"Location: {transaction['location']}\nTime: {transaction['transaction_date']}\n\n"
        f"Triggered evidence:\n{rule_lines}\n"
    )
    status = "mocked"
    message_id = None
    error_message = None
    if sender and recipient:
        try:
            ses = boto3.client("ses", region_name=region)
            response = ses.send_email(
                Source=sender,
                Destination={"ToAddresses": [recipient]},
                Message={
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
                },
            )
            status = "sent"
            message_id = response.get("MessageId")
        except Exception as error:  # AWS errors are recorded without exposing credentials.
            status = "failed"
            error_message = type(error).__name__
    db.execute(
        "INSERT INTO notifications(fraud_flag_id,channel,recipient,status,message_id,error_message,created_at) VALUES(?,?,?,?,?,?,?)",
        (flag_id, "SES", recipient or "development-mock", status, message_id, error_message, now_iso()),
    )
    return {"status": status, "error": error_message or ""}


def current_staff(token: str = Depends(oauth_scheme)) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        staff_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    with connect() as db:
        staff = db.execute("SELECT id,email,name,role FROM staff WHERE id=?", (staff_id,)).fetchone()
    if staff is None:
        raise HTTPException(status_code=401, detail="Session no longer exists")
    return dict(staff)


class LoginRequest(BaseModel):
    email: str
    password: str


class ReviewRequest(BaseModel):
    status: str
    comment: str = Field(default="", max_length=1000)


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    config: dict[str, Any] | None = None


def risk_level(results: list[dict[str, Any]]) -> str:
    triggered = [result for result in results if result["triggered"]]
    if not triggered:
        return "LOW"
    if any(result["severity"] == "CRITICAL" for result in triggered):
        return "CRITICAL"
    if len(triggered) > 1 or any(result["severity"] == "HIGH" for result in triggered):
        return "HIGH"
    return "MEDIUM"


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radians = math.pi / 180
    delta_lat = (lat2 - lat1) * radians
    delta_lon = (lon2 - lon1) * radians
    a = math.sin(delta_lat / 2) ** 2 + math.cos(lat1 * radians) * math.cos(lat2 * radians) * math.sin(delta_lon / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(a))


def evaluate_rules(transaction: sqlite3.Row, history: list[sqlite3.Row], active_rules: list[sqlite3.Row]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    current_date = datetime.fromisoformat(transaction["transaction_date"])
    for rule in active_rules:
        config = json.loads(rule["config"])
        evidence: dict[str, Any]
        triggered = False
        if rule["name"] == "Transaction Velocity":
            window_minutes = int(config["time_window_minutes"])
            start = current_date - timedelta(minutes=window_minutes)
            prior = [item for item in history if start <= datetime.fromisoformat(item["transaction_date"]) < current_date]
            count = len(prior) + 1
            triggered = count > int(config["max_transactions"])
            evidence = {
                "transaction_count_in_window": count,
                "time_window_minutes": window_minutes,
                "configured_threshold": int(config["max_transactions"]),
                "relevant_transaction_ids": [item["transaction_id"] for item in prior] + [transaction["transaction_id"]],
            }
        elif rule["name"] == "Unusual Transaction Amount":
            amounts = [float(item["amount"]) for item in history]
            if amounts:
                baseline = median(amounts)
                deviation = float(transaction["amount"]) / baseline if baseline else float("inf")
                threshold = float(config["deviation_multiplier"])
                triggered = deviation > threshold
                evidence = {
                    "current_amount": float(transaction["amount"]), "historical_baseline": baseline,
                    "baseline_method": config["baseline_method"], "deviation_multiplier": threshold,
                    "actual_deviation": round(deviation, 2), "configured_threshold": threshold,
                    "transaction_count_in_history": len(amounts),
                }
            else:
                evidence = {"reason": "insufficient_history", "transaction_count": 0}
        else:
            if history:
                previous = history[-1]
                previous_date = datetime.fromisoformat(previous["transaction_date"])
                distance = haversine(float(previous["latitude"]), float(previous["longitude"]), float(transaction["latitude"]), float(transaction["longitude"]))
                minutes = (current_date - previous_date).total_seconds() / 60
                speed = distance / (minutes / 60) if minutes > 0 else float("inf")
                max_speed = float(config["max_plausible_speed_kmh"])
                triggered = speed > max_speed
                evidence = {
                    "previous_location": previous["location"], "previous_timestamp": previous["transaction_date"],
                    "previous_latitude": float(previous["latitude"]), "previous_longitude": float(previous["longitude"]),
                    "current_location": transaction["location"], "current_timestamp": transaction["transaction_date"],
                    "current_latitude": float(transaction["latitude"]), "current_longitude": float(transaction["longitude"]),
                    "distance_km": round(distance, 2), "time_difference_minutes": round(minutes, 2),
                    "required_speed_kmh": round(speed, 2), "max_plausible_speed_kmh": max_speed,
                }
            else:
                evidence = {"reason": "no_previous_transaction"}
        results.append({
            "rule_name": rule["name"], "triggered": triggered,
            "severity": rule["severity"] if triggered else "LOW", "evidence": evidence,
            "evaluated_at": now_iso(),
        })
    return results


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    init_db()
    return {"status": "ok", "service": "SENTINEL"}


@app.post("/auth/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    init_db()
    with connect() as db:
        staff = db.execute("SELECT * FROM staff WHERE email=?", (payload.email.lower(),)).fetchone()
        if staff is None or not pwd_context.verify(payload.password, staff["password_hash"]):
            raise HTTPException(status_code=401, detail="Email or password is incorrect")
        audit(db, "login", {"email": staff["email"]}, user_id=staff["id"])
        token = jwt.encode({"sub": str(staff["id"]), "exp": datetime.now(timezone.utc) + timedelta(hours=1)}, JWT_SECRET, algorithm="HS256")
        return {"access_token": token, "token_type": "bearer", "user": {"id": staff["id"], "email": staff["email"], "name": staff["name"], "role": staff["role"]}}


@app.get("/auth/me")
def me(staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    return staff


@app.post("/auth/logout", status_code=204)
def logout(staff: dict[str, Any] = Depends(current_staff)) -> None:
    with connect() as db:
        audit(db, "logout", {}, user_id=staff["id"])


@app.post("/demo/generate")
def generate_demo(staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    names = [
        ("USER-001", "Aarav Mehta", "aarav@example.test", "normal", "Mumbai", 19.076, 72.8777),
        ("USER-002", "Diya Kapoor", "diya@example.test", "high_amount", "Delhi", 28.6139, 77.209),
        ("USER-003", "Ishaan Rao", "ishaan@example.test", "high_velocity", "Bengaluru", 12.9716, 77.5946),
        ("USER-004", "Mira Shah", "mira@example.test", "impossible_travel", "Mumbai", 19.076, 72.8777),
        ("USER-005", "Kabir Nair", "kabir@example.test", "multiple_signals", "Chennai", 13.0827, 80.2707),
    ]
    with connect() as db:
        db.execute("DELETE FROM users")
        user_ids: dict[str, int] = {}
        for user_id, name, email, scenario, home, lat, lon in names:
            cursor = db.execute("INSERT INTO users(user_id,name,email,scenario,home_location,latitude,longitude,device_id) VALUES(?,?,?,?,?,?,?,?)", (user_id, name, email, scenario, home, lat, lon, f"DEV-{user_id[-3:]}"))
            user_ids[scenario] = cursor.lastrowid
        base = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(days=2)
        city_coords = {"Mumbai": (19.076, 72.8777), "Delhi": (28.6139, 77.209), "Bengaluru": (12.9716, 77.5946), "Chennai": (13.0827, 80.2707)}
        transaction_number = 10001
        for scenario, user_pk in user_ids.items():
            for index in range(12):
                dt = base + timedelta(hours=index * 4 + 1)
                amount = [3200, 4500, 5200, 6100, 3900, 7200, 4800, 5600, 4300, 6700, 5100, 3800][index]
                location = "Mumbai"
                lat, lon = city_coords[location]
                if scenario == "high_amount" and index >= 5:
                    amount = 54000 + index * 5700
                if scenario == "high_velocity" and index >= 4:
                    dt = base + timedelta(hours=2, minutes=(index - 4) * 0.6)
                    amount = 3900 + index * 180
                if scenario == "impossible_travel" and index >= 4:
                    location = "Mumbai" if index % 2 == 0 else "Delhi"
                    lat, lon = city_coords[location]
                    dt = base + timedelta(hours=2, minutes=(index - 4) * 5)
                if scenario == "multiple_signals" and index >= 4:
                    location = "Mumbai" if index % 2 == 0 else "Delhi"
                    lat, lon = city_coords[location]
                    dt = base + timedelta(hours=2, minutes=(index - 4) * 0.6)
                    amount = 65000 + index * 2600
                if scenario == "normal":
                    lat += ((index % 3) - 1) * 0.008
                    lon += ((index % 2) - 0.5) * 0.008
                db.execute("INSERT INTO transactions(transaction_id,user_id,amount,transaction_date,location,latitude,longitude,device_id) VALUES(?,?,?,?,?,?,?,?)", (f"TXN-{transaction_number}", user_pk, amount, dt.isoformat(), location, lat, lon, f"DEV-{scenario[:3].upper()}"))
                transaction_number += 1
        audit(db, "transactions_generated", {"users": 5, "transactions": 60}, user_id=staff["id"])
    return {"generated_users": 5, "generated_transactions": 60}


@app.get("/dashboard/overview")
def overview(staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    with connect() as db:
        totals = db.execute("SELECT (SELECT COUNT(*) FROM users) users,(SELECT COUNT(*) FROM transactions) transactions,(SELECT COUNT(*) FROM fraud_flags WHERE status!='CLEARED') flagged,(SELECT COUNT(*) FROM fraud_flags WHERE risk_level IN ('HIGH','CRITICAL') AND status!='CLEARED') high_critical").fetchone()
        risk_rows = db.execute("SELECT risk_level,COUNT(*) count FROM fraud_flags GROUP BY risk_level").fetchall()
        trend = db.execute("SELECT substr(transaction_date,1,10) day,COUNT(*) count,ROUND(AVG(amount),2) amount FROM transactions GROUP BY day ORDER BY day").fetchall()
        return {"total_users": totals["users"], "total_transactions": totals["transactions"], "flagged_transactions": totals["flagged"], "high_critical_risk": totals["high_critical"], "risk_distribution": [dict(row) for row in risk_rows], "activity_graph_data": [dict(row) for row in trend]}


@app.get("/users")
def list_users(search: str = "", staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    with connect() as db:
        rows = db.execute("""SELECT u.*,COUNT(DISTINCT t.id) transaction_count,COUNT(DISTINCT CASE WHEN f.status!='CLEARED' THEN f.id END) flagged_count,MAX(t.transaction_date) last_transaction_date FROM users u LEFT JOIN transactions t ON t.user_id=u.id LEFT JOIN fraud_flags f ON f.transaction_id=t.id WHERE u.user_id LIKE ? OR u.name LIKE ? OR u.email LIKE ? GROUP BY u.id ORDER BY u.user_id""", tuple([f"%{search}%"] * 3)).fetchall()
        return {"data": [dict(row) for row in rows], "total": len(rows)}


@app.get("/transactions")
def list_transactions(user_id: str = "", risk_level: str = "", status: str = "", limit: int = 100, staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    limit = min(max(limit, 1), 500)
    with connect() as db:
        query = """SELECT t.*,u.user_id,u.name user_name,f.risk_level,f.status flag_status,COUNT(rr.id) triggered_rule_count FROM transactions t JOIN users u ON u.id=t.user_id LEFT JOIN fraud_flags f ON f.transaction_id=t.id LEFT JOIN rule_results rr ON rr.transaction_id=t.id AND rr.triggered=1 WHERE 1=1"""
        params: list[Any] = []
        if user_id:
            query += " AND u.user_id=?"; params.append(user_id)
        if risk_level:
            query += " AND f.risk_level=?"; params.append(risk_level)
        if status:
            query += " AND f.status=?"; params.append(status)
        query += " GROUP BY t.id ORDER BY t.transaction_date DESC LIMIT ?"; params.append(limit)
        rows = db.execute(query, params).fetchall()
        return {"data": [dict(row) for row in rows], "total": len(rows)}


@app.post("/analysis/run/{user_id}")
def analyze_user(user_id: str, staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    with connect() as db:
        user = db.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        active_rules = db.execute("SELECT * FROM rules WHERE enabled=1").fetchall()
        transactions = db.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY transaction_date,id", (user["id"],)).fetchall()
        results_by_tx: dict[int, list[dict[str, Any]]] = {}
        for index, transaction in enumerate(transactions):
            results = evaluate_rules(transaction, transactions[:index], active_rules)
            results_by_tx[transaction["id"]] = results
            db.execute("DELETE FROM rule_results WHERE transaction_id=?", (transaction["id"],))
            for result in results:
                db.execute("INSERT INTO rule_results(transaction_id,rule_name,triggered,severity,evidence,evaluated_at) VALUES(?,?,?,?,?,?)", (transaction["id"], result["rule_name"], int(result["triggered"]), result["severity"], json.dumps(result["evidence"]), result["evaluated_at"]))
            triggered = [result for result in results if result["triggered"]]
            if triggered:
                level = risk_level(results)
                existing = db.execute("SELECT status,created_at FROM fraud_flags WHERE transaction_id=?", (transaction["id"],)).fetchone()
                status = existing["status"] if existing else "UNREVIEWED"
                created = existing["created_at"] if existing else now_iso()
                db.execute("""INSERT INTO fraud_flags(transaction_id,risk_level,status,reason,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(transaction_id) DO UPDATE SET risk_level=excluded.risk_level,reason=excluded.reason,updated_at=excluded.updated_at""", (transaction["id"], level, status, f"{len(triggered)} rule(s) triggered", created, now_iso()))
                flag = db.execute("SELECT id FROM fraud_flags WHERE transaction_id=?", (transaction["id"],)).fetchone()
                if level in {"HIGH", "CRITICAL"}:
                    notification = send_high_risk_email(db, flag["id"], transaction, user["name"], level, triggered)
                    if notification["status"] == "sent":
                        audit(db, "notification_sent", {"channel": "SES", "status": "sent", "risk_level": level}, transaction["id"], staff["id"])
                    elif notification["status"] == "failed":
                        audit(db, "notification_failed", {"channel": "SES", "error": notification["error"]}, transaction["id"], staff["id"])
            else:
                db.execute("DELETE FROM fraud_flags WHERE transaction_id=? AND status='UNREVIEWED'", (transaction["id"],))
        triggered_count = sum(sum(1 for result in results if result["triggered"]) for results in results_by_tx.values())
        flag_count = db.execute("SELECT COUNT(*) FROM fraud_flags f JOIN transactions t ON t.id=f.transaction_id WHERE t.user_id=?", (user["id"],)).fetchone()[0]
        notification_counts = db.execute("SELECT n.status,COUNT(*) count FROM notifications n JOIN fraud_flags f ON f.id=n.fraud_flag_id JOIN transactions t ON t.id=f.transaction_id WHERE t.user_id=? GROUP BY n.status", (user["id"],)).fetchall()
        audit(db, "fraud_analysis_executed", {"user_id": user_id, "transactions_analyzed": len(transactions), "triggered_rule_results": triggered_count, "flags": flag_count}, user_id=staff["id"])
        return {"user_id": user_id, "transactions_analyzed": len(transactions), "triggered_rule_results": triggered_count, "flagged_transactions": flag_count, "notifications": {row["status"]: row["count"] for row in notification_counts}}


@app.get("/fraud-alerts")
def alerts(risk_level: str = "", status: str = "", user_id: str = "", staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    with connect() as db:
        query = """SELECT f.id fraud_flag_id,t.id transaction_pk,t.transaction_id,u.user_id,u.name user_name,t.amount,t.currency,t.transaction_date,t.location,t.latitude,t.longitude,t.device_id,f.risk_level,f.status,f.reason,f.created_at, GROUP_CONCAT(rr.rule_name, '|||') triggered_rules FROM fraud_flags f JOIN transactions t ON t.id=f.transaction_id JOIN users u ON u.id=t.user_id LEFT JOIN rule_results rr ON rr.transaction_id=t.id AND rr.triggered=1 WHERE 1=1"""
        params: list[Any] = []
        if risk_level:
            query += " AND f.risk_level=?"; params.append(risk_level)
        if status:
            query += " AND f.status=?"; params.append(status)
        if user_id:
            query += " AND u.user_id=?"; params.append(user_id)
        query += " GROUP BY f.id ORDER BY CASE f.risk_level WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,f.created_at DESC"
        rows = db.execute(query, params).fetchall()
        values = []
        for row in rows:
            item = dict(row)
            item["triggered_rules"] = item["triggered_rules"].split("|||") if item["triggered_rules"] else []
            values.append(item)
        return {"data": values, "total": len(values)}


@app.get("/transactions/{transaction_id}/analysis")
def transaction_analysis(transaction_id: str, staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    with connect() as db:
        transaction = db.execute("SELECT t.*,u.user_id business_user_id,u.name user_name,f.risk_level,f.status flag_status,f.id fraud_flag_id FROM transactions t JOIN users u ON u.id=t.user_id LEFT JOIN fraud_flags f ON f.transaction_id=t.id WHERE t.transaction_id=?", (transaction_id,)).fetchone()
        if transaction is None:
            raise HTTPException(status_code=404, detail="Transaction not found")
        results = db.execute("SELECT rule_name,triggered,severity,evidence,evaluated_at FROM rule_results WHERE transaction_id=? ORDER BY id", (transaction["id"],)).fetchall()
        history = db.execute("SELECT transaction_id,transaction_date,location,latitude,longitude,amount FROM transactions WHERE user_id=? AND transaction_date<? ORDER BY transaction_date DESC LIMIT 8", (transaction["user_id"], transaction["transaction_date"])).fetchall()
        notifications = db.execute("SELECT n.channel,n.status,n.recipient,n.created_at,n.error_message FROM notifications n JOIN fraud_flags f ON f.id=n.fraud_flag_id WHERE f.transaction_id=? ORDER BY n.created_at DESC", (transaction["id"],)).fetchall()
        transaction_data = dict(transaction)
        transaction_data["user_id"] = transaction_data.pop("business_user_id")
        return {"transaction": transaction_data, "rule_results": [{**dict(row), "triggered": bool(row["triggered"]), "evidence": json.loads(row["evidence"])} for row in results], "history": [dict(row) for row in reversed(history)], "notifications": [dict(row) for row in notifications]}


@app.post("/transactions/{transaction_id}/review")
def review_transaction(transaction_id: str, payload: ReviewRequest, staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    if payload.status not in {"REVIEWED", "CLEARED"}:
        raise HTTPException(status_code=422, detail="Status must be REVIEWED or CLEARED")
    with connect() as db:
        transaction = db.execute("SELECT id FROM transactions WHERE transaction_id=?", (transaction_id,)).fetchone()
        if transaction is None:
            raise HTTPException(status_code=404, detail="Transaction not found")
        flag = db.execute("SELECT id FROM fraud_flags WHERE transaction_id=?", (transaction["id"],)).fetchone()
        if flag is None:
            raise HTTPException(status_code=409, detail="Transaction has no fraud flag")
        stamp = now_iso()
        cursor = db.execute("INSERT INTO reviews(transaction_id,reviewer_id,status,comment,reviewed_at) VALUES(?,?,?,?,?)", (transaction["id"], staff["id"], payload.status, payload.comment, stamp))
        db.execute("UPDATE fraud_flags SET status=?,updated_at=? WHERE transaction_id=?", (payload.status, stamp, transaction["id"]))
        audit(db, "transaction_cleared" if payload.status == "CLEARED" else "transaction_reviewed", {"status": payload.status, "comment": payload.comment}, transaction["id"], staff["id"])
        return {"id": cursor.lastrowid, "transaction_id": transaction_id, "reviewer": staff["name"], "status": payload.status, "comment": payload.comment, "reviewed_at": stamp}


@app.get("/rules")
def get_rules(staff: dict[str, Any] = Depends(current_staff)) -> list[dict[str, Any]]:
    with connect() as db:
        return [{**dict(row), "enabled": bool(row["enabled"]), "config": json.loads(row["config"])} for row in db.execute("SELECT * FROM rules ORDER BY name")]


@app.put("/rules/{rule_name}")
def update_rule(rule_name: str, payload: RuleUpdate, staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    if staff["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    with connect() as db:
        rule = db.execute("SELECT * FROM rules WHERE name=?", (rule_name,)).fetchone()
        if rule is None:
            raise HTTPException(status_code=404, detail="Rule not found")
        config = json.loads(rule["config"])
        if payload.config:
            config.update(payload.config)
        enabled = int(payload.enabled if payload.enabled is not None else rule["enabled"])
        db.execute("UPDATE rules SET enabled=?,config=? WHERE name=?", (enabled, json.dumps(config), rule_name))
        audit(db, "rule_updated", {"rule_name": rule_name, "enabled": bool(enabled), "config": config}, user_id=staff["id"])
        return {"name": rule_name, "enabled": bool(enabled), "config": config}


@app.get("/activity")
def activity(limit: int = 100, staff: dict[str, Any] = Depends(current_staff)) -> dict[str, Any]:
    if staff["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    with connect() as db:
        rows = db.execute("SELECT a.*,s.name staff_name,t.transaction_id FROM audit_logs a LEFT JOIN staff s ON s.id=a.user_id LEFT JOIN transactions t ON t.id=a.transaction_id ORDER BY a.created_at DESC LIMIT ?", (min(max(limit, 1), 500),)).fetchall()
        return {"data": [{**dict(row), "details": json.loads(row["details"])} for row in rows], "total": len(rows)}


init_db()