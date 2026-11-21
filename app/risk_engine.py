from datetime import datetime, timedelta
from .db import get_db


def calculate_risk(user_id, window_minutes=10):
    """Simple heuristic risk score based on recent app access events."""
    db = get_db()
    cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    failed = db.execute("""
    SELECT COUNT(*) FROM access_events
    WHERE user_id = ?
      AND decision = 'BLOCKED'
      AND created_at >= ?
""", (user_id, cutoff)).fetchone()[0]
    downloads = db.execute("""SELECT COUNT(*) FROM access_events
        WHERE user_id=? AND action='download' AND decision='ALLOWED' AND created_at >= ?""",
        (user_id, cutoff)).fetchone()[0]
    score = min(100, (25 if failed >= 3 else 0) + (30 if downloads >= 10 else 0))
    level = 'HIGH' if score >= 50 else 'MEDIUM' if score >= 25 else 'LOW'
    return score, level, {"blocked_events": failed, "recent_downloads": downloads}


def create_alert(user_id, alert_type, severity, detail):
    db = get_db()
    db.execute("INSERT INTO alerts (user_id, alert_type, severity, detail) VALUES (?, ?, ?, ?)",
               (user_id, alert_type, severity, detail))
    db.commit()
