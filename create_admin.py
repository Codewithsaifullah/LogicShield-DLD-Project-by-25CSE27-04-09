
from app import create_app
from app.db import get_db
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    db = get_db()

    accounts = [
        ("admin", "Admin@12345", "admin"),
        ("teacher", "Teacher@12345", "teacher"),
    ]

    for username, password, role in accounts:
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing:
            print(f"{username} already exists")
            continue

        db.execute(
            """
            INSERT INTO users
            (username, password_hash, role, is_active)
            VALUES (?, ?, ?, 1)
            """,
            (
                username,
                generate_password_hash(password),
                role
            )
        )

        print(f"{username} account created")

    db.commit()
    print("Account setup completed!")
