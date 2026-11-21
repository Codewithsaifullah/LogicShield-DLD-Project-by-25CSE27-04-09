
import sqlite3

database = "instance/logicshield.sqlite"
username = "teacher_dld"

connection = sqlite3.connect(database)

cursor = connection.execute(
    """
    UPDATE users
    SET must_change_password = 1
    WHERE username = ? AND role = ?
    """,
    (username, "teacher")
)

connection.commit()

print("Updated rows:", cursor.rowcount)

connection.close()
