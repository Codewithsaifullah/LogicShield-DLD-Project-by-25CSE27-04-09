
import os
import uuid

from flask import (
    Blueprint,
    current_app,
    request,
    send_file,
    render_template_string,
    url_for,
    redirect
)

from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash

from .db import get_db
from .dld_engine import evaluate_access
from .risk_engine import calculate_risk, create_alert


files = Blueprint("files", __name__)

ALLOWED_EXTENSIONS = {
    "pdf", "docx", "doc", "xlsx", "xls",
    "txt", "csv", "png", "jpg", "jpeg"
}


# --------------------------------------------------
# COMMON HELPERS
# --------------------------------------------------

def allowed_file(filename):
    return (
        bool(filename)
        and "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def log_access(database, file_id, action, decision, reason):
    database.execute(
        """
        INSERT INTO access_events
        (user_id, file_id, action, decision, reason)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            int(current_user.id),
            file_id,
            action,
            decision,
            reason
        )
    )
    database.commit()


def save_alert(user_id, alert_type, severity, detail):
    try:
        create_alert(
            user_id,
            alert_type,
            severity,
            detail
        )
    except Exception:
        current_app.logger.exception(
            "Could not create security alert"
        )


# --------------------------------------------------
# VIEW AUTHORIZED FILES
# --------------------------------------------------

@files.route("/files")
@login_required
def file_list():
    database = get_db()
    category = request.args.get("category", "").strip()
    if current_user.role == "admin":
        # Start with a WHERE clause so optional filters can safely
        # append conditions using AND.
        query = "SELECT * FROM files WHERE 1=1"
        params = []
    elif current_user.role == "teacher":
        query = "SELECT * FROM files WHERE owner_id=?"
        params = [int(current_user.id)]
    else:
        student = database.execute("SELECT department FROM student_registry WHERE id=? AND is_active=1 AND is_approved=1", (current_user.student_id,)).fetchone()
        if not student:
            return "Student profile is not approved or active.", 403
        query = "SELECT * FROM files WHERE department IN (?, 'ALL')"
        params = [student["department"]]
    if category:
        query += " AND category=?"
        params.append(category)
    query += " ORDER BY id DESC"
    records = database.execute(query, params).fetchall()
    return render_template_string("""
      <section class="ls-card"><div class="ls-row-between"><div><h2>{{heading}}</h2><p class="ls-muted">Academic resources published for your portal.</p></div>{% if current_user.role in ['admin','teacher'] %}<a class="ls-button" href="{{url_for('files.upload_file')}}">Upload content</a>{% endif %}</div>
      <div class="ls-filters"><a href="/files">All</a><a href="/files?category=study_material">Study Material</a><a href="/files?category=assignment">Assignments</a><a href="/files?category=mid_result">Mid Results</a><a href="/files?category=final_result">Final Results</a></div>
      {% if records %}<div class="ls-table-wrap"><table class="ls-table"><thead><tr><th>File</th><th>Category</th><th>Subject</th><th>Department</th><th>Term</th><th>Security</th><th>Action</th></tr></thead><tbody>{% for f in records %}<tr><td>{{f.original_name}}</td><td>{{f.category.replace('_',' ').title()}}</td><td>{{f.subject or '—'}}</td><td>{{f.department}}</td><td>{{f.term or '—'}}</td><td>{{f.sensitivity}}</td><td><a class="ls-button ls-button-small" href="{{url_for('files.download_file',file_id=f.id)}}">Open / Download</a></td></tr>{% endfor %}</tbody></table></div>{% else %}<div class="ls-empty">No content has been published here yet.</div>{% endif %}</section>
    """, records=records, heading="Academic Content" if current_user.role == "student" else "My Uploaded Content" if current_user.role == "teacher" else "All Protected Files")


# --------------------------------------------------
# UPLOAD FILE
# --------------------------------------------------

@files.route("/files/upload", methods=["GET", "POST"])
@login_required
def upload_file():

    if current_user.role not in ("admin", "teacher"):
        return "Access Denied: Upload not allowed", 403

    if request.method == "POST":

        uploaded = request.files.get("file")

        if not uploaded or not uploaded.filename:
            return "Please select a file", 400

        if not allowed_file(uploaded.filename):
            return "File type not allowed", 400

        original_name = secure_filename(uploaded.filename)

        if not original_name:
            return "Invalid filename", 400

        sensitivity = request.form.get("sensitivity", "normal").lower()
        category = request.form.get("category", "study_material")
        department = request.form.get("department", "ALL")
        subject = request.form.get("subject", "").strip()
        term = request.form.get("term", "").strip()
        description = request.form.get("description", "").strip()
        if sensitivity not in ("normal", "sensitive"):
            return "Invalid sensitivity selection", 400
        if category not in ("study_material", "assignment", "mid_result", "final_result"):
            return "Invalid academic content category", 400
        if department not in ("ALL", "COMPUTER SYSTEMS ENGINEERING", "SOFTWARE ENGINEERING"):
            return "Invalid department", 400

        storage_key = uuid.uuid4().hex

        storage_path = os.path.join(
            current_app.instance_path,
            "secure_files"
        )

        os.makedirs(storage_path, exist_ok=True)

        file_path = os.path.join(
            storage_path,
            storage_key
        )

        try:
            uploaded.save(file_path)

            database = get_db()

            database.execute(
                """
                INSERT INTO files
                (original_name, storage_key, sensitivity, owner_id, category, department, subject, term, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    original_name,
                    storage_key,
                    sensitivity,
                    int(current_user.id),
                    category,
                    department,
                    subject,
                    term,
                    description
                )
            )

            database.commit()

        except Exception:
            if os.path.exists(file_path):
                os.remove(file_path)

            current_app.logger.exception(
                "File upload failed"
            )

            return "File upload failed", 500

        return redirect(url_for("files.file_list"))

    return render_template_string("""
      <section class="ls-card"><h2>Publish Academic Content</h2><p class="ls-muted">Upload study material, assignments or examination results for a department.</p>
      <form method="post" enctype="multipart/form-data" class="ls-form">
        <label>Choose file</label><input type="file" name="file" required>
        <label>Content category</label><select name="category"><option value="study_material">Study Material</option><option value="assignment">Assignment</option><option value="mid_result">Midterm Result</option><option value="final_result">Final Result</option></select>
        <label>Target department</label><select name="department"><option value="ALL">All allowed departments</option><option value="COMPUTER SYSTEMS ENGINEERING">Computer Systems Engineering (CSE)</option><option value="SOFTWARE ENGINEERING">Software Engineering (SW)</option></select>
        <label>Subject / Course</label><input name="subject" placeholder="e.g. Digital Logic Design">
        <label>Semester / Term</label><input name="term" placeholder="e.g. Semester 3 - Fall 2026">
        <label>Description</label><textarea name="description" rows="3"></textarea>
        <label>File sensitivity</label><select name="sensitivity"><option value="normal">Normal</option><option value="sensitive">Sensitive - password verification required</option></select>
        <button class="ls-button" type="submit">Publish securely</button>
      </form></section>
    """)


# --------------------------------------------------
# DLD SECURE DOWNLOAD
# --------------------------------------------------

@files.route(
    "/files/download/<int:file_id>",
    methods=["GET", "POST"]
)
@login_required
def download_file(file_id):

    database = get_db()
    user_id = int(current_user.id)

    # Find requested file
    record = database.execute(
        "SELECT * FROM files WHERE id = ?",
        (file_id,)
    ).fetchone()

    if not record:
        return "File not found", 404

    # Check permission
    permission = database.execute(
        """
        SELECT can_read, can_download
        FROM file_permissions
        WHERE file_id = ? AND user_id = ?
        """,
        (file_id, user_id)
    ).fetchone()

    if current_user.role == "admin":
        P = True
    elif current_user.role == "student":
        student = database.execute("SELECT department,is_active,is_approved FROM student_registry WHERE id=?", (current_user.student_id,)).fetchone()
        published_for_student = bool(student and student["is_active"] == 1 and student["is_approved"] == 1 and record["department"] in (student["department"], "ALL"))
        explicitly_allowed = bool(permission and permission["can_read"] == 1 and permission["can_download"] == 1)
        P = published_for_student or explicitly_allowed
    elif permission is not None:
        P = permission["can_read"] == 1 and permission["can_download"] == 1
    else:
        P = record["owner_id"] == user_id

    A = current_user.is_authenticated
    S = record["sensitivity"] == "sensitive"

    # Permission denied
    if not P:

        log_access(
            database,
            file_id,
            "download",
            "BLOCKED",
            "Permission denied"
        )

        return "Access Denied: No download permission", 403

    # Check private file exists
    storage_path = os.path.join(
        current_app.instance_path,
        "secure_files"
    )

    path = os.path.join(
        storage_path,
        record["storage_key"]
    )

    if not os.path.isfile(path):
        return "Stored file not found", 404

    # --------------------------------------------------
    # EXTRA PASSWORD VERIFICATION
    # --------------------------------------------------

    M = False

    if S:

        if request.method == "GET":

            return render_template_string("""
                <h2>LogicShield - Sensitive File Verification</h2>

                <p>
                    This file contains sensitive information.
                </p>

                <p>
                    Re-enter your account password to continue.
                </p>

                <form method="POST">

                    <input
                        type="password"
                        name="password"
                        placeholder="Enter account password"
                        required
                        autocomplete="current-password"
                    >

                    <button type="submit">
                        Verify and Download
                    </button>

                </form>

                <p><a href="/files">Cancel</a></p>
            """)

        password = request.form.get("password", "")

        user = database.execute(
            """
            SELECT password_hash
            FROM users
            WHERE id = ? AND is_active = 1
            """,
            (user_id,)
        ).fetchone()

        if (
            user
            and check_password_hash(
                user["password_hash"],
                password
            )
        ):
            M = True

        else:

            log_access(
                database,
                file_id,
                "download",
                "BLOCKED",
                "Step-up password verification failed"
            )

            save_alert(
                user_id,
                "STEP_UP_FAILURE",
                "MEDIUM",
                "Incorrect password entered for sensitive file"
            )

            return "Access Denied: Incorrect password", 403

    # --------------------------------------------------
    # RISK ENGINE
    # --------------------------------------------------

    try:

        risk_score, risk_level, risk_details = calculate_risk(
            user_id
        )

        risk_score = int(risk_score)

        R = risk_score >= 50

        recent_downloads = int(
            risk_details.get("recent_downloads", 0)
        )

        E = recent_downloads >= 10

    except Exception:

        current_app.logger.exception(
            "Risk engine calculation failed"
        )

        # Fail closed: do not allow download if risk
        # calculation cannot be completed.
        log_access(
            database,
            file_id,
            "download",
            "BLOCKED",
            "Risk engine unavailable"
        )

        return "Access Denied: Security verification unavailable", 503

    # Create alert for suspicious activity
    if E or risk_score >= 25:

        save_alert(
            user_id,
            "SUSPICIOUS_ACTIVITY",
            risk_level,
            (
                f"Risk score: {risk_score}; "
                f"Recent downloads: {recent_downloads}; "
                f"Details: {risk_details}"
            )
        )

    # --------------------------------------------------
    # DLD BOOLEAN DECISION
    # --------------------------------------------------

    decision = evaluate_access(
        A,
        P,
        S,
        M,
        R,
        E
    )

    if not decision["ALLOW"]:

        reason = "DLD security policy denied access"

        if R:
            reason = "High risk score"

        elif E:
            reason = "Suspicious export activity"

        elif S and not M:
            reason = "Extra verification required"

        log_access(
            database,
            file_id,
            "download",
            "BLOCKED",
            reason
        )

        return "Access Denied: DLD Security Policy", 403

    # --------------------------------------------------
    # ALLOW DOWNLOAD
    # --------------------------------------------------

    log_access(
        database,
        file_id,
        "download",
        "ALLOWED",
        "DLD policy passed"
    )

    return send_file(
        path,
        as_attachment=True,
        download_name=record["original_name"]
    )


# --------------------------------------------------
# ADMIN FILE PERMISSIONS
# --------------------------------------------------

@files.route(
    "/admin/permissions",
    methods=["GET", "POST"]
)
@login_required
def manage_permissions():

    if current_user.role != "admin":
        return "Access Denied: Admin only", 403

    database = get_db()

    if request.method == "POST":

        try:
            file_id = int(request.form["file_id"])
            user_id = int(request.form["user_id"])

            can_read = int(
                request.form.get("can_read", 0)
            )

            can_download = int(
                request.form.get("can_download", 0)
            )

        except (ValueError, KeyError):
            return "Invalid permission details", 400

        if can_read not in (0, 1):
            return "Invalid read permission", 400

        if can_download not in (0, 1):
            return "Invalid download permission", 400

        if can_download == 1 and can_read == 0:
            return (
                "Download permission requires read permission",
                400
            )

        file_record = database.execute(
            "SELECT id FROM files WHERE id = ?",
            (file_id,)
        ).fetchone()

        user_record = database.execute(
            """
            SELECT id FROM users
            WHERE id = ? AND is_active = 1
            """,
            (user_id,)
        ).fetchone()

        if not file_record or not user_record:
            return "File or active user not found", 404

        database.execute(
            """
            INSERT INTO file_permissions
            (file_id, user_id, can_read, can_download)
            VALUES (?, ?, ?, ?)

            ON CONFLICT(file_id, user_id)
            DO UPDATE SET
                can_read = excluded.can_read,
                can_download = excluded.can_download
            """,
            (
                file_id,
                user_id,
                can_read,
                can_download
            )
        )

        database.commit()

        return """
            <h2>Permission saved successfully!</h2>
            <a href="/admin/permissions">Back to Permissions</a>
            """

    return """
        <h1>LogicShield - Manage File Permissions</h1>

        <form method="POST">

            <label>File ID:</label>
            <input type="number" name="file_id" required>

            <br><br>

            <label>User ID:</label>
            <input type="number" name="user_id" required>

            <br><br>

            <label>Read Permission:</label>
            <select name="can_read">
                <option value="1">Allow</option>
                <option value="0">Deny</option>
            </select>

            <br><br>

            <label>Download Permission:</label>
            <select name="can_download">
                <option value="1">Allow</option>
                <option value="0">Deny</option>
            </select>

            <br><br>

            <button type="submit">Save Permissions</button>

        </form>
        """


# --------------------------------------------------
# ADMIN AUDIT LOGS
# --------------------------------------------------

@files.route("/admin/audit-logs")
@login_required
def audit_logs():

    if current_user.role != "admin":
        return "Access Denied: Admin only", 403

    database = get_db()

    logs = database.execute(
        """
        SELECT
            access_events.id,
            users.username,
            files.original_name,
            access_events.action,
            access_events.decision,
            access_events.reason,
            access_events.created_at

        FROM access_events

        LEFT JOIN users
            ON users.id = access_events.user_id

        LEFT JOIN files
            ON files.id = access_events.file_id

        ORDER BY access_events.id DESC
        LIMIT 100
        """
    ).fetchall()

    return render_template_string("""
        <h1>LogicShield - Audit Logs</h1>

        <p>
            <a href="/dashboard">Dashboard</a> |
            <a href="/admin/alerts">Security Alerts</a>
        </p>

        <table border="1" cellpadding="8">

            <tr>
                <th>User</th>
                <th>File</th>
                <th>Action</th>
                <th>Decision</th>
                <th>Reason</th>
                <th>Date</th>
            </tr>

            {% for log in logs %}
            <tr>
                <td>{{ log.username or 'Unknown' }}</td>
                <td>{{ log.original_name or 'Unknown' }}</td>
                <td>{{ log.action }}</td>
                <td>{{ log.decision }}</td>
                <td>{{ log.reason }}</td>
                <td>{{ log.created_at }}</td>
            </tr>
            {% endfor %}

        </table>
    """, logs=logs)


# --------------------------------------------------
# ADMIN SECURITY ALERTS
# --------------------------------------------------

@files.route("/admin/alerts")
@login_required
def security_alerts():

    if current_user.role != "admin":
        return "Access Denied: Admin only", 403

    rows = get_db().execute(
        """
        SELECT
            alerts.*,
            users.username

        FROM alerts

        LEFT JOIN users
            ON users.id = alerts.user_id

        ORDER BY alerts.id DESC
        LIMIT 100
        """
    ).fetchall()

    return render_template_string("""
        <h1>LogicShield - Security Alerts</h1>

        <p>
            <a href="/dashboard">Dashboard</a> |
            <a href="/admin/audit-logs">Audit Logs</a>
        </p>

        {% if rows %}

        <table border="1" cellpadding="8">

            <tr>
                <th>User</th>
                <th>Alert Type</th>
                <th>Severity</th>
                <th>Details</th>
                <th>Date</th>
            </tr>

            {% for alert in rows %}
            <tr>
                <td>{{ alert.username or 'Unknown' }}</td>
                <td>{{ alert.alert_type }}</td>
                <td>{{ alert.severity }}</td>
                <td>{{ alert.detail }}</td>
                <td>{{ alert.created_at }}</td>
            </tr>
            {% endfor %}

        </table>

        {% else %}

        <p>No security alerts available.</p>

        {% endif %}
    """, rows=rows)
