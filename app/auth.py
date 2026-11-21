import os
import uuid
from flask import Blueprint, request, redirect, url_for, render_template_string, current_app, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from .db import get_db
from .ocr_service import extract_student_details
from .student_verification import verify_student

login_manager = LoginManager()
login_manager.login_view = "auth.login"
auth = Blueprint("auth", __name__)

DEPARTMENTS = {
    "CSE": "COMPUTER SYSTEMS ENGINEERING",
    "SW": "SOFTWARE ENGINEERING",
}

class User(UserMixin):
    def __init__(self, row):
        self.id = str(row["id"])
        self.username = row["username"]
        self.role = row["role"]
        self.student_id = row["student_id"]
        self.must_change_password = bool(row["must_change_password"]) if "must_change_password" in row.keys() else False

@login_manager.user_loader
def load_user(user_id):
    user = get_db().execute("SELECT * FROM users WHERE id=? AND is_active=1", (user_id,)).fetchone()
    return User(user) if user else None

@auth.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        selected_role = request.form.get("role", "").lower()
        account = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        valid = bool(account and account["is_active"] == 1
                     and account["role"] == selected_role
                     and check_password_hash(account["password_hash"], password))

        if valid and account["role"] == "student":
            session.pop("pending_student_verification_user_id", None)
            session["pending_student_verification_user_id"] = int(account["id"])
            return redirect(url_for("auth.verify_student_login"))

        if valid:
            session.pop("student_card_verified", None)
            db.execute("""INSERT INTO access_events
                (user_id,file_id,action,decision,reason)
                VALUES (?,NULL,'login','ALLOWED','Successful staff login')""", (account["id"],))
            db.commit()
            login_user(User(account), fresh=True)
            if account["role"] == "teacher" and bool(account["must_change_password"]):
                return redirect(url_for("auth.change_password"))
            return redirect(url_for("auth.dashboard"))

        db.execute("""INSERT INTO access_events
            (user_id,file_id,action,decision,reason)
            VALUES (?,NULL,'login','BLOCKED',?)""",
            (account["id"] if account else None,
             "Invalid credentials, role mismatch, or account pending approval"))
        db.commit()
        error = "Login failed. Check your role and credentials. Student accounts must be approved first."

    return render_template_string('''
    <section class="ls-card ls-auth-card"><div class="ls-eyebrow">SECURE SIGN IN</div><h2>Welcome to LogicShield</h2><p>Select your portal and sign in.</p>
    {% if error %}<div class="ls-alert">{{error}}</div>{% endif %}
    <form method="post" class="ls-form">
      <label>Login as</label><select name="role" required><option value="">Choose portal</option><option value="admin">Admin</option><option value="teacher">Teacher</option><option value="student">Student</option></select>
      <label>Username</label><input name="username" autocomplete="username" required>
      <label>Password</label><input type="password" name="password" autocomplete="current-password" required>
      <button class="ls-button" type="submit">Sign in securely</button>
    </form>
    <p class="ls-muted">Student login also requires a fresh enrollment-card scan.</p>
    <p class="ls-muted">New student? <a href="{{url_for('auth.student_register')}}">Create a student account</a></p></section>
    ''', error=error)


@auth.route("/student/verify-login", methods=["GET", "POST"])
def verify_student_login():
    # Require a fresh enrollment-card OCR check for every student login.
    pending_id = session.get("pending_student_verification_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    db = get_db()
    account = db.execute("""SELECT u.*, s.enrollment_number, s.department,
                  s.is_active AS student_active, s.is_approved
           FROM users u JOIN student_registry s ON s.id = u.student_id
           WHERE u.id = ? AND u.role = 'student'""", (pending_id,)).fetchone()

    if (not account or account["is_active"] != 1
            or account["student_active"] != 1 or account["is_approved"] != 1):
        session.pop("pending_student_verification_user_id", None)
        return redirect(url_for("auth.login"))

    message = ""
    if request.method == "POST":
        card = request.files.get("card_image")
        if not card or not card.filename:
            message = "Please select your enrollment card image."
        elif not card.filename.lower().endswith((".jpg", ".jpeg", ".png")):
            message = "Only JPG and PNG images are accepted."
        else:
            os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
            temp_name = uuid.uuid4().hex + "_" + secure_filename(card.filename)
            temp_path = os.path.join(current_app.config["UPLOAD_FOLDER"], temp_name)
            try:
                card.save(temp_path)
                details = extract_student_details(temp_path)
                scanned_enrollment = (details.get("enrollment_number") or "").strip().upper()
                scanned_department = (details.get("department") or "").strip().upper()
                expected_enrollment = account["enrollment_number"].strip().upper()
                expected_department = account["department"].strip().upper()

                if not scanned_enrollment or not scanned_department:
                    message = "Could not read both details. Upload a clear, front-facing card image."
                elif scanned_enrollment != expected_enrollment or scanned_department != expected_department:
                    db.execute("""INSERT INTO access_events
                        (user_id,file_id,action,decision,reason)
                        VALUES (?,NULL,'student_card_login','BLOCKED',
                                'Enrollment card OCR did not match registered student')""", (pending_id,))
                    db.commit()
                    message = "Card verification failed. The card details do not match this student account."
                else:
                    db.execute("""INSERT INTO access_events
                        (user_id,file_id,action,decision,reason)
                        VALUES (?,NULL,'student_card_login','ALLOWED',
                                'Enrollment card OCR matched registered student')""", (pending_id,))
                    db.commit()
                    session.pop("pending_student_verification_user_id", None)
                    session["student_card_verified"] = True
                    login_user(User(account), fresh=True)
                    return redirect(url_for("auth.dashboard"))
            except Exception:
                current_app.logger.exception("Student login card verification failed")
                message = "Card verification could not be completed. Please try again."
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

    return render_template_string('''
    <section class="ls-card ls-auth-card">
      <div class="ls-eyebrow">SECOND-FACTOR IDENTITY CHECK</div>
      <h2>Verify your student identity</h2>
      <p>Upload the front of the university enrollment card registered to your account.</p>
      <div class="ls-alert">Login completes only when OCR reads an exact enrollment number and department match.</div>
      {% if message %}<div class="ls-alert">{{message}}</div>{% endif %}
      <form method="post" enctype="multipart/form-data" class="ls-form">
        <label>Enrollment card image (JPG/PNG)</label>
        <input type="file" name="card_image" accept=".jpg,.jpeg,.png" required>
        <button class="ls-button" type="submit">Scan card and complete login</button>
      </form>
      <p class="ls-muted"><a href="{{url_for('auth.login')}}">Cancel and return to login</a></p>
    </section>
    ''', message=message)


@auth.before_app_request
def require_card_verification_for_student_sessions():
    # Force old student sessions to authenticate again with a card scan.
    if current_user.is_authenticated and current_user.role == "student":
        if not session.get("student_card_verified"):
            logout_user()
            session.pop("pending_student_verification_user_id", None)
            return redirect(url_for("auth.login"))


@auth.route("/teacher/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if current_user.role != "teacher":
        return redirect(url_for("auth.dashboard"))
    db = get_db()
    account = db.execute("SELECT must_change_password FROM users WHERE id=?", (int(current_user.id),)).fetchone()
    if not account or not account["must_change_password"]:
        return redirect(url_for("auth.dashboard"))
    message = ""
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        row = db.execute("SELECT password_hash FROM users WHERE id=?", (int(current_user.id),)).fetchone()
        if not row or not check_password_hash(row["password_hash"], current_password):
            message = "Current temporary password is incorrect."
        elif len(new_password) < 10:
            message = "New password must contain at least 10 characters."
        elif new_password == current_password:
            message = "Choose a new password different from the temporary password."
        elif new_password != confirm_password:
            message = "New password and confirmation do not match."
        else:
            db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                       (generate_password_hash(new_password), int(current_user.id)))
            db.execute("INSERT INTO audit_logs (actor_id,action,target,result) VALUES (?,?,?,?)",
                       (int(current_user.id), "TEACHER_PASSWORD_CHANGED", current_user.username, "SUCCESS"))
            db.commit()
            return redirect(url_for("auth.dashboard"))
    return render_template_string('''
    <section class="ls-card ls-auth-card">
      <div class="ls-eyebrow">ACCOUNT SECURITY · REQUIRED ACTION</div>
      <h2>Change your temporary password</h2>
      <p>You must choose a new password before accessing the Teacher Portal.</p>
      {% if message %}<div class="ls-alert" role="alert">{{message}}</div>{% endif %}
      <form method="post" class="ls-form">
        <label>Current temporary password</label><input type="password" name="current_password" autocomplete="current-password" required>
        <label>New password (at least 10 characters)</label><input type="password" name="new_password" minlength="10" autocomplete="new-password" required>
        <label>Confirm new password</label><input type="password" name="confirm_password" minlength="10" autocomplete="new-password" required>
        <button class="ls-button" type="submit">Save new password</button>
      </form>
      <p class="ls-muted"><a href="{{url_for('auth.logout')}}">Sign out</a></p>
    </section>
    ''', message=message)


@auth.before_app_request
def require_teacher_password_change():
    if not current_user.is_authenticated or current_user.role != "teacher":
        return None
    if request.endpoint in ("auth.change_password", "auth.logout", "static"):
        return None
    row = get_db().execute("SELECT must_change_password FROM users WHERE id=?",
                           (int(current_user.id),)).fetchone()
    if row and row["must_change_password"]:
        return redirect(url_for("auth.change_password"))
    return None


@auth.route("/student/register", methods=["GET", "POST"])
def student_register():
    db = get_db()
    message = ""
    message_type = "error"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        enrollment = request.form.get("enrollment_number", "").strip().upper()
        selected_department_code = request.form.get("department", "").strip().upper()
        selected_department = DEPARTMENTS.get(selected_department_code)
        card = request.files.get("card_image")

        if (not username or len(password) < 8 or not enrollment
                or not selected_department or not card or not card.filename):
            message = "Complete all fields, select a valid department, and use a password of at least 8 characters."
        elif db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            message = "This username is already taken. Choose another username."
        elif not card.filename.lower().endswith((".jpg", ".jpeg", ".png")):
            message = "Upload a JPG or PNG enrollment card image."
        else:
            os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
            temp_name = uuid.uuid4().hex + "_" + secure_filename(card.filename)
            temp_path = os.path.join(current_app.config["UPLOAD_FOLDER"], temp_name)
            try:
                card.save(temp_path)
                details = extract_student_details(temp_path)
                scanned_enrollment = (details.get("enrollment_number") or "").strip().upper()
                scanned_department = (details.get("department") or "").strip().upper()
                detected_label = (details.get("detected_department_label") or "").strip().upper()

                if not scanned_enrollment:
                    message = "We could not read the enrollment number from your card. Upload a clearer front-side image."
                elif not scanned_department:
                    label = detected_label or "an unsupported or unreadable department"
                    message = (f"Registration cannot continue: your card appears to show {label}, "
                               "but LogicShield only accepts Computer Systems Engineering (CSE) "
                               "and Software Engineering (SW). No Admin request was created.")
                elif scanned_enrollment != enrollment:
                    message = ("Enrollment number mismatch: the number you entered does not match "
                               "the number read from your card. No Admin request was created.")
                elif scanned_department != selected_department:
                    message = (f"Department mismatch: you selected {selected_department}, but your card "
                               f"shows {scanned_department}. You cannot create this account with these details. "
                               "No Admin request was created.")
                else:
                    expected_suffix = "-CSE" if selected_department_code == "CSE" else "-SW"
                    if not enrollment.endswith(expected_suffix):
                        message = (f"Enrollment format mismatch: the selected department requires an "
                                   f"enrollment number ending in {expected_suffix}. No Admin request was created.")
                    else:
                        existing_student = db.execute(
                            "SELECT * FROM student_registry WHERE enrollment_number=?",
                            (enrollment,)
                        ).fetchone()
                        if existing_student:
                            if existing_student["department"] != selected_department:
                                message = "This enrollment number is already registered under a different department. Contact the department administrator."
                            elif existing_student["is_active"] != 1:
                                message = "This enrollment is inactive. Contact the department administrator."
                            elif db.execute("SELECT id FROM users WHERE student_id=?", (existing_student["id"],)).fetchone():
                                message = "An account or approval request already exists for this enrollment number."
                            else:
                                db.execute(
                                    "INSERT INTO users (username,password_hash,role,student_id,is_active) VALUES (?,?, 'student', ?,0)",
                                    (username, generate_password_hash(password), existing_student["id"])
                                )
                                db.execute(
                                    "INSERT INTO audit_logs (actor_id,action,target,result) VALUES (NULL,'STUDENT_REGISTRATION',?,'PENDING_APPROVAL')",
                                    (enrollment,)
                                )
                                db.commit()
                                message_type = "success"
                                message = "All card details match. Your registration request has been sent to Admin for approval."
                        else:
                            db.execute(
                                "INSERT INTO student_registry (enrollment_number,department,batch,is_active,is_approved) VALUES (?,?,?,1,0)",
                                (enrollment, selected_department, request.form.get("batch", "").strip())
                            )
                            student_id = db.execute(
                                "SELECT id FROM student_registry WHERE enrollment_number=?", (enrollment,)
                            ).fetchone()["id"]
                            db.execute(
                                "INSERT INTO users (username,password_hash,role,student_id,is_active) VALUES (?,?, 'student', ?,0)",
                                (username, generate_password_hash(password), student_id)
                            )
                            db.execute(
                                "INSERT INTO audit_logs (actor_id,action,target,result) VALUES (NULL,'STUDENT_REGISTRATION',?,'PENDING_APPROVAL')",
                                (enrollment,)
                            )
                            db.commit()
                            message_type = "success"
                            message = "All card details match. Your registration request has been sent to Admin for approval."
            except Exception:
                db.rollback()
                current_app.logger.exception("Student registration failed")
                message = "Registration could not be completed. Please try again or contact the administrator."
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

    return render_template_string("""
    <div class="reg-layout">
      <aside class="reg-aside">
        <div class="reg-brand"><span class="reg-mark">L</span><div><b>LogicShield</b><small>STUDENT IDENTITY PORTAL</small></div></div>
        <div class="reg-aside-copy">
          <span class="reg-kicker">QUEST NAWABSHAH</span>
          <h1>One secure identity.<br><em>One trusted portal.</em></h1>
          <p>Verify your academic identity before joining the protected student workspace.</p>
          <div class="reg-assurance"><span>✓</span><div><b>Pre-approval validation</b><small>Card details are checked before an Admin request is created.</small></div></div>
          <div class="reg-assurance"><span>⌁</span><div><b>Department-aware access</b><small>For Computer Systems Engineering and Software Engineering.</small></div></div>
        </div>
        <div class="reg-aside-foot">© 2026 All rights reserved<br>Department of Computer Systems Engineering, QUEST Nawabshah<br><b>Made by 25CSE27 · 25CSE04 · 25CSE09</b></div>
      </aside>
      <section class="reg-panel">
        <div class="reg-panel-top"><span class="reg-step-label">STUDENT ONBOARDING</span><span class="reg-secure">▣ Secure registration</span></div>
        <div class="reg-heading"><div class="reg-step-badge">01 <span>/ 03</span></div><h2>Create your student account</h2><p>Enter your details exactly as printed on your official enrollment card.</p></div>
        <div class="reg-progress"><span class="active"></span><span></span><span></span></div>
        {% if message %}<div class="reg-message {% if message_type == 'success' %}success{% endif %}" role="alert"><b>{% if message_type == 'success' %}✓ Registration validated{% else %}! Please review{% endif %}</b><div>{{message}}</div></div>{% endif %}
        <form method="post" enctype="multipart/form-data" class="reg-form" id="studentRegForm">
          <div class="reg-section-title">ACCOUNT CREDENTIALS <span>01</span></div>
          <div class="reg-two">
            <div class="reg-field"><label for="reg_username">Username</label><input id="reg_username" name="username" required maxlength="80" autocomplete="username" placeholder="Choose a username"></div>
            <div class="reg-field"><label for="reg_password">Password</label><div class="reg-password"><input id="reg_password" type="password" name="password" minlength="8" required autocomplete="new-password" placeholder="At least 8 characters"><button type="button" class="reg-show" data-toggle="reg_password">Show</button></div><div class="reg-strength"><span id="strengthBar"></span></div><small id="strengthText">Use 8+ characters with a mix of letters and numbers.</small></div>
          </div>
          <div class="reg-section-title">ACADEMIC IDENTITY <span>02</span></div>
          <div class="reg-two">
            <div class="reg-field"><label for="reg_department">Department</label><select id="reg_department" name="department" required><option value="">Select department</option><option value="CSE">Computer Systems Engineering (CSE)</option><option value="SW">Software Engineering (SW)</option></select></div>
            <div class="reg-field"><label for="reg_enrollment">Enrollment / Roll number</label><input id="reg_enrollment" name="enrollment_number" required placeholder="e.g. 25CSE27-CSE" autocomplete="off"></div>
          </div>
          <div class="reg-field reg-batch"><label for="reg_batch">Batch <span>(optional)</span></label><input id="reg_batch" name="batch" placeholder="e.g. 2025"></div>
          <div class="reg-section-title">ENROLLMENT CARD <span>03</span></div>
          <label class="reg-drop" id="dropZone" for="card_image">
            <input type="file" id="card_image" name="card_image" accept=".jpg,.jpeg,.png,image/jpeg,image/png" required>
            <span class="reg-upload-icon">↑</span><b id="uploadTitle">Drop your card image here</b><span id="uploadSub">or browse files · JPG or PNG · front side only</span>
            <span class="reg-file-meta" id="fileMeta">Maximum recommended size: 5 MB</span>
            <img id="cardPreview" alt="Enrollment card preview" hidden>
          </label>
          <div class="reg-validation" id="validationStatus"><span class="reg-status-dot"></span><span id="validationText">Your card will be scanned securely after you submit the form.</span></div>
          <div class="reg-note"><b>Identity validation</b><p>Your entered department and enrollment number must exactly match the details extracted from the card. Unsupported departments or mismatches are rejected before Admin review. OCR checks printed text; it does not independently authenticate a card as genuine.</p></div>
          <button class="reg-submit" id="submitReg" type="submit">Validate identity & submit <span>→</span></button>
        </form>
        <div class="reg-login-link">Already registered? <a href="{{url_for('auth.login')}}">Return to student login</a></div>
        <div class="reg-mobile-legal">© 2026 Department of Computer Systems Engineering, QUEST Nawabshah<br>Made by 25CSE27 · 25CSE04 · 25CSE09</div>
      </section>
    </div>
    <script>
    (() => {
      const fileInput=document.getElementById('card_image'), drop=document.getElementById('dropZone');
      const preview=document.getElementById('cardPreview'), title=document.getElementById('uploadTitle');
      const sub=document.getElementById('uploadSub'), meta=document.getElementById('fileMeta');
      const status=document.getElementById('validationStatus'), statusText=document.getElementById('validationText');
      const form=document.getElementById('studentRegForm');
      function showFile(file){
        if(!file) return;
        if(!['image/jpeg','image/png'].includes(file.type)){status.classList.add('invalid');statusText.textContent='Unsupported file type. Please choose a JPG or PNG image.';fileInput.value='';return;}
        if(file.size>5*1024*1024){status.classList.add('invalid');statusText.textContent='Image is larger than 5 MB. Please choose a smaller image.';fileInput.value='';return;}
        preview.src=URL.createObjectURL(file);preview.hidden=false;title.textContent=file.name;sub.textContent='Card image selected';meta.textContent=(file.size/1024/1024).toFixed(2)+' MB · Ready for server-side OCR verification';
        status.classList.remove('invalid');status.classList.add('ready');statusText.textContent='Image selected. Department and enrollment matching will run securely after submission.';
      }
      fileInput.addEventListener('change',()=>showFile(fileInput.files[0]));
      ['dragenter','dragover'].forEach(evt=>drop.addEventListener(evt,e=>{e.preventDefault();drop.classList.add('dragging');}));
      ['dragleave','drop'].forEach(evt=>drop.addEventListener(evt,e=>{e.preventDefault();drop.classList.remove('dragging');}));
      drop.addEventListener('drop',e=>{if(e.dataTransfer.files.length){fileInput.files=e.dataTransfer.files;showFile(fileInput.files[0]);}});
      document.querySelectorAll('[data-toggle]').forEach(btn=>btn.addEventListener('click',()=>{const input=document.getElementById(btn.dataset.toggle);input.type=input.type==='password'?'text':'password';btn.textContent=input.type==='password'?'Show':'Hide';}));
      const password=document.getElementById('reg_password'), bar=document.getElementById('strengthBar'), strength=document.getElementById('strengthText');
      password.addEventListener('input',()=>{const v=password.value;let n=0;if(v.length>=8)n++;if(/[A-Z]/.test(v))n++;if(/[a-z]/.test(v))n++;if(/[0-9]/.test(v))n++;if(/[^A-Za-z0-9]/.test(v))n++;bar.style.width=(n*20)+'%';bar.dataset.level=n;strength.textContent=!v?'Use 8+ characters with a mix of letters and numbers.':n<3?'Password strength: weak':n<5?'Password strength: fair':'Password strength: strong';});
      form.addEventListener('submit',()=>{const btn=document.getElementById('submitReg');btn.disabled=true;btn.innerHTML='Submitting for secure validation <span>…</span>';status.classList.add('checking');statusText.textContent='Uploading image. Server-side OCR validation is in progress…';});
    })();
    </script>
    """, message=message, message_type=message_type)

@auth.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    if current_user.role == "student":
        student = db.execute(
            "SELECT enrollment_number, department FROM student_registry WHERE id=?",
            (current_user.student_id,)
        ).fetchone()
        department = student["department"] if student else ""
        counts = db.execute("""
            SELECT category, COUNT(*) AS total FROM files
            WHERE department IN (?, 'ALL') GROUP BY category
        """, (department,)).fetchall() if student else []
        category_counts = {row["category"]: row["total"] for row in counts}
        total_files = sum(category_counts.values())
        return render_template_string("""
        <div class="ls-portal-dashboard">
          <section class="ls-portal-hero student-hero">
            <div><div class="ls-eyebrow">STUDENT LEARNING SPACE</div>
              <h2>Welcome back, {{ name }}!</h2>
              <p>Your departmental academic resources, assignments and results in one secure place.</p>
              <div class="ls-portal-meta"><span>{{ enrollment or 'Enrollment pending' }}</span><span>{{ department or 'Department not available' }}</span></div>
            </div><div class="ls-portal-hero-mark">LS</div>
          </section>
          <section class="ls-portal-stats">
            <article><span>Available resources</span><strong>{{ total }}</strong><small>Files shared with your department</small></article>
            <article><span>Study materials</span><strong>{{ counts.get('study_material', 0) }}</strong><small>Notes and learning resources</small></article>
            <article><span>Assignments</span><strong>{{ counts.get('assignment', 0) }}</strong><small>Coursework shared by teachers</small></article>
            <article><span>Results</span><strong>{{ counts.get('mid_result', 0) + counts.get('final_result', 0) }}</strong><small>Midterm and final results</small></article>
          </section>
          <div class="ls-portal-section-head"><div><div class="ls-eyebrow">ACADEMIC LIBRARY</div><h2>Explore your resources</h2><p>Open a category to view the files available to your department.</p></div></div>
          <section class="ls-portal-shortcuts">
            <a href="/files?category=study_material"><b>▤</b><span><strong>Study Materials</strong><small>Lecture notes and course resources</small></span><em>→</em></a>
            <a href="/files?category=assignment"><b>✎</b><span><strong>Assignments</strong><small>Tasks and coursework</small></span><em>→</em></a>
            <a href="/files?category=mid_result"><b>◷</b><span><strong>Midterm Results</strong><small>View published midterm results</small></span><em>→</em></a>
            <a href="/files?category=final_result"><b>✓</b><span><strong>Final Results</strong><small>View published final results</small></span><em>→</em></a>
          </section>
          <div class="ls-portal-note"> <strong>Security reminder</strong><span>Access to academic files is controlled by your account permissions. Do not share your login credentials or downloaded student records.</span></div>
        </div>
        """, name=current_user.username, enrollment=student["enrollment_number"] if student else "",
        department=department, total=total_files, counts=category_counts)

    if current_user.role == "teacher":
        uploaded = db.execute("SELECT COUNT(*) FROM files WHERE owner_id=?", (current_user.id,)).fetchone()[0]
        return render_template_string("""
        <div class="ls-portal-dashboard">
          <section class="ls-portal-hero teacher-hero">
            <div><div class="ls-eyebrow">FACULTY WORKSPACE</div><h2>Welcome, {{ name }}.</h2>
              <p>Publish academic content and manage the resources shared with your students.</p>
              <div class="ls-portal-meta"><span>Teacher account</span><span>Secure publishing enabled</span></div>
            </div><div class="ls-portal-hero-mark">LS</div>
          </section>
          <section class="ls-portal-stats teacher-stats">
            <article><span>Your uploaded files</span><strong>{{ uploaded }}</strong><small>Resources published by your account</small></article>
            <article><span>Workspace</span><strong>Active</strong><small>Manage your academic content</small></article>
          </section>
          <div class="ls-portal-section-head"><div><div class="ls-eyebrow">TEACHING TOOLS</div><h2>Manage academic content</h2><p>Upload new resources or review files you have already published.</p></div></div>
          <section class="ls-portal-shortcuts">
            <a href="/files/upload"><b>＋</b><span><strong>Publish Content</strong><small>Upload study materials, assignments or results</small></span><em>→</em></a>
            <a href="/files"><b>▤</b><span><strong>My Academic Files</strong><small>Browse and manage your uploaded content</small></span><em>→</em></a>
          </section>
          <div class="ls-portal-note"><strong>Responsible publishing</strong><span>Choose the correct department, category and sensitivity level before publishing student-related information.</span></div>
        </div>
        """, name=current_user.username, uploaded=uploaded)

    return redirect(url_for("auth.admin_panel"))

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("student_card_verified", None)
    session.pop("pending_student_verification_user_id", None)
    return redirect(url_for("auth.login"))

@auth.route("/admin")
@login_required
def admin_panel():
    if current_user.role != "admin":
        return "Access Denied: Admin only", 403
    db = get_db()
    stats = db.execute("SELECT (SELECT COUNT(*) FROM users WHERE role='student') students, (SELECT COUNT(*) FROM users WHERE role='teacher') teachers, (SELECT COUNT(*) FROM student_registry WHERE is_approved=0) pending, (SELECT COUNT(*) FROM files) files, (SELECT COUNT(*) FROM alerts) alerts, (SELECT COUNT(*) FROM access_events WHERE decision='BLOCKED') blocked").fetchone()
    recent_alerts = db.execute("SELECT a.*,u.username FROM alerts a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 5").fetchall()
    recent_events = db.execute("SELECT e.*,u.username,f.original_name FROM access_events e LEFT JOIN users u ON u.id=e.user_id LEFT JOIN files f ON f.id=e.file_id ORDER BY e.created_at DESC LIMIT 7").fetchall()
    return render_template_string('''
    <div class="ls-admin-dashboard">
      <section class="ls-admin-hero"><div><div class="ls-eyebrow">LOGICSHIELD · ADMIN CONTROL CENTER</div><h1>Good day, {{ admin_name }} <span>✦</span></h1><p>Monitor academic accounts, protected files and security activity from one place.</p></div><div class="ls-admin-live"><i></i> SYSTEM OVERVIEW</div></section>
      <section class="ls-admin-stats">
        <article class="ls-admin-stat"><div class="ls-admin-stat-icon blue">♙</div><div><span>Student accounts</span><strong>{{ stats.students }}</strong><small>Registered students</small></div></article>
        <article class="ls-admin-stat"><div class="ls-admin-stat-icon violet">▣</div><div><span>Teacher accounts</span><strong>{{ stats.teachers }}</strong><small>Faculty members</small></div></article>
        <article class="ls-admin-stat"><div class="ls-admin-stat-icon amber">◷</div><div><span>Pending approvals</span><strong>{{ stats.pending }}</strong><small>Require admin review</small></div></article>
        <article class="ls-admin-stat"><div class="ls-admin-stat-icon cyan">▤</div><div><span>Protected files</span><strong>{{ stats.files }}</strong><small>Managed by LogicShield</small></div></article>
        <article class="ls-admin-stat"><div class="ls-admin-stat-icon red">⚑</div><div><span>Security alerts</span><strong>{{ stats.alerts }}</strong><small>Total recorded alerts</small></div></article>
        <article class="ls-admin-stat"><div class="ls-admin-stat-icon slate">⊘</div><div><span>Blocked events</span><strong>{{ stats.blocked }}</strong><small>Access decisions blocked</small></div></article>
      </section>
      <div class="ls-admin-section-head"><div class="ls-eyebrow">QUICK MANAGEMENT</div><h2>Administration tools</h2></div>
      <section class="ls-admin-actions">
        <a href="/admin/student-registrations"><b>✓</b><span><strong>Student approvals</strong><small>Review pending registrations</small></span><em>→</em></a>
        <a href="/admin/create-user"><b>＋</b><span><strong>Create teacher</strong><small>Add a faculty account</small></span><em>→</em></a>
        <a href="/admin/permissions"><b>⌑</b><span><strong>File permissions</strong><small>Manage read and download rights</small></span><em>→</em></a>
        <a href="/admin/audit-logs"><b>≡</b><span><strong>Audit logs</strong><small>Review recorded system actions</small></span><em>→</em></a>
        <a href="/admin/alerts"><b>⚑</b><span><strong>Security alerts</strong><small>Inspect suspicious activity</small></span><em>→</em></a>
        <a href="/files"><b>▤</b><span><strong>Protected files</strong><small>Browse managed academic files</small></span><em>→</em></a>
      </section>
      <section class="ls-admin-lower">
        <div class="ls-admin-panel"><div class="ls-admin-panel-head"><div><div class="ls-eyebrow">SECURITY</div><h2>Recent alerts</h2></div><a href="/admin/alerts">View all →</a></div>
        {% if recent_alerts %}<div class="ls-admin-feed">{% for a in recent_alerts %}<div class="ls-admin-feed-row"><span class="ls-admin-dot alert"></span><div><strong>{{ a.alert_type }}</strong><small>{{ a.username or 'System' }} · {{ a.created_at }}</small><p>{{ a.detail }}</p></div><label>{{ a.severity }}</label></div>{% endfor %}</div>{% else %}<div class="ls-admin-empty">No security alerts have been recorded yet.</div>{% endif %}</div>
        <div class="ls-admin-panel"><div class="ls-admin-panel-head"><div><div class="ls-eyebrow">ACTIVITY</div><h2>Recent access events</h2></div><a href="/admin/audit-logs">Audit logs →</a></div>
        {% if recent_events %}<div class="ls-admin-feed">{% for e in recent_events %}<div class="ls-admin-feed-row"><span class="ls-admin-dot {{ 'good' if e.decision == 'ALLOWED' else 'alert' }}"></span><div><strong>{{ e.action or 'Access' }} · {{ e.decision }}</strong><small>{{ e.username or 'Unknown user' }} · {{ e.created_at }}</small><p>{{ e.original_name or 'No file specified' }}{% if e.reason %} — {{ e.reason }}{% endif %}</p></div></div>{% endfor %}</div>{% else %}<div class="ls-admin-empty">No access events recorded yet.</div>{% endif %}</div>
      </section><footer class="ls-admin-footer">LogicShield · Student Data Protection <span>QUEST Nawabshah</span></footer>
    </div>''', admin_name=current_user.username, stats=stats, recent_alerts=recent_alerts, recent_events=recent_events)

@auth.route("/admin/student-registrations", methods=["GET", "POST"])
@login_required
def student_registrations():
    if current_user.role != "admin": return "Access Denied: Admin only", 403
    db = get_db()
    if request.method == "POST":
        student_id = request.form.get("student_id", type=int)
        action = request.form.get("action")
        row = db.execute("SELECT * FROM student_registry WHERE id=?", (student_id,)).fetchone()
        if row and action in ("approve", "reject"):
            if action == "approve":
                db.execute("UPDATE student_registry SET is_approved=1,is_active=1 WHERE id=?", (student_id,))
                db.execute("UPDATE users SET is_active=1 WHERE student_id=? AND role='student'", (student_id,))
            else:
                db.execute("UPDATE student_registry SET is_approved=0,is_active=0 WHERE id=?", (student_id,))
                db.execute("UPDATE users SET is_active=0 WHERE student_id=? AND role='student'", (student_id,))
            db.execute("INSERT INTO audit_logs (actor_id,action,target,result) VALUES (?,?,?,?)", (int(current_user.id), "STUDENT_"+action.upper(), row["enrollment_number"], "SUCCESS"))
            db.commit()
    rows = db.execute("SELECT s.*,u.username FROM student_registry s LEFT JOIN users u ON u.student_id=s.id WHERE s.is_approved=0 ORDER BY s.created_at DESC").fetchall()
    return render_template_string('''<section class="ls-card"><h2>Pending Student Registrations</h2>{% if rows %}<div class="ls-table-wrap"><table class="ls-table"><thead><tr><th>Username</th><th>Enrollment</th><th>Department</th><th>Action</th></tr></thead><tbody>{% for r in rows %}<tr><td>{{r.username or '—'}}</td><td>{{r.enrollment_number}}</td><td>{{r.department}}</td><td><form method="post" class="ls-inline"><input type="hidden" name="student_id" value="{{r.id}}"><button class="ls-button" name="action" value="approve">Approve</button><button class="ls-button ls-danger" name="action" value="reject">Reject</button></form></td></tr>{% endfor %}</tbody></table></div>{% else %}<p>No pending registrations.</p>{% endif %}</section>''', rows=rows)

@auth.route("/admin/create-user", methods=["GET", "POST"])
@login_required
def create_user():
    if current_user.role != "admin": return "Access Denied: Admin only", 403
    db = get_db(); message = ""
    if request.method == "POST":
        username=request.form.get("username","").strip(); password=request.form.get("password",""); role=request.form.get("role","")
        if role != "teacher": message="Admin can create teacher accounts here. Students use self-registration."
        elif not username or len(password)<8: message="Enter username and a password of at least 8 characters."
        elif db.execute("SELECT id FROM users WHERE username=?",(username,)).fetchone(): message="Username already exists."
        else:
            db.execute("INSERT INTO users(username,password_hash,role,is_active,must_change_password) VALUES(?,?, 'teacher',1,1)",(username,generate_password_hash(password)))
            db.commit(); message="Teacher account created. The teacher must change the temporary password at first login."
    return render_template_string('''<section class="ls-card"><h2>Create Teacher Account</h2>{% if message %}<div class="ls-alert">{{message}}</div>{% endif %}<form method="post" class="ls-form"><label>Teacher username</label><input name="username" required><label>Temporary password (8+ characters)</label><input type="password" name="password" minlength="8" required><p class="ls-muted">Teacher will be required to change this password on first login.</p><input type="hidden" name="role" value="teacher"><button class="ls-button">Create Teacher</button></form></section>''',message=message)
