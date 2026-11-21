from html import escape

from flask import request, url_for
from flask_login import current_user


def install_ui(app):
    @app.after_request
    def apply_logicshield_layout(response):
        content_type = response.content_type or ""
        if response.status_code >= 500 or "text/html" not in content_type:
            return response
        body = response.get_data(as_text=True)
        if "ls-shell" in body or "ls-public" in body:
            return response

        path = request.path
        titles = {
            "/": "Student Verification", "/upload-card": "Enrollment Card Verification",
            "/login": "Sign in", "/dashboard": "Dashboard", "/admin": "Administration",
            "/admin/create-user": "Create Account", "/admin/student-registrations": "Student Approvals", "/student/register": "Student Registration", "/files": "Secure Files",
            "/files/upload": "Upload File", "/admin/permissions": "File Permissions",
            "/admin/audit-logs": "Audit Logs", "/admin/alerts": "Security Alerts",
        }
        title = titles.get(path, "Security Workspace")
        authenticated = bool(current_user.is_authenticated)
        role = current_user.role if authenticated else ""
        username = escape(current_user.username) if authenticated else ""
        initial = escape((current_user.username[:1] or "U").upper()) if authenticated else "G"
        css_url = url_for("static", filename="logicshield.css")

        if not authenticated:
            layout = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} | LogicShield</title><link rel="stylesheet" href="{css_url}"></head>
<body><div class="ls-public"><div class="ls-public-wrap">
<div class="ls-public-brand"><div class="ls-logo">L</div><div><strong>LogicShield</strong><br><small>STUDENT DATA PROTECTION</small></div></div>
<main class="ls-content">{body}</main>
<div class="ls-login-note">Secure access | Departmental academic prototype</div>
<footer class="ls-footer">© 2026 All rights reserved | <strong>Department of Computer Systems Engineering, QUEST Nawabshah</strong><br>Made by: 25CSE27 | 25CSE04 | 25CSE09</footer>
</div></div></body></html>'''
        else:
            links = [
                ("◫", "Dashboard", "auth.dashboard", "/dashboard", "WORKSPACE"),
                ("▤", "Secure Files", "files.file_list", "/files", "WORKSPACE"),
            ]
            if role in ("admin", "teacher"):
                links.append(("↑", "Publish Content" if role == "teacher" else "Upload File", "files.upload_file", "/files/upload", "WORKSPACE"))
            if role == "student":
                links.extend([
                    ("▧", "Study Material", "files.file_list", "/files?category=study_material", "ACADEMICS"),
                    ("✎", "Assignments", "files.file_list", "/files?category=assignment", "ACADEMICS"),
                    ("◷", "Midterm Results", "files.file_list", "/files?category=mid_result", "ACADEMICS"),
                    ("▣", "Final Results", "files.file_list", "/files?category=final_result", "ACADEMICS"),
                ])
            if role == "admin":
                links.extend([
                    ("⌘", "Admin Panel", "auth.admin_panel", "/admin", "ADMINISTRATION"),
                    ("＋", "Create Teacher", "auth.create_user", "/admin/create-user", "ADMINISTRATION"),
                    ("✓", "Student Approvals", "auth.student_registrations", "/admin/student-registrations", "ADMINISTRATION"),
                    ("⚙", "Permissions", "files.manage_permissions", "/admin/permissions", "ADMINISTRATION"),
                    ("≡", "Audit Logs", "files.audit_logs", "/admin/audit-logs", "SECURITY"),
                    ("⚑", "Security Alerts", "files.security_alerts", "/admin/alerts", "SECURITY"),
                ])
            nav = []
            last_group = None
            for icon, label, endpoint, href, group in links:
                if group != last_group:
                    nav.append(f'<div class="ls-nav-label">{group}</div>')
                    last_group = group
                active = "active" if path == href or (href != "/" and path.startswith(href + "/")) or (href.startswith("/files?") and path == "/files" and request.query_string.decode().endswith(href.split("?",1)[1])) else ""
                nav.append(f'<a class="{active}" href="{url_for(endpoint)}"><span class="nav-ico">{icon}</span>{label}</a>')
            layout = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} | LogicShield</title><link rel="stylesheet" href="{css_url}"></head>
<body><div class="ls-shell">
<aside class="ls-sidebar"><div class="ls-brand"><div class="ls-logo">L</div><div><strong>LogicShield</strong><small>SECURITY CONSOLE</small></div></div>
<nav class="ls-nav">{"".join(nav)}</nav>
<div class="ls-sidebar-foot"><strong style="color:#c8d9ee">PROTECTED WORKSPACE</strong><br>DATA LOSS PREVENTION<br>QUEST Nawabshah · Academic Portal</div></aside>
<div class="ls-main"><header class="ls-topbar"><div class="ls-breadcrumb">LOGICSHIELD / <strong>{escape(title.upper())}</strong></div>
<div class="ls-user"><span>{username} <b style="color:#9aaac0">·</b> {escape(role.title())}</span><span class="ls-avatar">{initial}</span><a href="{url_for('auth.logout')}">Sign out&nbsp; ↗</a></div></header>
<main class="ls-content"><div class="ls-pagehead"><div><div class="ls-eyebrow">SECURE WORKSPACE</div><h1>{escape(title)}</h1><p>Protecting student information through controlled access, policy enforcement and security monitoring.</p></div></div>{body}</main>
<footer class="ls-footer">© 2026 All rights reserved | <strong>Department of Computer Systems Engineering, QUEST Nawabshah</strong><br>Made by: 25CSE27 | 25CSE04 | 25CSE09</footer>
</div></div></body></html>'''
        response.set_data(layout)
        return response
