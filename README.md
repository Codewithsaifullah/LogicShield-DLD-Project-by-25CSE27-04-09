# LogicShield

### Student Data Protection & Leakage Detection System

**LogicShield** is an academic web-application prototype developed to demonstrate how Digital Logic Design (DLD) concepts can be applied to application-level access control for academic files and student information. It combines role-based portals, student enrollment-card text extraction, file permissions, additional verification for sensitive files, rule-based risk scoring, and security-event logging.

> **Academic project** · Department of Computer Systems Engineering  
> **Quaid-e-Awam University of Engineering, Science & Technology (QUEST), Nawabshah, Pakistan**  
> **Subject:** Digital Logic Design (DLD)  
> **Submitted to:** Engr. Iftikhar Ali Koondhar  
> **Project team:** 25CSE27 · 25CSE04 · 25CSE09

---

## Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [User Roles](#user-roles)
- [How the DLD Logic Works](#how-the-dld-logic-works)
- [Technology Stack](#technology-stack)
- [Application Workflow](#application-workflow)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation on Windows](#installation-on-windows)
- [Run the Application](#run-the-application)
- [Database and Demo Data](#database-and-demo-data)
- [Automated Tests](#automated-tests)
- [Security Notes and Limitations](#security-notes-and-limitations)
- [Future Improvements](#future-improvements)
- [Academic Use](#academic-use)

---

## Project Overview

Universities manage academic documents such as study materials, assignments, and results. These files may contain information that should only be available to specific users. LogicShield demonstrates an application-level approach to protecting such files.

The application provides separate Admin, Teacher, and Student workflows. It checks a user's authenticated session and the permissions associated with a requested file. Sensitive files can require an additional password check. The DLD decision engine combines the relevant conditions using Boolean logic and returns access-control outputs. Access attempts and security-related events can be recorded for administrative review.

LogicShield is designed as an **academic prototype**. Its protection applies to files and events managed inside this application; it is not a university-wide network-monitoring or endpoint-security product.

## Key Features

- **Role-based portals:** Separate Admin, Teacher, and Student experiences.
- **Student registration and review:** Student registration details are checked before the account is approved and activated.
- **Enrollment-card OCR:** Text is extracted from a submitted card image to identify the department and enrollment number.
- **Department and enrollment matching:** The prototype supports Computer Systems Engineering (CSE) and Software Engineering (SW), with department/enrollment consistency checks.
- **Admin approval:** Student accounts require the configured administrative approval process before activation.
- **Academic file management:** Teachers can upload academic files and categorize supported content.
- **Private application storage:** Uploaded files are stored in application-managed storage rather than being treated as public static assets.
- **Per-file permissions:** Read and download permissions can be managed separately for users.
- **Sensitive-file step-up check:** Sensitive-file access can require the user to re-enter their password.
- **DLD access decision:** Boolean logic evaluates whether an access request should be allowed or blocked and whether an alert condition is present.
- **Risk scoring:** A configurable recent-event window is used by a basic rule-based risk heuristic.
- **Audit and security records:** Access events, audit logs, and alerts support administrative review.

Feature availability can vary with the exact source revision and local configuration. Review the routes and modules in your checked-out version before publishing screenshots or claiming a feature is operational.

## User Roles

| Role | Main responsibilities |
|---|---|
| **Admin** | Review student registrations, approve accounts, create teacher accounts, manage file permissions, and review audit logs and security alerts. |
| **Teacher** | Sign in, manage their academic content, and upload materials such as study resources and assignments. File access remains subject to application permissions. |
| **Student** | Register with department and enrollment details, submit a card image for OCR-based text checking, complete the configured approval/verification process, and access permitted academic files. |

## How the DLD Logic Works

The DLD engine uses six Boolean inputs. The following notation describes the access-decision logic implemented in the project; confirm the current `app/dld_engine.py` in your local revision if you have customized it.

| Symbol | Meaning | `1` means |
|---|---|---|
| `A` | Authentication | The user is authenticated. |
| `P` | Permission | The requested action is permitted. |
| `S` | Sensitive file | The requested file is marked sensitive. |
| `M` | Extra verification | The additional password verification has passed. |
| `R` | High risk | The risk engine has classified the user/request as high risk. |
| `E` | Suspicious export | The configured suspicious-export condition is present. |

### Boolean expressions

```text
ALLOW = A AND P AND NOT(R) AND (NOT(S) OR M) AND NOT(E)
BLOCK = NOT(ALLOW)
ALERT = NOT(A) OR NOT(P) OR R OR E
```

### Interpretation

- **AND** combines conditions that must all be satisfied.
- **OR** is true when at least one of its conditions is true.
- **NOT** inverts a Boolean value.
- For a **normal file** (`S = 0`), the term `(NOT(S) OR M)` is true, so the additional password check is not required by this term.
- For a **sensitive file** (`S = 1`), `M` must be `1` for the access expression to pass.
- A request is allowed only when authentication and permission are valid, risk is not high, the sensitive-file condition is satisfied, and the suspicious-export condition is absent.
- `BLOCK` is the complement of `ALLOW`. `ALERT` is a separate output governed by its own expression.

The Python implementation is in `app/dld_engine.py`, in the `evaluate_access()` function. The file-access workflow calls the decision logic when processing protected file actions.

## Technology Stack

| Technology / Library | Purpose |
|---|---|
| **Python** | Main backend programming language. |
| **Flask** | Web framework, application factory, and HTTP routes. |
| **SQLite** | Relational database for users, student records, file metadata, permissions, events, logs, and alerts. |
| **HTML** | Structure of web pages and forms. |
| **CSS** | Portal styling and responsive layouts. |
| **JavaScript** | Client-side interactions and form/upload behavior where implemented. |
| **Flask-Login** | Login session and authenticated-user management. |
| **Werkzeug** | Password hashing and secure filename utilities. |
| **pytesseract** | Python interface to the Tesseract OCR engine. |
| **Tesseract OCR** | Recognition of text in submitted student-card images. |
| **Pillow** | Image loading and preprocessing for OCR. |
| **pytest** | Automated testing of the DLD decision function. |

Python package dependencies are listed in `requirements.txt`. Tesseract OCR is a separate system application and must also be installed on the machine running the application.

## Application Workflow

1. An Admin signs in and manages users, approvals, permissions, and monitoring pages.
2. A Student submits registration details and a supported enrollment-card image.
3. The OCR service preprocesses the image and extracts readable text.
4. The verification logic checks the extracted department and enrollment number against the configured rules and student registry.
5. The student account follows the application's approval and activation process.
6. A Teacher signs in and uploads academic material.
7. The Admin assigns the appropriate read and/or download permissions.
8. A user requests access to a file.
9. The application checks authentication, permission, file sensitivity, additional verification, and risk-related conditions.
10. The DLD engine produces the `ALLOW`, `BLOCK`, and `ALERT` outputs.
11. The application serves or blocks the requested action and records relevant events for review.

## Project Structure

The exact tree may differ slightly between project revisions. A typical source layout is:

```text
LogicShield/
├── app/
│   ├── __init__.py              # Flask application factory and blueprint setup
│   ├── auth.py                  # Login, registration, role-specific routes
│   ├── db.py                    # SQLite connection and database initialization
│   ├── schema.sql               # Database tables, constraints, and indexes
│   ├── dld_engine.py            # Boolean access-decision function
│   ├── risk_engine.py           # Rule-based risk score and alert helper
│   ├── ocr_service.py           # Student-card image OCR and text extraction
│   ├── student_verification.py  # Department/enrollment and registry checks
│   ├── files.py                 # Upload, download, permissions, logs, alerts
│   ├── ui.py                    # Shared portal layout (if present in this revision)
│   └── static/
│       └── logicshield.css      # Application styles
├── tests/
│   └── test_dld_engine.py       # DLD decision-function tests
├── instance/                    # Local database and private runtime storage
├── create_admin.py               # Admin account setup helper (if included)
├── requirements.txt              # Python dependencies
└── README.md                     # Project documentation
```

The `instance/` directory may contain the SQLite database and uploaded files at runtime. It should not be committed with real user data or private documents.

## Prerequisites

For a Windows development environment:

- Windows 10 or later.
- Python 3.11 or later (use a Python version supported by the installed dependencies).
- pip.
- Tesseract OCR installed separately.
- Git (optional, for cloning and version control).
- Visual Studio Code or another Python editor (optional).

> **Tesseract configuration:** Check `app/ocr_service.py`. Some project revisions contain a machine-specific Windows executable path. If the configured path does not match your installation, update it to the actual `tesseract.exe` location or make it configurable through an environment variable. Do not assume that installing the Python package `pytesseract` also installs Tesseract itself.

## Installation on Windows

Open PowerShell in the project root directory.

### 1. Create and activate a virtual environment

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use the Python executable inside the environment directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. Install Python dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Configure a secret key

Set a unique secret for your local session. Do not publish the value or commit it to Git:

```powershell
$env:LOGICSHIELD_SECRET_KEY = "replace-with-a-long-random-secret"
```

This environment variable applies to the current PowerShell session. Set it again in a new terminal, or use a secure local environment configuration that is excluded from version control.

### 4. Configure Tesseract OCR

Install Tesseract OCR for Windows. Confirm the executable location, commonly:

```text
C:\Program Files\Tesseract-OCR\tesseract.exe
```

Make sure the path configured in `app/ocr_service.py` matches your installation. The application may start without a working OCR executable, but card-text extraction will fail until OCR is configured correctly.

### 5. Initialize the database

From the project root:

```powershell
python -m flask --app app:create_app init-db
```

This initializes the configured SQLite database. If you already have a database containing data, back it up before changing schemas or running migrations. Do not delete an existing database just to troubleshoot a page or route error.

## Run the Application

Start the Flask development server:

```powershell
python -m flask --app app:create_app run --debug
```

Open the local application in your browser:

```text
http://127.0.0.1:5000/
```

The login page is available at:

```text
http://127.0.0.1:5000/login
```

The debug server is intended for local development only. Do not expose it to the public internet or use it as a production server.

## Database and Demo Data

The application uses SQLite. Depending on the revision and configuration, the database is stored under the Flask `instance/` directory (for example, `instance/logicshield.sqlite`). The schema includes entities for user accounts, student registry entries, files, per-user permissions, access events, audit records, and alerts.

Use dummy accounts and fictional student records for demonstrations. Create or approve accounts through the application's supported Admin workflow or the provided setup helper, if included. Do not publish default credentials, password hashes, personal enrollment-card images, real student information, or a populated database.

## Automated Tests

Install pytest if it is not already available:

```powershell
python -m pip install pytest
```

Run the test suite from the project root:

```powershell
python -m pytest -v
```

The included DLD tests are intended to verify Boolean access-decision scenarios. The test output from your own environment is the source of truth; do not claim a particular number of passing tests unless you have run the suite against the version being published.

## Security Notes and Limitations

LogicShield is an academic prototype and should not be treated as a production-ready security product.

- **OCR is not proof of card authenticity.** It extracts visible text. A copied or edited image could contain matching text. Registry checks and Admin approval provide additional controls, but stronger institutional verification (such as a trusted QR/record validation process or manual review) would be needed.
- **Application scope is limited.** The system controls files and events managed by this application. It does not monitor all devices, operating systems, networks, or university infrastructure.
- **Risk scoring is heuristic.** The configured thresholds are demonstration rules, not a validated fraud-detection model or machine-learning system.
- **Web security hardening is required before deployment.** Review CSRF protection, rate limiting, secure cookie settings, HTTPS, session management, secret management, file-content/MIME validation, upload size limits, malware scanning, authorization checks, logging, backups, and dependency updates.
- **Private storage must remain private.** Do not move protected uploads into a publicly served static directory.
- **Database changes require care.** Back up existing SQLite data before schema changes or migrations.
- **Use a production-grade deployment setup** and perform a security review before any real institutional use.

## Future Improvements

Potential future work may include institution-verified QR codes, stronger student-card authenticity checks, CSRF protection across forms, authentication and upload rate limiting, robust file-content validation, malware scanning, configurable risk policies, improved reporting, encrypted backups, and integration with official university identity systems. These are future enhancements unless they are demonstrably implemented in the current source revision.

## Academic Use

LogicShield was developed as an academic project for the **Digital Logic Design (DLD)** subject in the **Department of Computer Systems Engineering, QUEST Nawabshah**. Its principal DLD demonstration is the use of Boolean operations to make structured access-control decisions in a software application.

**Submitted to:** Engr. Iftikhar Ali Koondhar  
**Project team:** 25CSE27 · 25CSE04 · 25CSE09

---


- [ ] Add a `.gitignore` suitable for Python, Flask, SQLite, and local uploads.
- [ ] Confirm that `requirements.txt` reflects the current source revision.
- [ ] Test setup instructions from a clean virtual environment.
- [ ] Run `python -m pytest -v` and report only the verified result.
- [ ] Review screenshots for private information before committing them.

