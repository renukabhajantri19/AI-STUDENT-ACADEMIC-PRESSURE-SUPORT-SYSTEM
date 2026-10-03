# Clarity — Academic Pressure Support

A privacy-minded starter app for subject-wise academic pressure check-ins and private student–lecturer support. The two supplied documents are the product and architecture references for this implementation.

## Run locally

Requires Python 3.10+.

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. FastAPI API documentation is at <http://127.0.0.1:8000/docs>.

On Windows, you can also start the local server from the project folder with:

```powershell
.\run_local.ps1
```

The script uses `.venv` and serves only on your local machine at `127.0.0.1:8000`.

### Demo accounts

| Role | Email | Password |
| --- | --- | --- |
| Student | `student@demo.edu` | `Student123!` |
| Lecturer | `lecturer@demo.edu` | `Faculty123!` |

Demo accounts and the nine required subjects are seeded into the configured database on first startup. Existing databases are migrated in place. With MySQL, the database is `academic_support`; with SQLite, the local file is `academic_support.db`.

## Configuration

Copy `.env.example` to `.env`, set your MySQL credentials in `DATABASE_URL`, and set `APP_SECRET` and `MESSAGE_ENCRYPTION_KEY` before using the app beyond a local demo. The MySQL account must be allowed to create the `academic_support` database on first startup. Generate a Fernet key with:

```powershell
py -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

MySQL is configured in the example environment; SQLite remains available with `DATABASE_URL=sqlite:///./academic_support.db`. Tables and demo accounts are created on first startup. Do not use the seeded credentials or development secrets in a real deployment.

Email verification during sign-in and password reset uses SMTP. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM` in `.env`; the example uses STARTTLS on port 587. Use `SMTP_USE_SSL=true` for an implicit-SSL service instead. SMTP username and password may be left empty for a trusted unauthenticated relay. If `SMTP_HOST` or `SMTP_FROM` is missing, sign-in completes without email verification; configure SMTP before deployment to restore the verification step. Password reset still requires working SMTP delivery.

## What is implemented

- Student and lecturer sign-in, signed expiring bearer tokens, and role checks.
- Four-question academic pressure assessment across the required subjects, with Low/Moderate/High tiers and ranked subject-wise factors.
- Automatically generated assessment reports with PDF downloads, recommendations, and catch-up suggestions.
- Explicit-consent support requests automatically routed to the lecturer assigned to the chosen subject.
- Lecturer inbox and assessment reports restricted to assigned subjects, with private replies and image attachments.
- Fernet encryption for support text and image files, plus audit records for sign-in, assessments, and support actions.

## Risk scoring

The estimate weights incomplete assignments (30%), class concept understanding (25%), exam readiness (25%), and incomplete notes (20%). It is an academic planning estimate rather than a clinical assessment or a trained machine-learning prediction.

## Project structure

```text
app/main.py       FastAPI API, local persistence, scoring, access control
web/              Browser client (HTML, CSS, JavaScript)
requirements.txt  Python dependencies
```
