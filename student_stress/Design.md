# System Architecture & Design Specification
## AI-Based Subject-Wise Academic Pressure Prediction & Private Student Support System

---

## 1. System Overview & Objectives
The platform provides a data-driven, privacy-centric mechanism to detect early indicators of academic pressure in higher education. It bypasses subjective self-reporting of mental health by evaluating concrete academic metrics (backlogs, topic comprehension, prerequisite gaps) and dynamically routes intervention requests to verified faculty members using Role-Based Access Control (RBAC).

---

## 2. High-Level Architecture Diagram

```
                             ┌────────────────────────┐
                             │   React.js Web Client  │
                             │   (Tailwind CSS UI)    │
                             └───────────┬────────────┘
                                         │
                                         │ REST API / JWT
                                         ▼
                             ┌────────────────────────┐
                             │    FastAPI Backend     │
                             │   (Business Logic)     │
                             └──────┬──────────┬──────┘
                                    │          │
            ┌───────────────────────┘          └───────────────────────┐
            ▼                                                          ▼
┌──────────────────────┐                                   ┌──────────────────────┐
│  Scikit-Learn Model  │                                   │    MySQL Database    │
│ (Risk & XAI Engine)  │                                   │ (Encrypted Payload) │
└──────────────────────┘                                   └──────────────────────┘
```

---

## 3. Detailed Component Design

### 3.1 Frontend Subsystem (React.js + Tailwind CSS)
* **Student Dashboard**: 
  * Questionnaire interface rendered dynamically per subject.
  * Graphical risk visualizations via Recharts (Subject Heatmap & Assessment History).
  * Private support request submission form with selective checkboxes.
* **Lecturer Dashboard**:
  * Real-time list of assigned support requests filterable by risk level.
  * Confidential reply portal and student interaction history.

### 3.2 Backend Subsystem (FastAPI / Python)
* **Authentication & Authorization**: JWT token issuance with encrypted user state handling.
* **Inference Pipeline**: Preprocessing questionnaire payloads and feeding feature arrays into the predictive model.
* **Routing Engine**: Mapping target `subject_id` directly to authorized `lecturer_id`.

### 3.3 Data Layer (MySQL Schema & Security)
* **Role-Based Isolation**: Foreign key structures ensuring lecturers cannot query requests outside their mapped `subject_id`.
* **Payload Encryption**: Symmetric encryption (e.g., AES-256 / Fernet) applied to message content before database persistence.

---

## 4. Machine Learning Design & Feature Engineering

### 4.1 Assessment Inputs & Weights
The academic pressure estimate uses four answers shared across the subjects selected for an assessment:

| Input | Options | Weight |
| :--- | :--- | ---: |
| Assignments completed | 0/3, 1/3, 2/3, 3/3 | 30% |
| Notes complete | 0%, 25%, 50%, 75%, 100% | 20% |
| Class concept understanding | Very Well, Well, Average, Poor, Very Poor | 25% |
| Exam readiness | Very Ready, Ready, Average, Not Ready, Very Not Ready | 25% |

### 4.2 Risk Calculation & Output Matrix
* **Formula Driver**: Weighted combination mapping to an estimated academic pressure risk from 0% to 100%.
* **Risk Tiers**:
  * **Low Risk**: $0\% - 40\%$
  * **Moderate Risk**: $41\% - 70\%$
  * **High Risk**: $71\% - 100\%$

---

## 5. Security, Privacy & Role-Based Access Control (RBAC)

```
┌─────────────────┬───────────────────┬───────────────────┬───────────────────┐
│ Entity          │ Own Assessments   │ Subject Requests  │ Other Lecturers   │
├─────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Student         │ Read / Create     │ Read / Create     │ No Access         │
│ Assigned Faculty│ No Access         │ Read / Reply      │ No Access         │
│ Unrelated Faculty│ No Access        │ No Access         │ No Access         │
└─────────────────┴───────────────────┴───────────────────┴───────────────────┘
```

* **Data Minimization**: Lecturers only receive academic context (issue tags, optional student message), avoiding unnecessary personal exposure.
* **Audit Trail**: Operational events (login, request dispatch, access attempt) logged to an immutable `AUDIT_LOGS` table.

---

## 6. API Endpoint Architecture

### Authentication
* `POST /api/v1/auth/login` - Authenticate student or lecturer; returns JWT.

### Student Module
* `GET /api/v1/student/subjects` - Fetch registered subject modules.
* `POST /api/v1/assessment/submit` - Process questionnaire inputs and return ML risk scores.
* `POST /api/v1/support/request` - Dispatch private support request to mapped lecturer.

### Lecturer Module
* `GET /api/v1/lecturer/requests` - Fetch active incoming support requests for assigned subjects.
* `POST /api/v1/lecturer/respond` - Send private guidance reply to student dashboard.
