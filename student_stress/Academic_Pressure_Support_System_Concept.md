# AI-Based Subject-Wise Academic Pressure Prediction & Private Student Support System

## Executive Overview
The **AI-Based Subject-Wise Academic Pressure Prediction & Private Student Support System** is a privacy-first, machine-learning-driven platform designed to assess, identify, and mitigate academic pressure in higher education students. 

Rather than attempting to make clinical medical diagnoses, the system focuses strictly on **Academic Pressure Risk Estimation**. By analyzing subject-specific inputs—such as assignment backlogs, class topic comprehension, notes completeness, prerequisite knowledge gaps, and exam preparation readiness—the platform identifies high-risk academic areas and seamlessly connects students with authorized faculty members through a private, role-restricted communication channel.

---

## Technical Concept & Architecture

### Core Definition
1. **Student Input**: Students complete structured, subject-wise questionnaires capturing objective academic indicators.
2. **AI/ML Analysis**: A deterministic predictive machine learning model calculates an overall and subject-specific **Academic Pressure Risk Score (%)**.
3. **Explainable AI (XAI)**: The platform highlights primary root-cause contributors (e.g., pending assignments, low concept clarity).
4. **Targeted Academic Support**: With explicit student consent, high-risk flags trigger a private academic support request routed exclusively to the designated subject lecturer.
5. **Private Faculty Response**: Lecturers provide direct, confidential guidance (e.g., setting up one-on-one sessions, offering catch-up materials) without exposing student data to peers or unrelated faculty.

---

## End-to-End System Workflow

```
[ STUDENT LOGIN ]
       │
       ▼
[ AI ASSESSMENT QUESTIONNAIRE ]
       │
       ├─► Java Inputs (Assignments, Notes, Comprehension, CIA Prep)
       ├─► DBMS Inputs
       └─► Mathematics / DCO Inputs
       │
       ▼
[ AI / ML PREDICTIVE PIPELINE ]
       │
       ├─► Explainable AI Engine (Root Cause Factors)
       └─► Heatmap Generation & Risk Score Calculation
       │
       ├─── LOW / MODERATE RISK ──► Self-Paced AI Catch-Up Plan & Study Suggestions
       │
       └─── HIGH RISK ───────────► Option: Initiate Private Academic Support Request
                                           │
                                           ▼
                                [ AUTOMATIC LECTURER ROUTING ]
                                (Matched by Subject ID & Role)
                                           │
                                           ▼
                                [ LECTURER PRIVATE PANEL ]
                                           │
                                           ▼
                                [ CONFIDENTIAL GUIDANCE & RESPONSE ]
                                           │
                                           ▼
                                [ STUDENT FOLLOW-UP ASSESSMENT ]
```

---

## Key Functional Modules

### 1. Student Dashboard & Assessment Engine
* **Secure Authentication**: JWT-based login supporting unique Student IDs and encrypted credentials.
* **Granular Subject-Wise Questionnaire**:
  * *Assignment Backlogs*: Quantified pending lab exercises or project submissions.
  * *Notes & Resource Status*: Percentage of syllabus material completed.
  * *In-Class Comprehension*: Qualitative rating of current subject topics.
  * *Prerequisite Readiness*: Self-assessment of basic foundation concepts.
  * *Exam / CIA Readiness*: Preparedness metrics prior to internal assessments.

### 2. AI Risk Engine & Explainable AI (XAI)
* **Academic Pressure Risk Index**: Categorized into **Low**, **Moderate**, and **High** risk tiers accompanied by an exact percentage estimation.
* **Explainability Breakdown**:
  * Identifies exact drivers behind elevated risk scores (e.g., *"Java: 4 pending assignments, prerequisite concept gap in OOP Inheritance"*).

### 3. Subject-Wise Heatmap & Analytics
* Visual representation of academic pressure distribution across all registered coursework.
* Enables students to prioritize workload based on urgency and risk score rather than intuition alone.

### 4. Role-Based Private Academic Support & Lecturer Panel
* **Privacy Architecture (RBAC)**:
  * **Student**: Access restricted to personal assessments, results, and support history.
  * **Subject Lecturer**: Access strictly confined to incoming support requests for their assigned course modules.
  * **Unrelated Faculty & Classmates**: Zero visibility across cross-subject or peer interactions.
* **Direct Communication Pipeline**: Allows faculty to reply with actionable guidance (e.g., *"Please meet me after class to discuss basic OOP concepts"*).

---

## Innovative Value-Add Features

1. **Academic Pressure Early Warning System**: Tracks longitudinal assessment trends over multiple weeks (e.g., Week 1: 31% ➔ Week 4: 81%) to alert students before critical failure points.
2. **Catch-Up Gap Analyzer**: Particularly beneficial for lateral-entry or transfer students, identifying foundational topics required prior to advancing to complex coursework.
3. **Automated AI Recovery / Catch-Up Plan**: Generates a structured 5-day study roadmap prioritizing urgent assignments and foundational revisions.
4. **Assignment Workload Prioritizer**: Organizes overlapping deadlines based on upcoming CIA exams, assignment difficulty, and submission proximity.
5. **Follow-Up & Trend Tracking**: Re-evaluates risk metrics post-lecturer intervention to measure risk reduction without claiming direct medical causation.
6. **Anonymized Institutional Insights**: Provides department heads and administrators with aggregated, non-identifiable statistics regarding high-difficulty subjects while fully protecting individual student identity.
7. **Database-Level Message Encryption**: Encrypts sensitive support messages at rest to maintain full data integrity and confidentiality.

---

## Recommended Technology Stack

| Layer | Recommended Technologies |
| :--- | :--- |
| **Frontend** | React.js, Tailwind CSS, Recharts / Chart.js |
| **Backend API** | Python (FastAPI), Pydantic |
| **Machine Learning** | Python, Scikit-Learn, Pandas, NumPy |
| **Database** | MySQL (Strict Foreign Key constraints, Encrypted fields) |
| **Authentication** | JSON Web Tokens (JWT), PassLib (Bcrypt Hashing) |
| **Optional LLM Integration**| OpenAI / Gemini API (Restricted strictly to generating Catch-Up Plans and explanation formatting) |

---

## Database Architecture Overview

### Primary Relational Tables

1. **`STUDENTS`**: Stores `student_id`, `name`, `email`, `department`, `hashed_password`.
2. **`LECTURERS`**: Stores `lecturer_id`, `name`, `email`, `department`, `hashed_password`.
3. **`SUBJECTS`**: Maps `subject_id`, `subject_code`, `subject_name`, `department`.
4. **`LECTURER_SUBJECT_MAP`**: Foreign-key mapping linking specific `subject_id`s to assigned `lecturer_id`s.
5. **`ASSESSMENTS`**: Tracks overall test sessions with `assessment_id`, `student_id`, `timestamp`, `overall_risk_score`, `risk_level`.
6. **`SUBJECT_RISK`**: Detailed breakdowns per test session (`assessment_id`, `subject_id`, `risk_percentage`, `risk_factors`).
7. **`SUPPORT_REQUESTS`**: Manages private requests (`request_id`, `student_id`, `subject_id`, `lecturer_id`, `encrypted_message`, `status`, `created_at`).
8. **`LECTURER_RESPONSES`**: Captures faculty replies (`response_id`, `request_id`, `lecturer_id`, `encrypted_response`, `created_at`).
9. **`AUDIT_LOGS`**: Maintains security logs for authorization and access validation.

---

## Implementation Roadmap

* **Phase 1: Architecture & UI Wireframing** — Design responsive React components for Student and Lecturer dashboards.
* **Phase 2: Authentication & RBAC Engine** — Implement JWT-based API endpoints and secure password hashing in FastAPI.
* **Phase 3: Database Schema Design** — Deploy MySQL tables with strict relational constraints and indexing.
* **Phase 4: ML Model Development** — Train a regression/classification pipeline using historical or synthesized academic metrics.
* **Phase 5: Explainable AI & Heatmap Integration** — Connect model output with visual diagnostic features.
* **Phase 6: Private Communication Channel** — Implement end-to-end support request flow with lecturer mapping.
* **Phase 7: Security & Audit Hardening** — Conduct strict role-based authorization tests and payload encryption.

---

## Strategic Project Positioning

Present and defend this project as:

> *"An AI-powered academic early-support platform that detects subject-wise academic pressure risk and creates a privacy-controlled connection between students and appropriate faculty members for timely, targeted academic assistance."*
