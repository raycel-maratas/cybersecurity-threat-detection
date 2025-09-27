# **CyberTrack: Cybersecurity Threat Detection System**

CyberTrack is a Flask-based cybersecurity threat detection system that processes uploaded logs to identify known threats and suspicious behavior. It employs hashing and binary search algorithms to efficiently detect malicious activity, failed login attempts, and time-based anomalies.

---

## Screenshots

<img width="1419" height="803" alt="Screenshot 2025-09-27 at 16 49 41" src="https://github.com/user-attachments/assets/73b86343-99ff-40cc-8a0c-6cb02e8940d2" />

<img width="1420" height="745" alt="Screenshot 2025-09-27 at 16 50 54" src="https://github.com/user-attachments/assets/863e60a0-6ac6-4974-a60b-0373a3f462b0" />

<img width="1418" height="801" alt="Screenshot 2025-09-27 at 16 54 28" src="https://github.com/user-attachments/assets/6947ec01-2cc3-4ac8-8174-5e493106670a" />

<img width="1418" height="801" alt="Screenshot 2025-09-27 at 16 54 08" src="https://github.com/user-attachments/assets/8774e53f-4545-449e-a2bb-5b23b0cc4417" />

<img width="1418" height="801" alt="Screenshot 2025-09-27 at 16 54 28" src="https://github.com/user-attachments/assets/0998eb3b-2503-49ce-baa6-45b72448920c" />

<img width="1412" height="800" alt="Screenshot 2025-09-27 at 17 06 24" src="https://github.com/user-attachments/assets/ee1cf448-ddbc-41e4-806e-05ce28ffa63f" />

<img width="1418" height="801" alt="Screenshot 2025-09-27 at 16 54 28" src="https://github.com/user-attachments/assets/ca25b7d6-4f8c-4dec-8cc7-5ec0c24a14d7" />

<img width="1422" height="787" alt="Screenshot 2025-09-27 at 17 04 25" src="https://github.com/user-attachments/assets/21b1d15f-7886-438c-b663-97f25d660475" />

<img width="1422" height="788" alt="Screenshot 2025-09-27 at 17 04 35" src="https://github.com/user-attachments/assets/c4f8f6f9-0041-4371-8a53-229408d85ce6" />

<img width="1418" height="798" alt="Screenshot 2025-09-27 at 17 04 50" src="https://github.com/user-attachments/assets/36259b4b-c5c0-4e58-bd05-8c222c58a6e8" />

## Features

* Role-based access for Admin and Users
* Log upload and parsing
* Hash-based malware detection
* Binary search anomaly detection
* Alert generation and database logging
* Failed login tracking and user account lockout
* Real-time dashboards for both Admin and Users

---

## Accounts

You must seed users before logging in.

### Admin

* **Username**: `admin`
* **Password**: `admin123`

### Example User

* **Username**: `JonSnow`
* **Password**: `password123`

To create these accounts, upload hash, and create the database, run:

```bash
flask init-db
flask seed-users
flask seed-threats
```

---

## How to Use

### User Dashboard

1. Log in using user credentials.
2. Upload your log file.
3. View detection results in table format:

   * Known Threats
   * Suspicious Behavior
   * Normal Activity

### Admin Dashboard

1. Log in using admin credentials.
2. View all user alerts and logs.
3. Use the dropdown to sort logs by timestamp, user, IP, or action.
4. Monitor threat severity visually.

---

## Deployment Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/raycel-maratas/cybersecurity-threat-detection.git
```

### 2. Create and Activate a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Environment Variables

```bash
export FLASK_APP=app
export FLASK_ENV=development
```

### 5. Initialize the Database

```bash
flask db init
flask db migrate
flask db upgrade
```

### 6. Seed Default Users and ThreatHash Table

```bash
flask seed-users
flask seed-threats
```

### 7. Run the Application

```bash
flask run
```

Open your browser and navigate to:
[http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Notes

* The system uses SQLite for local storage.
* Alerts and log data are stored in the database and displayed dynamically.
* The system is designed for testing and demonstration using simulated.


