# **# CyberTrack: Cybersecurity Threat Detection System**

CyberTrack is a Flask-based cybersecurity threat detection system that processes uploaded logs to identify known threats and suspicious behavior. It employs hashing and binary search algorithms to efficiently detect malicious activity, failed login attempts, and time-based anomalies.

---

## Features

* Role-based access for Admin and Users
* Log upload and parsing (CSV format)
* Hash-based malware detection
* Binary search anomaly detection
* Alert generation and database logging
* Failed login tracking and user account lockout
* Real-time dashboards for both Admin and Users

---

## User Accounts

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
git clone https://github.com/yourusername/cybertrack-threat-detection.git
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

### 6. Seed Default Users

```bash
flask seed-users
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


