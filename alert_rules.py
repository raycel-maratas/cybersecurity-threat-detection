# alert_rules.py

ALERT_RULES = [
    {
        "conditions": {"hash_match": True, "anomaly": True},
        "type": "Multi-Factor Threat",
        "description": "Detected hash match and abnormal behavior.",
        "severity": "High"
    },
    {
        "conditions": {"hash_match": True, "anomaly": False},
        "type": "Known Threat",
        "description": "IP/User matches threat database.",
        "severity": "High"
    },
    {
        "conditions": {"hash_match": False, "anomaly": True},
        "type": "Suspicious Behavior",
        "description": "Unusual access pattern or login time.",
        "severity": "Medium"
    },
    {
        "conditions": {"hash_match": False, "anomaly": False},
        "type": "Normal Activity",
        "description": "No known threat or unusual behavior.",
        "severity": "Low"
    }
]