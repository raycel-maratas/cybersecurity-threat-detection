from app.alert_rules import ALERT_RULES

def evaluate(match):

    for rule in ALERT_RULES:
        if (
            rule["conditions"]["hash_match"] == match["hash_match"]
            and rule["conditions"]["anomaly"] == match["anomaly"]
        ):
            return {
                "type": rule["type"],
                "description": rule["description"],
                "severity": rule["severity"]
            }
    return None