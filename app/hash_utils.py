import os
import hashlib
import binascii

def hash_password(password):
    salt = os.urandom(16)
    pwdhash = hashlib.sha256(salt + password.encode('utf-8')).digest()
    return binascii.hexlify(salt + pwdhash).decode('utf-8')

def verify_password(stored_password, provided_password):
    stored_password = binascii.unhexlify(stored_password.encode('utf-8'))
    salt = stored_password[:16]
    stored_hash = stored_password[16:]
    pwdhash = hashlib.sha256(salt + provided_password.encode('utf-8')).digest()
    return pwdhash == stored_hash

def is_malware_hash(h):
    from app.models import ThreatHash
    if not h:
        return False
    return ThreatHash.query.filter_by(hash_value=h.strip()).first() is not None