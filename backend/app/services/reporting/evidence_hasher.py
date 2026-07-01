"""SHA-256 evidence hashing for integrity verification."""

import hashlib


def hash_evidence(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def hash_evidence_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def hash_evidence_dict(data: dict) -> str:
    import json
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hash_evidence(serialized)


def verify_evidence(content: str, expected_hash: str) -> bool:
    return hash_evidence(content) == expected_hash
