from enum import Enum

class ThreatLevel(Enum):
    OK = "OK"
    POLICY = "POLICY_VIOLATION"
    REPLAY = "REPLAY_ATTACK"
    INVALID_SIG = "INVALID_SIGNATURE"
    EVIL = "EVIL_EVENT"
