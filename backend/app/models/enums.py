import enum


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    RETEST_REQUIRED = "retest_required"


class AttackVector(str, enum.Enum):
    NETWORK = "network"
    ADJACENT = "adjacent"
    LOCAL = "local"
    PHYSICAL = "physical"


class AttackComplexity(str, enum.Enum):
    LOW = "low"
    HIGH = "high"


class PrivilegesRequired(str, enum.Enum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"


class UserInteraction(str, enum.Enum):
    NONE = "none"
    REQUIRED = "required"
