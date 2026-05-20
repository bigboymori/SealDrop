
"""SealDrop exception types."""


class SealDropError(Exception):
    """Base class for all SealDrop errors."""


class ConfigError(SealDropError):
    """Raised on invalid user configuration or unsafe CLI choices."""


class PackageFormatError(SealDropError):
    """Raised when a package is malformed or unsupported."""


class AuthenticationError(SealDropError):
    """Raised when package authentication or key material is invalid."""


class SafetyError(SealDropError):
    """Raised when an extraction target violates safety checks."""
