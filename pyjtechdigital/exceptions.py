"""J-Tech Digital HDMI Matrix exceptions."""


class JtechError(Exception):
    """Base Jtech exception."""


class JtechAuthError(JtechError):
    """Raised to indicate auth error."""


class JtechNotSupported(JtechError):
    """Raised to indicate not supported error."""


class JtechConnectionError(JtechError):
    """Raised to indicate connection error."""


class JtechConnectionTimeout(JtechError):
    """Raised to indicate connection timeout."""


class JtechTurnedOff(JtechError):
    """Raised to indicate that matrix is turned off and do not respond."""


class JtechInvalidSource(JtechError):
    """Raised to indicate invalid source error."""


class JtechInvalidOutput(JtechError):
    """Raised to indicate invalid output error."""


class JtechOptionError(JtechError):
    """Raised to indicate option error."""