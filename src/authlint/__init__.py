"""authlint: audit OAuth 2.0 and OpenID Connect deployments against RFC 9700."""

__version__ = "0.1.1"

from .client import check_client  # noqa: E402
from .findings import SEVERITIES, Finding  # noqa: E402
from .jwks import check_jwks  # noqa: E402
from .provider import check_provider  # noqa: E402
from .rules import RULES  # noqa: E402

__all__ = ["RULES", "SEVERITIES", "Finding", "__version__", "check_client", "check_jwks", "check_provider"]
