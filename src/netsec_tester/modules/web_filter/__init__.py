"""Web filtering test modules."""

from netsec_tester.modules.web_filter.api_abuse import APIAbuseModule
from netsec_tester.modules.web_filter.categories import WebCategoryModule
from netsec_tester.modules.web_filter.http_smuggling import HTTPSmugglingModule
from netsec_tester.modules.web_filter.tls_inspection import TLSInspectionModule
from netsec_tester.modules.web_filter.url_patterns import URLPatternsModule
from netsec_tester.modules.web_filter.web_shells import WebShellsModule

__all__ = [
    "WebCategoryModule",
    "URLPatternsModule",
    "TLSInspectionModule",
    "APIAbuseModule",
    "WebShellsModule",
    "HTTPSmugglingModule",
]
