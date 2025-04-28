from mitmproxy import http
from mitmproxy import ctx
import win32api
import re
import threading

# Keywords to detect suspicious extension data (e.g., keylogging, screen capture)
SUSPICIOUS_PATTERNS = [
    r"keylog",
    r"keystroke",
    r"screenshot",
    r"screen_capture",
    r"keyevent",
    r"keyboard",
    r"capture",
]

# Patterns to identify Chrome extension requests
EXTENSION_INDICATORS = [
    r"chrome-extension://",  # Extension-specific URLs
    r"extension",           # Generic extension-related keywords
]

class NetworkAlert:
    def show_alert(self, title, message):
        """Show a Windows pop-up message in a separate thread."""
        def alert_task():
            try:
                win32api.MessageBox(0, message, title, 0x00001000)  # MB_OK | MB_SYSTEMMODAL
            except Exception as e:
                ctx.log.warn(f"Failed to show message box: {e}")
        
        # Run in a separate thread to avoid blocking mitmproxy
        threading.Thread(target=alert_task, daemon=True).start()

    def request(self, flow: http.HTTPFlow):
        """Inspect outgoing requests."""
        self.check_flow(flow, "request")

    def check_flow(self, flow: http.HTTPFlow, flow_type: str):
        """Check the flow for suspicious extension-related data."""
        url = flow.request.pretty_url
        headers = dict(flow.request.headers)
        content = flow.request.content

        # Skip localhost or internal requests
        if "localhost" in url or "127.0.0.1" in url:
            return

        # Check if the request is likely from a Chrome extension
        is_extension = False
        user_agent = headers.get("User-Agent", "").lower()
        for indicator in EXTENSION_INDICATORS:
            if indicator in url or indicator in user_agent:
                is_extension = True
                break

        # If it's an extension request, check for suspicious patterns
        if is_extension:
            # Check URL for suspicious patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    self.show_alert(
                        "Suspicious Extension Activity",
                        f"Suspicious {flow_type} detected!\nURL: {url}\nPattern: {pattern}"
                    )
                    ctx.log.info(f"Suspicious extension {flow_type} URL: {url}")
                    return

            # Check headers for suspicious patterns
            for header, value in headers.items():
                for pattern in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        self.show_alert(
                            "Suspicious Extension Activity",
                            f"Suspicious {flow_type} detected!\nHeader: {header}: {value}\nPattern: {pattern}"
                        )
                        ctx.log.info(f"Suspicious extension {flow_type} header: {header}: {value}")
                        return

            # Check content for suspicious patterns (if available)
            if content:
                try:
                    content_str = content.decode("utf-8", errors="ignore")
                    for pattern in SUSPICIOUS_PATTERNS:
                        if re.search(pattern, content_str, re.IGNORECASE):
                            self.show_alert(
                                "Suspicious Extension Activity",
                                f"Suspicious {flow_type} detected!\nContent contains: {pattern}\nURL: {url}"
                            )
                            ctx.log.info(f"Suspicious extension {flow_type} content in: {url}")
                            return
                except Exception as e:
                    ctx.log.warn(f"Error decoding content: {e}")

# Register the addon
addons = [NetworkAlert()]

if __name__ == "__main__":
    print("Run this script with mitmproxy: `mitmdump -s mitm_alert_win32.py -p 8080`")