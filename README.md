# Extension-Threat-Detector-ETD-
# Extension Watchdog 🔒
> Real-time Chrome Extension Traffic Monitor and Suspicious Activity Detector

**Extension Watchdog** is a powerful tool built with **mitmproxy** and **Python** that monitors Chrome extension network traffic in real-time, detects suspicious activities like **keylogging**, **screenshot capturing**, **large payload uploads**, and identifies **image uploads**.  
It alerts the user immediately via desktop notifications to potential threats, helping you stay safe from malicious browser extensions.

---

## 🚀 Features
- ✅ Detects suspicious keywords (e.g., `keylog`, `capture`, `screenshot`) in network requests and responses.
- ✅ Alerts if payload size exceeds a safe threshold (default: **100KB**).
- ✅ Detects if network traffic involves **images** (e.g., JPEG, PNG uploads).
- ✅ Focuses only on **Chrome Extension** related traffic.
- ✅ Sends **Windows popup alerts** for suspicious activities.
- ✅ Lightweight and runs seamlessly in the background.
- ✅ Fully **open-source** and **extensible**.

---

## 🛠 How It Works
- Hooks into HTTP(S) traffic using **mitmproxy**.
- Filters requests and responses from `chrome-extension://` URLs or headers.
- Scans:
  - URL
  - HTTP headers
  - Request/Response body content
- Checks for:
  - Suspicious patterns (keylogging, screenshots, etc.)
  - Large payload uploads
  - Image uploads (based on Content-Type or file extensions)
- Triggers a **Windows desktop alert** when suspicious activity is found.

---
# 🛠 Install Dependencies

```bash
pip install mitmproxy
```

# ▶️ Usage

Run the script with mitmproxy:

```bash
mitmproxy -s extension_watchdog.py
```

- Open Chrome with your extensions installed.
- Configure your system/browser to use mitmproxy as HTTP proxy (default: `127.0.0.1:8080`).
- Watch for real-time alerts if any suspicious extension activity is detected.

# ⚙️ Configuration

- Suspicious patterns are defined in the `SUSPICIOUS_PATTERNS` list inside the script.  
  You can add or remove patterns based on your needs.

- Payload size threshold is configurable (default: 100 KB):

```python
PAYLOAD_SIZE_THRESHOLD = 100 * 1024  # 100 KB
```

# 📋 Example Alert

🚨 **Suspicious Extension Request Detected!**

```
Request Body matched keylog
URL: chrome-extension://abcd1234/somepath/keylogger.js
```

# 🧩 Requirements

- Python 3.7+
- mitmproxy
- Windows OS (for popup alerts via ctypes)

# 📢 Important Notes

- Make sure SSL/TLS interception is enabled if you want to inspect HTTPS traffic.
- Some Chrome extensions may encrypt their traffic, which could make detection harder.

# 🤝 Contributing

Contributions are welcome!  
Feel free to open issues, pull requests, or suggestions to improve **Extension Watchdog**.

# 📜 License

This project is licensed under the **MIT License**.

# 🙏 Acknowledgements

- Thanks to **mitmproxy** for providing the awesome proxy framework.
- Inspiration from various browser security research papers and tools.
