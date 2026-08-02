---
"@vex-chat/libvex": patch
"@vex-chat/spire": patch
---

Harden websocket ingress: malformed message frames and auth-handler failures now drop the offending connection instead of crashing the server process or the host application.
