---
"@vex-chat/spire": patch
"@vex-chat/libvex": patch
---

Harden WebSocket authentication and connection cleanup, and reduce repeated database work when notifying group members. Accept intended call signaling payloads consistently at both WebSocket limits.

Preserve current encrypted-session state when delayed messages arrive from an older ratchet epoch, validate ratchet headers and counters, and speed up skipped-message key handling. Save encrypted credentials atomically and correctly remove repeated WebSocket listeners.

Update vulnerable dependencies to patched releases.
