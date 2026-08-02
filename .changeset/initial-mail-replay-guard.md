---
"@vex-chat/libvex": patch
---

Fix initial-mail replay: redelivered handshake mail no longer rolls back the ratchet session or strips its verified flag, and re-sessions over unchanged identity keys now preserve verification state.
