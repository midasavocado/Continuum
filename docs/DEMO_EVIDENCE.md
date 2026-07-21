# Reproduced Build Week demo evidence

This output was reproduced from commit `fdbea47` on July 21, 2026 before submission. The proof builds and signs its own controlled AppKit target, lets the original GUI process fully exit, restores the certified RAM capsule into a different PID, interacts with the replacement window, and verifies that the restore path did not change local files.

```text
gui-cold-proof: PASS
  original PID:    35974 (exited)
  replacement PID: 35978
  preflight:       replacement validated before original exit
  restored RAM:    0x140000000 = 222
  late-run-loop RAM: 0x140008000 = 510
  worker-thread RAM: 0x140010000 = 707
  Objective-C RAM: 0x140018000 = 805
  divergent future: 333 discarded with the original PID
  live mutation:   333 after restore
  WindowServer:    new functional window owned by replacement
  local files:     unchanged by restore
SIP status unchanged.
```

This is a controlled proof, not arbitrary-app certification. The branch intentionally fails closed outside the state classes named in the README.
