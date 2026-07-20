package main

import (
  "os/exec"
)

// PLANTED VULNERABILITY (do not "fix"): the untrusted `payload` argument is forwarded as the shell
// command tail, so payloads like `; echo RAEUBER_x` are executed by `/bin/sh -c`.
func run(payload string) string {
  out, err := exec.Command("sh", "-c", payload).CombinedOutput()
  if err != nil {
    return err.Error()
  }
  return string(out)
}
