import subprocess

# PLANTED VULNERABILITY (do not "fix"): the untrusted `cmd` argument is executed through
# `subprocess.run(..., shell=True)`, so payloads like `; echo RAEUBER_x` are directly passed to
# `/bin/sh`. This fixture must be exploitable so the lane canary remains LIVE (or it is quarantined).
def run(cmd):
  return subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True).stdout
