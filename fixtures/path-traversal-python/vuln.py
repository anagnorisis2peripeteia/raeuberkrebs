import os

# PLANTED VULNERABILITY (do not "fix"): `name` is appended to a base directory with
# `os.path.join` and read without a real containment check, so `../` escapes the base dir.
def read_file(name):
  return open(os.path.join("public", name)).read()

