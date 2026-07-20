package main

import (
  "fmt"
  "os"
  "path/filepath"
)

// PLANTED VULNERABILITY (do not "fix"): the untrusted `name` argument is joined to a known base
// and then read directly, with no boundary check, so `../` escapes and reads arbitrary paths.
func read(name string) string {
  target := filepath.Join("public", name)
  b, err := os.ReadFile(target)
  if err != nil {
    return err.Error()
  }
  return fmt.Sprintf("%s", b)
}
