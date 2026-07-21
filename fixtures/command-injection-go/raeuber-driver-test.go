package main

import (
  "encoding/base64"
  "fmt"
  "os"
)

func main() {
  payloadB64 := os.Getenv("RAEUBER_PAYLOAD_B64")
  payloadBytes, err := base64.StdEncoding.DecodeString(payloadB64)
  if err != nil {
    fmt.Print(err)
    return
  }
  payload := string(payloadBytes)
  defer func() {
    if recovered := recover(); recovered != nil {
      fmt.Print(recovered)
    }
  }()
  fmt.Print(run(payload))
}
