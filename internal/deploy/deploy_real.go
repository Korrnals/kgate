//go:build kgate_real_payload

package deploy

import _ "embed"

// Payload is the REAL deploy payload (kgate arm64 + sing-box + configs)
// built by `make payload` into internal/deploy/payload.tgz. Only local
// `-tags kgate_real_payload` builds embed it: the file is gitignored
// (carries live credentials) and must never reach release artifacts or
// commits — the v1.3.1 incident class.
//
//go:embed payload.tgz
var Payload []byte
