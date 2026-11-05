//go:build kgate_real_payload

package deploy

import _ "embed"

// Payload is the deploy payload (kgate arm64 + sing-box + configs) built by
// `make payload` (local/etc — real credentials, operator machine only) or
// `make payload-release` (examples/etc — sanitized placeholders, used by the
// release pipeline so release binaries can deploy the stack). The file
// internal/deploy/payload.tgz is gitignored and must never reach commits —
// the v1.3.1 incident class.
//
//go:embed payload.tgz
var Payload []byte
