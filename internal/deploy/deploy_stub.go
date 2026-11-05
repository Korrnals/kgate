//go:build !kgate_real_payload

package deploy

import _ "embed"

// Payload is the committed 45-byte stub: default builds (CI, release
// binaries from clean checkouts) carry no stack and refuse `kgate deploy`
// loudly via payloadIsPlaceholder. Local deploy builds use
// `-tags kgate_real_payload` (see deploy_real.go / Makefile `build`).
//
//go:embed payload.embed.tgz
var Payload []byte
