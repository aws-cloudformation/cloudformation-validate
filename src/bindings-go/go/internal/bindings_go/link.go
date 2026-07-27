package bindings_go

// Hand-maintained cgo configuration, copied next to the generated bindings by
// build.sh. Links the Rust static library staged by build.sh under
// go/libs/<os>-<arch>/, using the same platform tokens as the other bindings.

// #cgo CFLAGS: -I${SRCDIR}
// #cgo darwin,arm64 LDFLAGS: ${SRCDIR}/../../libs/darwin-aarch64/libbindings_go.a
// #cgo linux,amd64 LDFLAGS: ${SRCDIR}/../../libs/linux-x86-64/libbindings_go.a -lm
// #cgo windows,amd64 LDFLAGS: ${SRCDIR}/../../libs/win32-x86-64/libbindings_go.a -lws2_32 -luserenv -lbcrypt -lntdll
import "C"
