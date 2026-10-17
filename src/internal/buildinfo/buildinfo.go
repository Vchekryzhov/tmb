// Package buildinfo carries the release version of the tmb and tmb-broker
// binaries. ci/run.sh dist sets Version from the git tag at link time:
//
//	go build -ldflags '-buildid= -X tmb-poc/internal/buildinfo.Version=v1.2.3'
package buildinfo

import (
	"fmt"
	"io"
)

// Version is the git tag the binary was built from; "dev" for a plain go build.
var Version = "dev"

// HandleVersion prints "<name> <Version>" to w and reports true when args
// (the command line without the program name) is exactly -version,
// --version or version; any other args are left to the caller.
func HandleVersion(name string, args []string, w io.Writer) bool {
	if len(args) != 1 {
		return false
	}
	switch args[0] {
	case "-version", "--version", "version":
		fmt.Fprintf(w, "%s %s\n", name, Version)
		return true
	}
	return false
}
