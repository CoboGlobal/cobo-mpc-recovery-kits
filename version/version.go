package version

import "fmt"

// These constants define the application version.
const (
	Major = 0
	Minor = 1
	Patch = 7
)

func TextVersion() string {
	version := fmt.Sprintf("%d.%d.%d", Major, Minor, Patch)
	return version
}
