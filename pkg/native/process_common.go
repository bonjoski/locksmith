package native

import (
	"os"
	"path/filepath"
	"strings"
)

type ProcessInfo struct {
	Path       string
	Identifier string
	TeamID     string
}

var shellBinaries = map[string]bool{
	"sh":   true,
	"bash": true,
	"zsh":  true,
	"fish": true,
	"dash": true,
	"ksh":  true,
	"tcsh": true,
}

// GetCallingProcessInfo walks up the process tree starting from the parent of the current process.
// It skips common shell interpreters to identify the actual application/process that invoked the command.
func GetCallingProcessInfo() (*ProcessInfo, error) {
	pid := os.Getppid()
	depth := 0
	maxDepth := 5

	var lastInfo *ProcessInfo

	for pid > 1 && depth < maxDepth {
		info, err := getProcessInfo(pid)
		if err != nil {
			break
		}
		lastInfo = info

		binName := filepath.Base(info.Path)
		if !shellBinaries[strings.ToLower(binName)] {
			return info, nil
		}

		parentPID, err := getParentPID(pid)
		if err != nil || parentPID <= 1 {
			break
		}
		pid = parentPID
		depth++
	}

	if lastInfo != nil {
		return lastInfo, nil
	}
	return getProcessInfo(os.Getppid())
}
