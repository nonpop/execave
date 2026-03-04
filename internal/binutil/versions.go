package binutil

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// PinnedBwrapVersion is the known-good bwrap version (0.11.0).
//
//nolint:gochecknoglobals // package-level constant-like value
var PinnedBwrapVersion = [3]int{0, 11, 0}

// PinnedStraceVersion is the known-good strace version (6.19).
//
//nolint:gochecknoglobals // package-level constant-like value
var PinnedStraceVersion = [2]int{6, 19}

// compatLevel represents a version compatibility tier.
type compatLevel int

const (
	compatError compatLevel = iota // incompatible — error
	compatWarn                     // higher minor within major — warn but continue
	compatOK                       // exact minor series match — no warning
)

// straceVersionRe extracts the first MAJOR.MINOR pair from any line.
var straceVersionRe = regexp.MustCompile(`(\d+)\.(\d+)`) //nolint:gochecknoglobals

// bwrapVersionRe matches "X.Y.Z" and captures the three version components.
var bwrapVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`) //nolint:gochecknoglobals

// CheckBwrapVersion runs bwrap --version at path and returns a compatibility assessment.
//
// Returns ("", nil) for OK tier, (warning, nil) for WARN tier, ("", err) for ERROR tier.
// path must be the absolute path to the bwrap binary, already validated by ValidateBinary.
func CheckBwrapVersion(path string) (string, error) {
	out, err := exec.Command(path, "--version").Output() // #nosec G204 -- path validated by ValidateBinary
	if err != nil {
		return "", fmt.Errorf("run %s --version: %w", path, err)
	}

	v, err := parseBwrapVersion(string(out))
	if err != nil {
		return "", fmt.Errorf("parse bwrap version: %w", err)
	}

	switch bwrapCompatLevel(v) {
	case compatOK:
		return "", nil
	case compatWarn:
		return fmt.Sprintf("bwrap version %d.%d.%d differs from pinned %d.%d.%d; sandbox behavior may differ",
			v[0], v[1], v[2], PinnedBwrapVersion[0], PinnedBwrapVersion[1], PinnedBwrapVersion[2]), nil
	case compatError:
		return "", fmt.Errorf("incompatible bwrap version %d.%d.%d (pinned: %d.%d.%d)",
			v[0], v[1], v[2], PinnedBwrapVersion[0], PinnedBwrapVersion[1], PinnedBwrapVersion[2])
	}
	panic("unexpected compat level")
}

// CheckStraceVersion runs strace --version at path and returns a compatibility assessment.
//
// Returns ("", nil) for OK tier, (warning, nil) for WARN tier, ("", err) for ERROR tier.
// path must be the absolute path to the strace binary, already validated by ValidateBinary.
func CheckStraceVersion(path string) (string, error) {
	out, err := exec.Command(path, "--version").Output() // #nosec G204 -- path validated by ValidateBinary
	if err != nil {
		return "", fmt.Errorf("run %s --version: %w", path, err)
	}

	v, err := parseStraceVersion(string(out))
	if err != nil {
		return "", fmt.Errorf("parse strace version: %w", err)
	}

	switch straceCompatLevel(v) {
	case compatOK:
		return "", nil
	case compatWarn:
		return fmt.Sprintf("strace version %d.%d differs from pinned %d.%d; output format may differ",
			v[0], v[1], PinnedStraceVersion[0], PinnedStraceVersion[1]), nil
	case compatError:
		return "", fmt.Errorf("incompatible strace version %d.%d (pinned: %d.%d)",
			v[0], v[1], PinnedStraceVersion[0], PinnedStraceVersion[1])
	}
	panic("unexpected compat level")
}

// parseBwrapVersion extracts the version from bwrap --version output.
func parseBwrapVersion(output string) ([3]int, error) {
	line, _, _ := strings.Cut(output, "\n")
	m := bwrapVersionRe.FindStringSubmatch(line)
	if m == nil {
		return [3]int{}, fmt.Errorf("unexpected output %q", line)
	}
	var v [3]int
	for i, s := range m[1:] {
		v[i], _ = strconv.Atoi(s) // \d+ guarantees success
	}
	return v, nil
}

// parseStraceVersion extracts the first MAJOR.MINOR version match from strace --version output.
func parseStraceVersion(output string) ([2]int, error) {
	m := straceVersionRe.FindStringSubmatch(output)
	if m == nil {
		return [2]int{}, fmt.Errorf("no version found in output")
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return [2]int{major, minor}, nil
}

// bwrapCompatLevel returns the compatibility tier for a bwrap version.
//
// Tiers:
//   - OK:    0.11.x (same minor as pinned)
//   - WARN:  0.12.x–0.99.x (higher minor within 0.x)
//   - ERROR: < 0.11.0 or ≥ 1.0.0
func bwrapCompatLevel(v [3]int) compatLevel {
	if v[0] != PinnedBwrapVersion[0] {
		return compatError
	}
	if v[1] < PinnedBwrapVersion[1] {
		return compatError
	}
	if v[1] == PinnedBwrapVersion[1] {
		return compatOK
	}
	return compatWarn
}

// straceCompatLevel returns the compatibility tier for a strace version.
//
// Tiers:
//   - OK:    6.19 (exact match)
//   - WARN:  6.20–6.x (higher minor within major 6)
//   - ERROR: < 6.19 or ≥ 7.0
func straceCompatLevel(v [2]int) compatLevel {
	if v[0] != PinnedStraceVersion[0] {
		return compatError
	}
	if v[1] < PinnedStraceVersion[1] {
		return compatError
	}
	if v[1] == PinnedStraceVersion[1] {
		return compatOK
	}
	return compatWarn
}
