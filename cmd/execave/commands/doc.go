// Package commands defines the Cobra command tree for execave.
//
// This is a thin CLI layer: argument validation, config struct assembly,
// and delegation to [run.Run]. All security-critical logic lives in the
// internal packages.
package commands
