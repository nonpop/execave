// Package textlog provides a text-based access log writer that subscribes to an
// accesslog.Logger, applies filtering, and writes formatted entries to an io.Writer.
//
// Filtering: by default, OK entries are hidden (denied-only) and entries matching
// nolog rules are hidden. Both behaviours can be overridden via showAllowed and
// showNolog constructor parameters.
package textlog

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/logfilter"
	"github.com/nonpop/execave/internal/netrules"
)

// Writer subscribes to an access logger and writes formatted entries to an io.Writer.
type Writer struct {
	out         io.Writer
	homeDir     string
	configDir   string
	showAllowed bool
	showNolog   bool
	fsRes       *fsrules.LogResolver
	netRes      *netrules.LogResolver
}

// New creates a Writer that writes access log entries to out.
// homeDir and configDir are used to shorten filesystem paths for display;
// pass empty strings to disable shortening.
// showAllowed includes OK entries when true (default: denied-only).
// showNolog includes entries matching nolog rules when true (default: hidden).
// fsRes and netRes may be nil if no log rules are configured.
func New(out io.Writer, homeDir, configDir string, showAllowed, showNolog bool, fsRes *fsrules.LogResolver, netRes *netrules.LogResolver) *Writer {
	return &Writer{
		out:         out,
		homeDir:     homeDir,
		configDir:   configDir,
		showAllowed: showAllowed,
		showNolog:   showNolog,
		fsRes:       fsRes,
		netRes:      netRes,
	}
}

// Run subscribes to logger and writes matching entries until ctx is cancelled.
// On cancellation, performs a final drain to capture any remaining entries.
// Blocks until ctx is done. Returns the first write error encountered.
func (w *Writer) Run(ctx context.Context, logger *accesslog.Logger) error {
	entryCh := logger.Subscribe()
	defer logger.Unsubscribe(entryCh)

	lastSeen := 0
	for {
		select {
		case <-ctx.Done():
			return w.drain(logger, &lastSeen)
		case <-entryCh:
			if err := w.drain(logger, &lastSeen); err != nil {
				return err
			}
		}
	}
}

// drain writes any entries after lastSeen that pass filters, then advances lastSeen.
func (w *Writer) drain(logger *accesslog.Logger, lastSeen *int) error {
	entries := logger.Entries()
	for i := *lastSeen; i < len(entries); i++ {
		if err := w.writeIfVisible(entries[i]); err != nil {
			return err
		}
	}
	*lastSeen = len(entries)
	return nil
}

// writeIfVisible writes entry to w.out if it passes the configured filters.
func (w *Writer) writeIfVisible(entry accesslog.Entry) error {
	if !w.showAllowed && entry.Result == accesslog.ResultOK {
		return nil
	}
	if !w.showNolog && logfilter.IsNolog(entry, w.fsRes, w.netRes) {
		return nil
	}
	_, err := fmt.Fprintf(w.out, "%s\n", w.formatEntry(entry))
	if err != nil {
		return fmt.Errorf("write entry: %w", err)
	}
	return nil
}

// formatEntry formats a single entry as a line of text.
// Format: %-7s %-5s  %s  (%s)
// Example: DENY    READ   ~/.ssh/id_rsa  (no-matching-rule).
func (w *Writer) formatEntry(entry accesslog.Entry) string {
	target := entry.Target
	if (entry.Operation == accesslog.OperationRead || entry.Operation == accesslog.OperationWrite) && filepath.IsAbs(target) {
		target = logfilter.ShortenPath(target, w.homeDir, w.configDir)
	}
	return fmt.Sprintf("%-7s %-5s  %s  (%s)", entry.Result, entry.Operation, target, entry.Rule)
}
