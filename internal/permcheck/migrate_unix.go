//go:build unix

package permcheck

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// needsMigration is a Unix-specific implementation of [NeedsMigration].
//
// TODO(a.garipov):  Consider ways to detect this better.
func needsMigration(ctx context.Context, l *slog.Logger, _, confFilePath string) (ok bool) {
	s, err := os.Stat(confFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Likely a first run.  Don't check.
			return false
		}

		l.ErrorContext(ctx, "checking a need for permission migration", slogutil.KeyError, err)

		// Unexpected error.  Try to migrate just in case.
		return true
	}

	return s.Mode().Perm() != aghos.DefaultPermFile
}

// migrate is a Unix-specific implementation of [Migrate].
func migrate(
	ctx context.Context,
	l *slog.Logger,
	workDir string,
	dataDir string,
	statsDir string,
	querylogDir string,
	confFilePath string,
) {
	dirLoggger, fileLogger := l.With("type", typeDir), l.With("type", typeFile)

	chmodDir(ctx, dirLoggger, workDir)

	chmodFile(ctx, fileLogger, confFilePath)

	// TODO(a.garipov): Put all paths in one place and remove this duplication.
	chmodDir(ctx, dirLoggger, dataDir)
	chmodDir(ctx, dirLoggger, filepath.Join(dataDir, "filters"))
	chmodFile(ctx, fileLogger, filepath.Join(dataDir, "sessions.db"))
	chmodFile(ctx, fileLogger, filepath.Join(dataDir, "leases.json"))

	if dataDir != querylogDir {
		chmodDir(ctx, dirLoggger, querylogDir)
	}
	chmodFile(ctx, fileLogger, filepath.Join(querylogDir, "querylog.json"))
	chmodFile(ctx, fileLogger, filepath.Join(querylogDir, "querylog.json.1"))

	if dataDir != statsDir {
		chmodDir(ctx, dirLoggger, statsDir)
	}
	chmodFile(ctx, fileLogger, filepath.Join(statsDir, "stats.db"))
}

// chmodDir changes the permissions of a single directory.  The results are
// logged at the appropriate level.
func chmodDir(ctx context.Context, l *slog.Logger, dirPath string) {
	chmodPath(ctx, l, dirPath, aghos.DefaultPermDir)
}

// chmodFile changes the permissions of a single file.  The results are logged
// at the appropriate level.
func chmodFile(ctx context.Context, l *slog.Logger, filePath string) {
	chmodPath(ctx, l, filePath, aghos.DefaultPermFile)
}

// chmodPath changes the permissions of a single filesystem entity.  The results
// are logged at the appropriate level.
func chmodPath(ctx context.Context, l *slog.Logger, fpath string, fm fs.FileMode) {
	var lvl slog.Level
	var msg string
	args := []any{"path", fpath}

	switch err := os.Chmod(fpath, fm); {
	case err == nil:
		lvl = slog.LevelInfo
		msg = "changed permissions"
	case errors.Is(err, os.ErrNotExist):
		lvl = slog.LevelDebug
		msg = "checking permissions"
		args = append(args, slogutil.KeyError, err)
	default:
		lvl = slog.LevelError
		msg = "cannot change permissions; this can leave your system vulnerable, see " +
			"https://adguard-dns.io/kb/adguard-home/running-securely/#os-service-concerns"
		args = append(args, "target_perm", fmt.Sprintf("%#o", fm), slogutil.KeyError, err)
	}

	l.Log(ctx, lvl, msg, args...)
}
