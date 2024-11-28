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

// check is the Unix-specific implementation of [Check].
func check(
	ctx context.Context,
	l *slog.Logger,
	workDir string,
	dataDir string,
	statsDir string,
	querylogDir string,
	confFilePath string,
) {
	dirLoggger, fileLogger := l.With("type", typeDir), l.With("type", typeFile)

	checkDir(ctx, dirLoggger, workDir)

	checkFile(ctx, fileLogger, confFilePath)

	// TODO(a.garipov): Put all paths in one place and remove this duplication.
	checkDir(ctx, dirLoggger, dataDir)
	checkDir(ctx, dirLoggger, filepath.Join(dataDir, "filters"))
	checkFile(ctx, fileLogger, filepath.Join(dataDir, "sessions.db"))
	checkFile(ctx, fileLogger, filepath.Join(dataDir, "leases.json"))

	if dataDir != querylogDir {
		checkDir(ctx, dirLoggger, querylogDir)
	}
	checkFile(ctx, fileLogger, filepath.Join(querylogDir, "querylog.json"))
	checkFile(ctx, fileLogger, filepath.Join(querylogDir, "querylog.json.1"))

	if dataDir != statsDir {
		checkDir(ctx, dirLoggger, statsDir)
	}
	checkFile(ctx, fileLogger, filepath.Join(statsDir, "stats.db"))
}

// checkDir checks the permissions of a single directory.  The results are
// logged at the appropriate level.
func checkDir(ctx context.Context, l *slog.Logger, dirPath string) {
	checkPath(ctx, l, dirPath, aghos.DefaultPermDir)
}

// checkFile checks the permissions of a single file.  The results are logged at
// the appropriate level.
func checkFile(ctx context.Context, l *slog.Logger, filePath string) {
	checkPath(ctx, l, filePath, aghos.DefaultPermFile)
}

// checkPath checks the permissions of a single filesystem entity.  The results
// are logged at the appropriate level.
func checkPath(ctx context.Context, l *slog.Logger, fpath string, want fs.FileMode) {
	l = l.With("path", fpath)
	s, err := os.Stat(fpath)
	if err != nil {
		lvl := slog.LevelError
		if errors.Is(err, os.ErrNotExist) {
			lvl = slog.LevelDebug
		}

		l.Log(ctx, lvl, "checking permissions", slogutil.KeyError, err)

		return
	}

	// TODO(a.garipov): Add a more fine-grained check and result reporting.
	perm := s.Mode().Perm()
	if perm == want {
		return
	}

	permOct, wantOct := fmt.Sprintf("%#o", perm), fmt.Sprintf("%#o", want)
	l.WarnContext(ctx, "found unexpected permissions", "perm", permOct, "want", wantOct)
}
