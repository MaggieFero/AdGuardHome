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
	checkDir(ctx, l, workDir)

	checkFile(ctx, l, confFilePath)

	// TODO(a.garipov): Put all paths in one place and remove this duplication.
	checkDir(ctx, l, dataDir)
	checkDir(ctx, l, filepath.Join(dataDir, "filters"))
	checkFile(ctx, l, filepath.Join(dataDir, "sessions.db"))
	checkFile(ctx, l, filepath.Join(dataDir, "leases.json"))

	if dataDir != querylogDir {
		checkDir(ctx, l, querylogDir)
	}
	checkFile(ctx, l, filepath.Join(querylogDir, "querylog.json"))
	checkFile(ctx, l, filepath.Join(querylogDir, "querylog.json.1"))

	if dataDir != statsDir {
		checkDir(ctx, l, statsDir)
	}
	checkFile(ctx, l, filepath.Join(statsDir, "stats.db"))
}

// checkDir checks the permissions of a single directory.  The results are
// logged at the appropriate level.
func checkDir(ctx context.Context, l *slog.Logger, dirPath string) {
	checkPath(ctx, l, dirPath, typeDir, aghos.DefaultPermDir)
}

// checkFile checks the permissions of a single file.  The results are logged at
// the appropriate level.
func checkFile(ctx context.Context, l *slog.Logger, filePath string) {
	checkPath(ctx, l, filePath, typeFile, aghos.DefaultPermFile)
}

// checkPath checks the permissions of a single filesystem entity.  The results
// are logged at the appropriate level.
func checkPath(ctx context.Context, l *slog.Logger, entPath, fileType string, want fs.FileMode) {
	s, err := os.Stat(entPath)
	if err != nil {
		logFunc := l.ErrorContext
		if errors.Is(err, os.ErrNotExist) {
			logFunc = l.DebugContext
		}

		logFunc(
			ctx,
			"checking permissions",
			"type", fileType,
			"path", entPath,
			slogutil.KeyError, err,
		)

		return
	}

	// TODO(a.garipov): Add a more fine-grained check and result reporting.
	perm := s.Mode().Perm()
	if perm != want {
		l.WarnContext(
			ctx,
			"found unexpected permissions",
			"type", fileType,
			"path", entPath,
			"got", fmt.Sprintf("%#o", perm),
			"want", fmt.Sprintf("%#o", want),
		)
	}
}
