//go:build windows

package permcheck

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"golang.org/x/sys/windows"
)

// needsMigration is the Windows-specific implementation of [NeedsMigration].
func needsMigration(ctx context.Context, l *slog.Logger, workDir, _ string) (ok bool) {
	dacl, owner, err := getSecurityInfo(workDir)
	if err != nil {
		l.ErrorContext(ctx, "getting security info", slogutil.KeyError, err)

		return true
	}

	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}

	err = rangeACEs(dacl, func(
		hdr windows.ACE_HEADER,
		mask windows.ACCESS_MASK,
		sid *windows.SID,
	) (cont bool) {
		switch {
		case hdr.AceType != windows.ACCESS_ALLOWED_ACE_TYPE:
			// Skip non-allowed access control entries.
		case !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			// Non-administrator access control entries should not have any
			// access rights.
			ok = mask > 0
		default:
			// Administrators should have full control.
			ok = mask&fullControlMask != fullControlMask
		}

		// Stop ranging if the access control entry is unexpected.
		return !ok
	})
	if err != nil {
		l.ErrorContext(ctx, "checking access control entries", slogutil.KeyError, err)

		return true
	}

	return ok
}

// migrate is the Windows-specific implementation of [Migrate].
func migrate(ctx context.Context, l *slog.Logger, workDir, _, _, _, _ string) {
	dacl, owner, err := getSecurityInfo(workDir)
	if err != nil {
		l.ErrorContext(ctx, "getting security info", slogutil.KeyError, err)

		return
	}

	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		var admins *windows.SID
		admins, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			l.ErrorContext(ctx, "creating administrators sid", slogutil.KeyError, err)
		} else {
			l.InfoContext(ctx, "migrating working directory owner", "sid", admins)
			owner = admins
		}
	}

	// TODO(e.burkov):  Check for duplicates?
	var accessEntries []windows.EXPLICIT_ACCESS
	err = rangeACEs(dacl, func(
		hdr windows.ACE_HEADER,
		mask windows.ACCESS_MASK,
		sid *windows.SID,
	) (cont bool) {
		switch {
		case hdr.AceType != windows.ACCESS_ALLOWED_ACE_TYPE:
			// Add non-allowed access control entries as is.
			l.InfoContext(ctx, "migrating deny control entry", "sid", sid)
			accessEntries = append(accessEntries, newDenyExplicitAccess(sid, mask))
		case !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			// Skip non-administrator ACEs.
			l.InfoContext(ctx, "removing access control entry", "sid", sid)
		default:
			l.InfoContext(ctx, "migrating access control entry", "sid", sid, "mask", mask)
			accessEntries = append(accessEntries, newFullExplicitAccess(sid))
		}

		return true
	})
	if err != nil {
		l.ErrorContext(ctx, "ranging trough access control entries", slogutil.KeyError, err)

		return
	}

	err = setSecurityInfo(workDir, owner, accessEntries)
	if err != nil {
		l.ErrorContext(ctx, "setting security info", slogutil.KeyError, err)
	}
}
