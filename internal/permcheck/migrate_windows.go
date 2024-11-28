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
	l = l.With("type", typeDir, "path", workDir)

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
			l.DebugContext(ctx, "skipping deny access control entry", "sid", sid)
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
//
// It
func migrate(ctx context.Context, logger *slog.Logger, workDir, _, _, _, _ string) {
	l := logger.With("type", typeDir, "path", workDir)

	dacl, owner, err := getSecurityInfo(workDir)
	if err != nil {
		l.ErrorContext(ctx, "getting security info", slogutil.KeyError, err)

		return
	}

	owner, err = adminsIfNot(owner)
	switch {
	case err != nil:
		l.ErrorContext(ctx, "creating administrators sid", slogutil.KeyError, err)
	case owner == nil:
		l.DebugContext(ctx, "owner is already an administrator")
	default:
		l.InfoContext(ctx, "migrating owner", "sid", owner)
	}

	// TODO(e.burkov):  Check for duplicates?
	var accessEntries []windows.EXPLICIT_ACCESS
	var useACL bool
	// Iterate over the access control entries in DACL to determine if its
	// migration is needed.
	err = rangeACEs(dacl, func(
		hdr windows.ACE_HEADER,
		mask windows.ACCESS_MASK,
		sid *windows.SID,
	) (cont bool) {
		switch {
		case hdr.AceType != windows.ACCESS_ALLOWED_ACE_TYPE:
			// Add non-allowed access control entries as is, since they specify
			// the access restrictions, which shouldn't be lost.
			l.InfoContext(ctx, "migrating deny access control entry", "sid", sid)
			accessEntries = append(accessEntries, newDenyExplicitAccess(sid, mask))
			useACL = true
		case !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			// Remove non-administrator ACEs, since such accounts should not
			// have any access rights.
			l.InfoContext(ctx, "removing access control entry", "sid", sid)
			useACL = true
		default:
			// Administrators should have full control.  Don't add a new entry
			// here since it will be added later in case there are other
			// required entries.
			l.InfoContext(ctx, "migrating access control entry", "sid", sid, "mask", mask)
			useACL = useACL || mask&fullControlMask != fullControlMask
		}

		return true
	})
	if err != nil {
		l.ErrorContext(ctx, "ranging through access control entries", slogutil.KeyError, err)

		return
	}

	if useACL {
		accessEntries = append(accessEntries, newFullExplicitAccess(owner))
	}

	err = setSecurityInfo(workDir, owner, accessEntries)
	if err != nil {
		l.ErrorContext(ctx, "setting security info", slogutil.KeyError, err)
	}
}

// adminsIfNot returns the administrators SID if sid is not a
// [windows.WinBuiltinAdministratorsSid] yet, or nil if it is.
func adminsIfNot(sid *windows.SID) (admins *windows.SID, err error) {
	if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil, nil
	}

	return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
}
