//go:build windows

package permcheck

import (
	"fmt"
	"unsafe"

	"github.com/AdguardTeam/golibs/errors"
	"golang.org/x/sys/windows"
)

// securityInfo defines the parts of a security descriptor to retrieve and set.
const securityInfo windows.SECURITY_INFORMATION = windows.OWNER_SECURITY_INFORMATION |
	windows.DACL_SECURITY_INFORMATION |
	windows.PROTECTED_DACL_SECURITY_INFORMATION |
	windows.UNPROTECTED_DACL_SECURITY_INFORMATION

// objectType is the type of the object for directories in context of security
// API.
const objectType = windows.SE_FILE_OBJECT

// fileDeleteChildRight is the mask bit for the right to delete a child object.
// It seems to be missing from the windows package.
//
// See https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/access-mask.
const fileDeleteChildRight = 0b1000000

// fullControlMask is the mask for full control access rights.
const fullControlMask windows.ACCESS_MASK = windows.FILE_LIST_DIRECTORY |
	windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_READ_EA |
	windows.FILE_WRITE_EA |
	windows.FILE_TRAVERSE |
	fileDeleteChildRight |
	windows.FILE_READ_ATTRIBUTES |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.DELETE |
	windows.READ_CONTROL |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.SYNCHRONIZE

// aceFunc is a function that handles access control entries in the
// discretionary access control list.  It should return true to continue
// iterating over the entries, or false to stop.
type aceFunc = func(
	hdr windows.ACE_HEADER,
	mask windows.ACCESS_MASK,
	sid *windows.SID,
) (cont bool)

// rangeACEs ranges over the access control entries in the discretionary access
// control list of the specified security descriptor and calls f for each one.
func rangeACEs(dacl *windows.ACL, f aceFunc) (err error) {
	var errs []error
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		err = windows.GetAce(dacl, i, &ace)
		if err != nil {
			errs = append(errs, fmt.Errorf("getting entry at index %d: %w", i, err))

			continue
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !f(ace.Header, ace.Mask, sid) {
			break
		}
	}

	if err = errors.Join(errs...); err != nil {
		return fmt.Errorf("checking access control entries: %w", err)
	}

	return nil
}

// setSecurityInfo sets the security information on the specified file, using
// ents to create a discretionary access control list.
func setSecurityInfo(fname string, owner *windows.SID, ents []windows.EXPLICIT_ACCESS) (err error) {
	if len(ents) == 0 {
		ents = []windows.EXPLICIT_ACCESS{
			newFullExplicitAccess(owner),
		}
	}

	acl, err := windows.ACLFromEntries(ents, nil)
	if err != nil {
		return fmt.Errorf("creating access control list: %w", err)
	}

	err = windows.SetNamedSecurityInfo(fname, objectType, securityInfo, owner, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("setting security info: %w", err)
	}

	return nil
}

// getSecurityInfo retrieves the security information for the specified file.
func getSecurityInfo(fname string) (dacl *windows.ACL, owner *windows.SID, err error) {
	sd, err := windows.GetNamedSecurityInfo(fname, objectType, securityInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("getting security descriptor: %w", err)
	}

	owner, _, err = sd.Owner()
	if err != nil {
		return nil, nil, fmt.Errorf("getting owner sid: %w", err)
	}

	dacl, _, err = sd.DACL()
	if err != nil {
		return nil, nil, fmt.Errorf("getting discretionary access control list: %w", err)
	}

	return dacl, owner, nil
}

// newFullExplicitAccess creates a new explicit access entry with full control
// permissions.
func newFullExplicitAccess(sid *windows.SID) (accEnt windows.EXPLICIT_ACCESS) {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: fullControlMask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// newDenyExplicitAccess creates a new explicit access entry with specified deny
// permissions.
func newDenyExplicitAccess(
	sid *windows.SID,
	mask windows.ACCESS_MASK,
) (accEnt windows.EXPLICIT_ACCESS) {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
