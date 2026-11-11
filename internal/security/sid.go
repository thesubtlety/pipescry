package security

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// Resolver maps a SID string to an account name. ok is false when unknown.
type Resolver func(sid string) (name string, ok bool)

var wellKnown = map[string]string{
	"S-1-0-0":      "NULL SID",
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "LOCAL",
	"S-1-3-0":      "CREATOR OWNER",
	"S-1-3-1":      "CREATOR GROUP",
	"S-1-3-4":      "OWNER RIGHTS",
	"S-1-5-1":      "NT AUTHORITY\\DIALUP",
	"S-1-5-2":      "NT AUTHORITY\\NETWORK",
	"S-1-5-3":      "NT AUTHORITY\\BATCH",
	"S-1-5-4":      "NT AUTHORITY\\INTERACTIVE",
	"S-1-5-6":      "NT AUTHORITY\\SERVICE",
	"S-1-5-7":      "NT AUTHORITY\\ANONYMOUS LOGON",
	"S-1-5-9":      "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS",
	"S-1-5-10":     "NT AUTHORITY\\SELF",
	"S-1-5-11":     "NT AUTHORITY\\Authenticated Users",
	"S-1-5-12":     "NT AUTHORITY\\RESTRICTED",
	"S-1-5-13":     "NT AUTHORITY\\TERMINAL SERVER USER",
	"S-1-5-14":     "NT AUTHORITY\\REMOTE INTERACTIVE LOGON",
	"S-1-5-15":     "NT AUTHORITY\\This Organization",
	"S-1-5-17":     "NT AUTHORITY\\IUSR",
	"S-1-5-18":     "NT AUTHORITY\\SYSTEM",
	"S-1-5-19":     "NT AUTHORITY\\LOCAL SERVICE",
	"S-1-5-20":     "NT AUTHORITY\\NETWORK SERVICE",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-32-547": "BUILTIN\\Power Users",
	"S-1-5-32-551": "BUILTIN\\Backup Operators",
	"S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
	"S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
	"S-1-5-32-559": "BUILTIN\\Performance Log Users",
	"S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
	"S-1-5-32-573": "BUILTIN\\Event Log Readers",
	"S-1-5-32-580": "BUILTIN\\Remote Management Users",
	"S-1-15-2-1":   "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES",
	"S-1-15-2-2":   "APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES",
	"S-1-16-0":     "Mandatory Label\\Untrusted Mandatory Level",
	"S-1-16-4096":  "Mandatory Label\\Low Mandatory Level",
	"S-1-16-8192":  "Mandatory Label\\Medium Mandatory Level",
	"S-1-16-12288": "Mandatory Label\\High Mandatory Level",
	"S-1-16-16384": "Mandatory Label\\System Mandatory Level",
}

var domainRIDs = map[uint32]string{
	500: "Administrator",
	501: "Guest",
	512: "Domain Admins",
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
}

// WellKnownName returns a fixed name for well-known SIDs and for the
// relative part of domain SIDs ("<domain>\Domain Users").
func WellKnownName(sid string) (string, bool) {
	if n, ok := wellKnown[sid]; ok {
		return n, true
	}
	if strings.HasPrefix(sid, "S-1-5-21-") {
		i := strings.LastIndexByte(sid, '-')
		rid, err := strconv.ParseUint(sid[i+1:], 10, 32)
		if err == nil && strings.Count(sid, "-") == 7 {
			if n, ok := domainRIDs[uint32(rid)]; ok {
				return "<domain>\\" + n, true
			}
		}
	}
	if strings.HasPrefix(sid, "S-1-5-80-") {
		return "NT SERVICE\\<service>", true
	}
	return "", false
}

// ParseSID decodes a binary SID and returns it with the number of bytes consumed.
func ParseSID(b []byte) (string, int, error) {
	if len(b) < 8 {
		return "", 0, fmt.Errorf("SID truncated: %d bytes", len(b))
	}
	rev, n := b[0], int(b[1])
	if rev != 1 {
		return "", 0, fmt.Errorf("SID revision %d", rev)
	}
	if n > 15 {
		return "", 0, fmt.Errorf("SID sub-authority count %d exceeds 15", n)
	}
	size := 8 + 4*n
	if len(b) < size {
		return "", 0, fmt.Errorf("SID truncated: need %d bytes, have %d", size, len(b))
	}
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-1-%d", auth)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return sb.String(), size, nil
}

// broadPrincipals are SIDs that cover most or all callers.
var broadPrincipals = map[string]bool{
	"S-1-1-0":      true, // Everyone
	"S-1-5-7":      true, // Anonymous Logon
	"S-1-5-11":     true, // Authenticated Users
	"S-1-5-32-545": true, // BUILTIN\Users
	"S-1-5-32-546": true, // BUILTIN\Guests
}

func IsBroadPrincipal(sid string) bool { return broadPrincipals[sid] }
