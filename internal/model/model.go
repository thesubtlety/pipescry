// Package model defines the evidence document written by pipescry.
// Field names are part of the output contract; change SchemaVersion when they change.
package model

import "time"

const SchemaVersion = "1.0"

type Result string

const (
	ResultAllowed     Result = "allowed"
	ResultDenied      Result = "denied"
	ResultBusy        Result = "busy"
	ResultError       Result = "error"
	ResultUnsupported Result = "unsupported"
	ResultNotTested   Result = "not_tested"
)

var AllResults = []Result{ResultAllowed, ResultDenied, ResultBusy, ResultError, ResultUnsupported, ResultNotTested}

type Mode string

const (
	ModeRemote Mode = "remote"
	ModeLocal  Mode = "local"
)

type Report struct {
	SchemaVersion string      `json:"schema_version"`
	Tool          Tool        `json:"tool"`
	Mode          Mode        `json:"mode"`
	Target        string      `json:"target"`
	StartedAt     time.Time   `json:"started_at"`
	FinishedAt    time.Time   `json:"finished_at"`
	Identity      Identity    `json:"identity"`
	Transport     *Transport  `json:"transport"`
	Options       ScanOptions `json:"options"`
	Collection    Collection  `json:"collection"`
	Pipes         []Pipe      `json:"pipes"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Identity is the principal whose access the scan observed. It never carries secrets.
type Identity struct {
	Name       string `json:"name"`
	SID        string `json:"sid,omitempty"`
	AuthMethod string `json:"auth_method"`
	Anonymous  bool   `json:"anonymous"`
	Guest      bool   `json:"guest"`
	Elevated   *bool  `json:"elevated"`
}

type Transport struct {
	Protocol   string `json:"protocol"`
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	Dialect    string `json:"dialect,omitempty"`
	DialectRaw uint16 `json:"dialect_raw,omitempty"`
	// SigningRequired is the session's signing requirement, not proof each message was signed.
	SigningRequired *bool `json:"signing_required"`
	// CipherNegotiated is the NEGOTIATE result. Anonymous and guest sessions
	// have no session key, so a negotiated cipher does not mean encryption is in use.
	CipherNegotiated string `json:"cipher_negotiated,omitempty"`
	Share            string `json:"share,omitempty"`
}

type ScanOptions struct {
	Enumerate     bool     `json:"enumerate"`
	NamesSupplied int      `json:"names_supplied"`
	AccessTest    bool     `json:"access_test"`
	AccessTests   []string `json:"access_tests"`
	TimeoutMS     int64    `json:"timeout_ms"`
	Concurrency   int      `json:"concurrency"`
}

type EnumerationStatus string

const (
	EnumComplete    EnumerationStatus = "complete"
	EnumPartial     EnumerationStatus = "partial"
	EnumFailed      EnumerationStatus = "failed"
	EnumUnsupported EnumerationStatus = "unsupported"
	EnumSkipped     EnumerationStatus = "skipped"
)

type Collection struct {
	Enumeration        EnumerationStatus `json:"enumeration"`
	EnumerationError   *OpError          `json:"enumeration_error"`
	PipesEnumerated    int               `json:"pipes_enumerated"`
	PipesSupplied      int               `json:"pipes_supplied"`
	PipesTotal         int               `json:"pipes_total"`
	DescriptorsByState map[string]int    `json:"descriptors_by_state"`
	TestsByResult      map[string]int    `json:"tests_by_result"`
	Errors             []OpError         `json:"errors"`
	Warnings           []string          `json:"warnings"`
}

// Status is a raw platform status code. Kind is "ntstatus" or "win32".
type Status struct {
	Kind string `json:"kind"`
	Code uint32 `json:"code"`
	Hex  string `json:"hex"`
	Name string `json:"name,omitempty"`
}

type OpError struct {
	Op      string  `json:"op"`
	Target  string  `json:"target"`
	Message string  `json:"message"`
	Status  *Status `json:"status"`
	// NTStatus is set locally when a Win32 failure also left an NTSTATUS in the TEB.
	NTStatus *Status `json:"ntstatus,omitempty"`
}

type Pipe struct {
	Name             string           `json:"name"`
	Sources          []string         `json:"sources"`
	ObservedAt       time.Time        `json:"observed_at"`
	CurrentInstances *uint64          `json:"current_instances"`
	MaxInstances     *int64           `json:"max_instances"`
	Security         SecurityEvidence `json:"security"`
	AccessTests      []AccessTest     `json:"access_tests"`
	Indicators       []Indicator      `json:"indicators"`
}

type DescriptorState string

const (
	SDCollected DescriptorState = "collected"
	SDFailed    DescriptorState = "failed"
	// SDUnavailable: the server or filesystem does not support the query.
	SDUnavailable DescriptorState = "unavailable"
	SDUnparsed    DescriptorState = "unparsed"
)

type SecurityEvidence struct {
	State           DescriptorState `json:"state"`
	RequestedAccess uint32          `json:"requested_access"`
	RequestedHex    string          `json:"requested_access_hex"`
	RawHex          string          `json:"raw_hex,omitempty"`
	HandleClosed    *bool           `json:"handle_closed"`
	CloseError      string          `json:"close_error,omitempty"`
	Descriptor      *Descriptor     `json:"descriptor"`
	Error           *OpError        `json:"error"`
}

type DACLState string

const (
	// DACLPresent: SE_DACL_PRESENT set and an ACL with at least one ACE.
	DACLPresent DACLState = "present"
	// DACLEmpty: an ACL with zero ACEs. Grants nothing to anyone except owner implicit rights.
	DACLEmpty DACLState = "empty"
	// DACLNull: SE_DACL_PRESENT set with no ACL. Grants all access to everyone.
	DACLNull DACLState = "null"
	// DACLNotPresent: SE_DACL_PRESENT clear. Access checks treat this like a NULL DACL.
	DACLNotPresent DACLState = "not_present"
)

type Descriptor struct {
	Revision     uint8    `json:"revision"`
	Control      uint16   `json:"control"`
	ControlHex   string   `json:"control_hex"`
	ControlFlags []string `json:"control_flags"`
	Owner        *SID     `json:"owner"`
	Group        *SID     `json:"group"`
	DACL         ACL      `json:"dacl"`
}

type ACL struct {
	State    DACLState `json:"state"`
	Revision uint8     `json:"revision,omitempty"`
	ACEs     []ACE     `json:"aces"`
}

type SID struct {
	Value      string `json:"sid"`
	Name       string `json:"name,omitempty"`
	NameSource string `json:"name_source,omitempty"`
}

type ACE struct {
	Index       int      `json:"index"`
	Type        uint8    `json:"type"`
	TypeName    string   `json:"type_name"`
	Flags       uint8    `json:"flags"`
	FlagNames   []string `json:"flag_names"`
	InheritOnly bool     `json:"inherit_only"`
	Mask        uint32   `json:"mask"`
	MaskHex     string   `json:"mask_hex"`
	Rights      []string `json:"rights"`
	// MappedMask is Mask after applying the file-object generic mapping.
	MappedMask   uint32   `json:"mapped_mask"`
	MappedHex    string   `json:"mapped_mask_hex"`
	MappedRights []string `json:"mapped_rights"`
	Trustee      *SID     `json:"trustee"`
	RawHex       string   `json:"raw_hex,omitempty"`
}

type AccessTest struct {
	Name            string    `json:"name"`
	RequestedAccess uint32    `json:"requested_access"`
	RequestedHex    string    `json:"requested_access_hex"`
	Identity        string    `json:"identity"`
	IdentitySID     string    `json:"identity_sid,omitempty"`
	Result          Result    `json:"result"`
	Status          *Status   `json:"status"`
	NTStatus        *Status   `json:"ntstatus,omitempty"`
	Error           string    `json:"error,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	DurationMS      int64     `json:"duration_ms"`
	Closed          *bool     `json:"handle_closed"`
	CloseError      string    `json:"close_error,omitempty"`
}

// Indicator records a factual property of the DACL. It is not an assessment.
type Indicator struct {
	Kind     string   `json:"kind"`
	ACEIndex *int     `json:"ace_index"`
	Trustee  *SID     `json:"trustee"`
	Mask     uint32   `json:"mask"`
	MaskHex  string   `json:"mask_hex"`
	Rights   []string `json:"rights"`
	Evidence string   `json:"evidence"`
}
