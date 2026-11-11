package model

import "testing"

func TestClassify(t *testing.T) {
	nt := map[uint32]Result{
		0: ResultAllowed, 0xC0000022: ResultDenied, 0xC00000AE: ResultBusy, 0xC00000AC: ResultBusy,
		0xC00000AB: ResultBusy, 0xC00000BB: ResultUnsupported, 0xC0000034: ResultError,
		0xC0000043: ResultError, 0xC00000B5: ResultError, 0xC000006D: ResultError,
	}
	for code, want := range nt {
		if got := ClassifyNTStatus(code); got != want {
			t.Errorf("ClassifyNTStatus(%#x) = %s, want %s", code, got, want)
		}
	}
	w32 := []struct {
		code uint32
		nt   *Status
		want Result
	}{
		{0, nil, ResultAllowed},
		{5, nil, ResultDenied},
		{5, NTStatus(0xC0000022), ResultDenied},
		{5, NTStatus(0xC0000056), ResultError}, // STATUS_DELETE_PENDING
		{5, NTStatus(0xC00000BA), ResultError}, // STATUS_FILE_IS_A_DIRECTORY
		{231, nil, ResultBusy},
		{2, nil, ResultError},
		{50, nil, ResultUnsupported},
	}
	for _, c := range w32 {
		if got := ClassifyWin32(c.code, c.nt); got != c.want {
			t.Errorf("ClassifyWin32(%d, %v) = %s, want %s", c.code, c.nt, got, c.want)
		}
	}
}
