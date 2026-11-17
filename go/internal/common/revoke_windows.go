//go:build windows

package common

import (
	"strconv"
	"strings"
)

var sessionStates = map[string]bool{
	"Active": true, "Disc": true, "Listen": true, "Conn": true,
	"ConnQ": true, "Shadow": true, "Down": true, "Idle": true,
}

func revokeImpl(cfg RevokeConfig) *RevokeReport {
	rep := &RevokeReport{OS: "windows"}
	if !IsPrivileged() {
		rep.fail("must run elevated (Administrator) to revoke sessions")
		return rep
	}

	myID := currentWinSession()

	// 1) Log off interactive / RDP sessions.
	res := Run("query", "session")
	if !res.OK() {
		// qwinsta is the same tool under a different name on some builds.
		res = Run("qwinsta")
	}
	if res.Stdout == "" {
		rep.fail("could not enumerate sessions (query session)")
	} else {
		for _, line := range strings.Split(res.Stdout, "\n") {
			id, userName, state, isCurrent, ok := parseSessionLine(line)
			if !ok {
				continue
			}
			if state == "Listen" || id == 0 || id == 65536 {
				continue // services / listener, not a user session
			}
			if isCurrent || id == myID {
				rep.act("kept own session id=%d (%s)", id, userName)
				continue
			}
			if !cfg.IncludeSelf && myID < 0 && userName != "" && strings.EqualFold(userName, currentSam()) {
				rep.act("kept session id=%d for current user (own id unknown)", id)
				continue
			}
			r := Run("logoff", strconv.Itoa(id))
			if r.OK() {
				rep.act("logged off session id=%d (%s)", id, userName)
			} else {
				rep.fail("logoff %d: %s", id, firstLine(r.Stderr))
			}
		}
	}

	// 2) Drop inbound SMB sessions (file-share footholds).
	smb := Powershell(`try { Close-SmbSession -Force -ErrorAction Stop; 'ok' } catch { $_.Exception.Message }`)
	if strings.Contains(smb.Stdout, "ok") || smb.OK() {
		rep.act("closed inbound SMB sessions")
	} else {
		// Fallback to the legacy net command.
		if Run("net", "session", "/delete", "/y").OK() {
			rep.act("closed inbound SMB sessions (net session)")
		}
	}

	return rep
}

// currentWinSession returns the session id of this process, or -1 if unknown.
func currentWinSession() int {
	res := Powershell(`(Get-Process -Id $PID).SessionId`)
	if n, err := strconv.Atoi(strings.TrimSpace(res.Stdout)); err == nil {
		return n
	}
	return -1
}

// parseSessionLine extracts (id, username, state, isCurrent) from a
// `query session` row. It is resilient to the variable-width USERNAME column
// (which is blank for disconnected sessions).
func parseSessionLine(raw string) (id int, user, state string, isCurrent, ok bool) {
	trimmed := strings.TrimLeft(raw, " \t")
	isCurrent = strings.HasPrefix(trimmed, ">")
	trimmed = strings.TrimPrefix(trimmed, ">")
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return 0, "", "", false, false
	}
	// Locate the STATE token.
	stateIdx := -1
	for i, f := range fields {
		if sessionStates[f] {
			stateIdx = i
			break
		}
	}
	if stateIdx < 1 {
		return 0, "", "", false, false
	}
	// The ID is the integer field immediately before STATE.
	idField := fields[stateIdx-1]
	n, err := strconv.Atoi(idField)
	if err != nil {
		return 0, "", "", false, false
	}
	state = fields[stateIdx]
	// Username: if there are three or more fields before STATE we have
	// SESSIONNAME USERNAME ID; with two it is SESSIONNAME ID (no user).
	if stateIdx-1 >= 2 {
		user = fields[stateIdx-2]
	}
	return n, user, state, isCurrent, true
}
