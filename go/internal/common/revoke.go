package common

// RevokeConfig controls session revocation.
type RevokeConfig struct {
	// IncludeSelf also terminates sessions owned by the account running the
	// tool. Off by default so the operator does not kill their own shell.
	IncludeSelf bool
	Deny        []string
}

// RevokeReport records what revocation did.
type RevokeReport struct {
	OS      string
	Actions []string
	Errors  []string
}

func (r *RevokeReport) act(format string, a ...any) {
	r.Actions = append(r.Actions, sprintf(format, a...))
}
func (r *RevokeReport) fail(format string, a ...any) {
	r.Errors = append(r.Errors, sprintf(format, a...))
}

// RevokeSessions terminates interactive and remote sessions for all non-system
// users (plus network/SMB sessions where applicable), dispatching to the
// platform implementation. It deliberately preserves the operator's own
// session unless IncludeSelf is set.
func RevokeSessions(cfg RevokeConfig) *RevokeReport {
	return revokeImpl(cfg)
}
