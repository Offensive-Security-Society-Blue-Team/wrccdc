//go:build windows

package common

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strings"
)

// hardenFilePerms strips inheritance and grants only Administrators and SYSTEM
// full control on the credential file. Best-effort.
func hardenFilePerms(path string) {
	Run("icacls", path, "/inheritance:r",
		"/grant:r", "*S-1-5-32-544:F", // BUILTIN\Administrators
		"/grant:r", "*S-1-5-18:F") // NT AUTHORITY\SYSTEM
}

type winUser struct {
	Name    string `json:"Name"`
	Enabled bool   `json:"Enabled"`
	SID     string `json:"SID"`
}

// parseWinUsers tolerates both the single-object and array JSON shapes that
// ConvertTo-Json emits.
func parseWinUsers(s string) []winUser {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var arr []winUser
	if err := json.Unmarshal([]byte(s), &arr); err == nil {
		return arr
	}
	var one winUser
	if err := json.Unmarshal([]byte(s), &one); err == nil {
		return []winUser{one}
	}
	return nil
}

// ridFromSID returns the trailing relative identifier of a SID string.
func ridFromSID(sid string) string {
	i := strings.LastIndexByte(sid, '-')
	if i < 0 {
		return ""
	}
	return sid[i+1:]
}

func currentSam() string {
	if u, err := user.Current(); err == nil {
		name := u.Username
		if i := strings.LastIndexByte(name, '\\'); i >= 0 {
			name = name[i+1:]
		}
		return strings.ToLower(name)
	}
	return ""
}

func rotateImpl(cfg RotateConfig) *RotateReport {
	rep := &RotateReport{OS: "windows"}

	if !IsPrivileged() && !cfg.DryRun {
		rep.Creds = append(rep.Creds, Credential{Scope: "local", User: "-",
			Status: "error: must run elevated (Administrator) to change passwords"})
		return rep
	}

	self := currentSam()
	rotateLocalWindows(cfg, self, rep)

	if cfg.IncludeDomain && isDomainController() && adAvailable() {
		rotateDomainWindows(cfg, self, rep)
	} else if cfg.IncludeDomain {
		rep.Skipped = append(rep.Skipped, "domain rotation (not a DC or ActiveDirectory module unavailable)")
	}
	return rep
}

func rotateLocalWindows(cfg RotateConfig, self string, rep *RotateReport) {
	res := Powershell(`@(Get-LocalUser | Select-Object Name,Enabled,@{n='SID';e={$_.SID.Value}}) | ConvertTo-Json -Compress`)
	if !res.OK() {
		rep.Creds = append(rep.Creds, Credential{Scope: "local", User: "-",
			Status: "error: Get-LocalUser: " + firstLine(res.Stderr)})
		return
	}
	for _, u := range parseWinUsers(res.Stdout) {
		if reason := skipReasonWinLocal(u, cfg, self); reason != "" {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s (%s)", u.Name, reason))
			continue
		}
		pw := Generate(GenOptions{Length: cfg.Length, Symbols: cfg.Symbols})
		cred := Credential{Scope: "local", User: u.Name, Password: pw}
		if cfg.DryRun {
			cred.Status = "dry-run"
			rep.Creds = append(rep.Creds, cred)
			continue
		}
		script := fmt.Sprintf(
			`Set-LocalUser -Name %s -Password (ConvertTo-SecureString %s -AsPlainText -Force)`,
			PSQuote(u.Name), PSQuote(pw))
		r := Powershell(script)
		if r.OK() {
			cred.Status = "changed"
		} else {
			cred.Password = ""
			cred.Status = "error: " + firstLine(r.Stderr)
		}
		rep.Creds = append(rep.Creds, cred)
	}
}

func skipReasonWinLocal(u winUser, cfg RotateConfig, self string) string {
	rid := ridFromSID(u.SID)
	switch rid {
	case "501", "503", "504": // Guest, DefaultAccount, WDAGUtilityAccount
		return "built-in system account"
	case "500": // Administrator
		if !cfg.IncludeRoot {
			return "built-in Administrator (use --include-root to rotate)"
		}
	}
	if !u.Enabled {
		return "disabled account"
	}
	if strings.ToLower(u.Name) == self && !cfg.IncludeSelf {
		return "current user (use --include-self to override)"
	}
	if IsServiceAccount(u.Name, cfg.Deny) {
		return "service/system account"
	}
	return ""
}

func isDomainController() bool {
	res := Powershell(`(Get-CimInstance Win32_ComputerSystem).DomainRole`)
	role := strings.TrimSpace(res.Stdout)
	return role == "4" || role == "5"
}

func adAvailable() bool {
	res := Powershell(`if (Get-Module -ListAvailable -Name ActiveDirectory) { 'yes' } else { 'no' }`)
	return strings.Contains(res.Stdout, "yes")
}

type adUser struct {
	Sam     string `json:"Sam"`
	Enabled bool   `json:"Enabled"`
	HasSPN  bool   `json:"HasSPN"`
}

func rotateDomainWindows(cfg RotateConfig, self string, rep *RotateReport) {
	// Pull candidate accounts. We flag accounts that carry a servicePrincipalName
	// (classic service accounts) so they are skipped — rotating them breaks the
	// service, which is exactly what we must avoid.
	ps := `Import-Module ActiveDirectory -ErrorAction Stop
$u = Get-ADUser -Filter * -Properties servicePrincipalName,Enabled |
  Select-Object @{n='Sam';e={$_.SamAccountName}},
                @{n='Enabled';e={[bool]$_.Enabled}},
                @{n='HasSPN';e={[bool]$_.servicePrincipalName}}
@($u) | ConvertTo-Json -Compress`
	res := Powershell(ps)
	if !res.OK() {
		rep.Creds = append(rep.Creds, Credential{Scope: "domain", User: "-",
			Status: "error: Get-ADUser: " + firstLine(res.Stderr)})
		return
	}
	var users []adUser
	s := strings.TrimSpace(res.Stdout)
	if err := json.Unmarshal([]byte(s), &users); err != nil {
		var one adUser
		if json.Unmarshal([]byte(s), &one) == nil {
			users = []adUser{one}
		}
	}

	for _, u := range users {
		if reason := skipReasonDomain(u, cfg, self); reason != "" {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s (domain: %s)", u.Sam, reason))
			continue
		}
		pw := Generate(GenOptions{Length: cfg.Length, Symbols: cfg.Symbols})
		cred := Credential{Scope: "domain", User: u.Sam, Password: pw}
		if cfg.DryRun {
			cred.Status = "dry-run"
			rep.Creds = append(rep.Creds, cred)
			continue
		}
		script := fmt.Sprintf(
			`Import-Module ActiveDirectory; Set-ADAccountPassword -Identity %s -Reset -NewPassword (ConvertTo-SecureString %s -AsPlainText -Force)`,
			PSQuote(u.Sam), PSQuote(pw))
		r := Powershell(script)
		if r.OK() {
			cred.Status = "changed"
		} else {
			cred.Password = ""
			cred.Status = "error: " + firstLine(r.Stderr)
		}
		rep.Creds = append(rep.Creds, cred)
	}
}

func skipReasonDomain(u adUser, cfg RotateConfig, self string) string {
	low := strings.ToLower(u.Sam)
	if low == "krbtgt" {
		return "krbtgt service account"
	}
	if u.HasSPN {
		return "has servicePrincipalName (service account)"
	}
	if !u.Enabled {
		return "disabled account"
	}
	if low == "administrator" && !cfg.IncludeRoot {
		return "domain Administrator (use --include-root to rotate)"
	}
	if low == self && !cfg.IncludeSelf {
		return "current user (use --include-self to override)"
	}
	if IsServiceAccount(u.Sam, cfg.Deny) {
		return "service/system account"
	}
	return ""
}

// firstLine is defined in rotate_unix.go for !windows; redeclare here for the
// windows build.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "unknown error"
	}
	return s
}

var _ = os.Getpid
