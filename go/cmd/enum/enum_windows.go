//go:build windows

package main

import "wrccdc/internal/common"

func enumerate(info common.OSInfo) []section {
	specs := []cmdSpec{
		{"OS version", "cmd", []string{"/c", "ver"}},
		{"System info", "systeminfo", nil},
		{"IP configuration", "ipconfig", []string{"/all"}},
		{"Listening ports & owning PIDs", "netstat", []string{"-ano"}},
		{"Routing table", "route", []string{"print"}},
		{"ARP cache", "arp", []string{"-a"}},
		{"Running processes", "tasklist", []string{"/v"}},
		{"Local users", "net", []string{"user"}},
		{"Administrators group", "net", []string{"localgroup", "administrators"}},
		{"Active sessions", "query", []string{"session"}},
		{"Scheduled tasks", "schtasks", []string{"/query", "/fo", "LIST", "/v"}},
		{"Shares", "net", []string{"share"}},
	}

	var out []section
	for _, s := range specs {
		out = append(out, s.run())
	}

	// Richer sections via PowerShell.
	out = append(out,
		psSection("Running services",
			`Get-Service | Where-Object {$_.Status -eq 'Running'} | Sort-Object Name | Format-Table -AutoSize Name,DisplayName | Out-String -Width 4096`),
		psSection("Installed applications",
			`$p=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*');`+
				`Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | `+
				`Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 4096`),
		psSection("Firewall profiles",
			`Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Out-String -Width 4096`),
		psSection("Listening TCP (owning process)",
			`Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | `+
				`Select-Object LocalAddress,LocalPort,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | `+
				`Sort-Object LocalPort | Format-Table -AutoSize | Out-String -Width 4096`),
		psSection("Local administrators (detailed)",
			`try { Get-LocalGroupMember -Group 'Administrators' | Format-Table Name,ObjectClass,PrincipalSource | Out-String -Width 4096 } catch { $_.Exception.Message }`),
	)
	return out
}

func psSection(title, script string) section {
	res := common.Powershell(script)
	body := res.Stdout
	if body == "" {
		body = res.Stderr
	}
	if body == "" {
		body = "(no output)"
	}
	return section{title, body}
}
