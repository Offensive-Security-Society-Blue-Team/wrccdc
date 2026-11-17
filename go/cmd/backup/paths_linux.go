//go:build linux

package main

import "wrccdc/internal/common"

// defaultPaths returns the folders most worth protecting on a Linux server:
// system config, DNS, and web content — the things red teams wipe or deface.
// Only paths that actually exist are archived.
func defaultPaths(info common.OSInfo) []string {
	return []string{
		"/etc",                  // system + service configuration
		"/etc/bind",             // BIND / DNS zones (Debian)
		"/var/named",            // BIND zones (RHEL)
		"/var/lib/bind",         // dynamic zones
		"/etc/nginx",            // nginx config
		"/etc/apache2",          // apache config (Debian)
		"/etc/httpd",            // apache config (RHEL)
		"/var/www",              // web roots
		"/usr/share/nginx/html", // default nginx site
		"/srv",                  // service data / sites
		"/etc/ssh",              // sshd config + host keys
		"/etc/pki",              // TLS material (RHEL)
		"/etc/ssl",              // TLS material (Debian)
		"/opt",                  // app installs
		"/root",                 // root's files (keys, notes)
	}
}
