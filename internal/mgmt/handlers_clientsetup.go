package mgmt

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/store"
)

func (s *Server) handleClientSetup(c echo.Context) error {
	ctx := c.Request().Context()

	var activeCA *store.CertificateMeta
	if s.store != nil {
		list, err := s.store.ListCertificates(ctx)
		if err == nil {
			for i := range list {
				if list[i].IsActive {
					c := list[i]
					activeCA = &c
					break
				}
			}
		}
	}

	proxyHost := hostFromAddr(s.proxyAddr, "PROXY_HOST")
	proxyPort := portFromAddr(s.proxyAddr, "8080")
	adminBase := strings.TrimRight(c.Scheme()+"://"+c.Request().Host, "/")

	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
  // WSP explicit proxy PAC (lab example)
  if (isPlainHostName(host) ||
      shExpMatch(host, "localhost") ||
      shExpMatch(host, "127.*") ||
      shExpMatch(host, "10.*") ||
      shExpMatch(host, "192.168.*")) {
    return "DIRECT";
  }
  return "PROXY %s:%s";
}
`, proxyHost, proxyPort)

	caDownload := ""
	if activeCA != nil {
		caDownload = adminBase + "/api/v1/certificates/" + activeCA.ID.String() + "/pem"
	}

	return c.JSON(http.StatusOK, map[string]any{
		"proxy": map[string]any{
			"listen": s.proxyAddr,
			"host":   proxyHost,
			"port":   proxyPort,
			"type":   "explicit",
		},
		"ca": map[string]any{
			"active":             activeCA != nil,
			"certificate":        activeCA,
			"download_url":       caDownload,
			"download_note":      "Downloads public CA PEM only — private key is never exported",
			"trust_instructions": trustInstructions(),
		},
		"pac": map[string]any{
			"snippet": pac,
			"note":    "Serve this PAC from an internal HTTP endpoint or GPO, then point browsers at it.",
		},
		"mdm_gpo_notes": []string{
			"Deploy the CA into the Trusted Root Certification Authorities store (Computer Configuration).",
			"Configure user/computer proxy via PAC URL or static PROXY host:port.",
			"For Chromium, ensure the enterprise policy CertificateTransparencyEnforcementDisabledForCas is not needed for private CAs in most lab setups.",
			"Firefox uses its own cert store — import the CA into Firefox or enable enterprise roots on Windows.",
		},
		"troubleshooting": []string{
			"NET::ERR_CERT_AUTHORITY_INVALID — client does not trust the WSP CA; re-import public PEM.",
			"Proxy connection failed — verify client can reach proxy listen address and no local firewall blocks it.",
			"HTTPS sites work without inspection — policy may have tls_intercept=false for that destination.",
			"Intermittent TLS errors after CA rotation — regenerate/redistribute CA and clear browser TLS state.",
		},
	})
}

func hostFromAddr(addr, fallback string) string {
	if addr == "" {
		return fallback
	}
	// ":8080" or "0.0.0.0:8080"
	if strings.HasPrefix(addr, ":") {
		return "PROXY_HOST"
	}
	host, _, ok := strings.Cut(addr, ":")
	if !ok || host == "" || host == "0.0.0.0" || host == "::" {
		return "PROXY_HOST"
	}
	return host
}

func portFromAddr(addr, fallback string) string {
	if addr == "" {
		return fallback
	}
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":")
	}
	_, port, ok := strings.Cut(addr, ":")
	if !ok || port == "" {
		return fallback
	}
	// strip IPv6 brackets edge cases lightly
	return port
}

func trustInstructions() map[string]string {
	return map[string]string{
		"chrome_edge_windows": "Settings → Privacy and security → Security → Manage certificates → Trusted Root Certification Authorities → Import the CA PEM.",
		"chrome_edge_macos":   "Open Keychain Access → System → Certificates → File → Import Items → set trust to Always Trust for SSL.",
		"firefox":             "Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import → trust for websites.",
		"linux":               "Copy PEM to /usr/local/share/ca-certificates/wsp-ca.crt and run update-ca-certificates (distro-specific).",
	}
}
