package mgmt

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

func (s *Server) handleListCerts(c echo.Context) error {
	list, err := s.store.ListCertificates(c.Request().Context())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"certificates": list})
}

func (s *Server) handleGetCertMeta(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	// Public metadata only — never private key.
	_, meta, err := s.store.GetCertificatePublicPEM(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "certificate not found")
		}
		return err
	}
	return c.JSON(http.StatusOK, meta)
}

type generateCARequest struct {
	Name string `json:"name"`
}

func (s *Server) handleGenerateCA(c echo.Context) error {
	if s.certs == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "certificate provider unavailable (WSP_DATA_KEY?)")
	}
	var req generateCARequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "WSP Root CA"
	}
	meta, err := s.certs.GenerateSelfSignedCA(c.Request().Context(), name)
	if err != nil {
		return err
	}
	s.writeAudit(c, "certificate.generate", "certificate", meta.ID.String(), "Generated self-signed CA", map[string]string{
		"name":        meta.Name,
		"fingerprint": meta.FingerprintSHA256,
	})
	return c.JSON(http.StatusCreated, meta)
}

// handleDownloadCertPEM returns only the public certificate PEM.
// NEVER returns private key material.
func (s *Server) handleDownloadCertPEM(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	pem, meta, err := s.store.GetCertificatePublicPEM(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "certificate not found")
		}
		return err
	}
	// Defense in depth: refuse if body looks like a private key.
	if strings.Contains(pem, "PRIVATE KEY") {
		return echo.NewHTTPError(http.StatusInternalServerError, "refusing to serve private key material")
	}
	s.writeAudit(c, "certificate.download_pem", "certificate", meta.ID.String(), "Downloaded CA public PEM", nil)
	c.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="wsp-ca.pem"`)
	return c.Blob(http.StatusOK, "application/x-pem-file", []byte(pem))
}
