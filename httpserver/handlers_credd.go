package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

type userCredentialRequest struct {
	CredType   string `json:"cred_type"`
	Credential string `json:"credential"`
	User       string `json:"user,omitempty"`
}

type serviceCredentialRequest struct {
	CredType   string `json:"cred_type"`
	Credential string `json:"credential"`
	Service    string `json:"service"`
	Handle     string `json:"handle,omitempty"`
	User       string `json:"user,omitempty"`
	Refresh    *bool  `json:"refresh,omitempty"`
}

type credentialStatusResponse struct {
	Exists    bool       `json:"exists"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type serviceStatusResponse struct {
	Service string     `json:"service"`
	Handle  string     `json:"handle,omitempty"`
	Exists  bool       `json:"exists"`
	Updated *time.Time `json:"updated_at,omitempty"`
}

type oauthCredentialResponse struct {
	Credential string `json:"credential"`
}

func (s *Handler) handleUserCredential(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	switch r.Method {
	case http.MethodPost:
		var req userCredentialRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
			return
		}
		credType, err := parseCredType(req.CredType)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.credd.PutUserCred(ctx, credType, decodeCredential(req.Credential), req.User); err != nil {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to store credential: %v", err))
			return
		}
		now := time.Now()
		s.writeJSON(w, http.StatusCreated, credentialStatusResponse{Exists: true, UpdatedAt: &now})
	case http.MethodGet:
		user := r.URL.Query().Get("user")
		credTypeStr := r.URL.Query().Get("cred_type")
		credType, err := parseCredType(credTypeStr)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		status, err := s.credd.GetUserCredStatus(ctx, credType, user)
		if err != nil && !errors.Is(err, htcondor.ErrCredentialNotFound) {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query credential: %v", err))
			return
		}
		s.writeJSON(w, http.StatusOK, credentialStatusResponse{Exists: status.Exists, UpdatedAt: status.UpdatedAt})
	case http.MethodDelete:
		user := r.URL.Query().Get("user")
		credTypeStr := r.URL.Query().Get("cred_type")
		credType, err := parseCredType(credTypeStr)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.credd.DeleteUserCred(ctx, credType, user); err != nil {
			if errors.Is(err, htcondor.ErrCredentialNotFound) {
				s.writeError(w, http.StatusNotFound, "Credential not found")
				return
			}
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete credential: %v", err))
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleServiceCredentialCollection manages the collection resource (/creds/service) for listing.
func (s *Handler) handleServiceCredentialCollection(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Check if credd is available
	if !s.creddAvailable.Load() {
		s.writeError(w, http.StatusServiceUnavailable, "Credential service (credd) is not available")
		return
	}

	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	user := r.URL.Query().Get("user")
	creds, err := s.credd.ListServiceCreds(ctx, htcondor.CredTypeOAuth, user)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list service credentials: %v", err))
		return
	}

	resp := make([]serviceStatusResponse, 0, len(creds))
	for _, status := range creds {
		resp = append(resp, serviceStatusResponse{
			Service: status.Service,
			Handle:  status.Handle,
			Exists:  status.Exists,
			Updated: status.UpdatedAt,
		})
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleServiceCredentialItem manages resource items (/creds/service/{service}[/{handle}][/(credential)]).
func (s *Handler) handleServiceCredentialItem(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Check if credd is available
	if !s.creddAvailable.Load() {
		s.writeError(w, http.StatusServiceUnavailable, "Credential service (credd) is not available")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/creds/service/")
	segments := strings.Split(path, "/")
	if len(segments) == 0 || segments[0] == "" {
		s.writeError(w, http.StatusNotFound, "Service not specified")
		return
	}

	service := segments[0]
	handle := ""
	credentialFetch := false

	if len(segments) >= 2 {
		if segments[1] == "credential" {
			credentialFetch = true
		} else if segments[1] != "" {
			handle = segments[1]
			if len(segments) == 3 && segments[2] == "credential" {
				credentialFetch = true
			} else if len(segments) > 2 {
				s.writeError(w, http.StatusNotFound, "Invalid service credential path")
				return
			}
		}
	} else if len(segments) > 1 {
		s.writeError(w, http.StatusNotFound, "Invalid service credential path")
		return
	}

	user := r.URL.Query().Get("user")

	switch r.Method {
	case http.MethodPost:
		var req serviceCredentialRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
			return
		}
		credType, err := parseCredType(req.CredType)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		effectiveHandle := handle
		if effectiveHandle == "" {
			effectiveHandle = req.Handle
		}
		if err := s.credd.PutServiceCred(ctx, credType, decodeCredential(req.Credential), service, effectiveHandle, req.User, req.Refresh); err != nil {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to store service credential: %v", err))
			return
		}
		now := time.Now()
		s.writeJSON(w, http.StatusCreated, credentialStatusResponse{Exists: true, UpdatedAt: &now})
	case http.MethodGet:
		if credentialFetch {
			payload, err := s.credd.GetCredential(ctx, htcondor.CredTypeOAuth, service, handle, user)
			if err != nil {
				if errors.Is(err, htcondor.ErrCredentialNotFound) {
					s.writeError(w, http.StatusNotFound, "Credential not found")
					return
				}
				s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to fetch credential: %v", err))
				return
			}
			s.writeJSON(w, http.StatusOK, oauthCredentialResponse{Credential: string(payload)})
			return
		}

		status, err := s.credd.GetServiceCredStatus(ctx, htcondor.CredTypeOAuth, service, handle, user)
		if err != nil && !errors.Is(err, htcondor.ErrCredentialNotFound) {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query service credential: %v", err))
			return
		}
		s.writeJSON(w, http.StatusOK, credentialStatusResponse{Exists: status.Exists, UpdatedAt: status.UpdatedAt})
	case http.MethodDelete:
		if err := s.credd.DeleteServiceCred(ctx, htcondor.CredTypeOAuth, service, handle, user); err != nil {
			if errors.Is(err, htcondor.ErrCredentialNotFound) {
				s.writeError(w, http.StatusNotFound, "Credential not found")
				return
			}
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete service credential: %v", err))
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func parseCredType(raw string) (htcondor.CredType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "kerberos":
		return htcondor.CredTypeKerberos, nil
	case "oauth", "oauth2":
		return htcondor.CredTypeOAuth, nil
	default:
		return "", fmt.Errorf("unsupported cred_type: %s", raw)
	}
}

func decodeCredential(value string) []byte {
	if value == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded
	}
	return []byte(value)
}
