package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

type passwordRequest struct {
	Password string `json:"password"`
	User     string `json:"user,omitempty"`
}

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

type serviceCheckRequest struct {
	CredType string          `json:"cred_type"`
	Services []serviceTarget `json:"services"`
	User     string          `json:"user,omitempty"`
}

type serviceTarget struct {
	Service string `json:"service"`
	Handle  string `json:"handle,omitempty"`
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

func (s *Server) handlePasswordCredential(w http.ResponseWriter, r *http.Request) {
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
		var req passwordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
			return
		}
		if req.Password == "" {
			s.writeError(w, http.StatusBadRequest, "password is required")
			return
		}
		if err := s.credd.AddPassword(ctx, req.Password, req.User); err != nil {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to store password: %v", err))
			return
		}
		now := time.Now()
		s.writeJSON(w, http.StatusCreated, credentialStatusResponse{Exists: true, UpdatedAt: &now})
	case http.MethodGet:
		user := r.URL.Query().Get("user")
		status, err := s.credd.QueryPassword(ctx, user)
		if err != nil && !errors.Is(err, htcondor.ErrCredentialNotFound) {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query password: %v", err))
			return
		}
		s.writeJSON(w, http.StatusOK, credentialStatusResponse{Exists: status.Exists, UpdatedAt: status.UpdatedAt})
	case http.MethodDelete:
		user := r.URL.Query().Get("user")
		deleted, err := s.credd.DeletePassword(ctx, user)
		if err != nil && !errors.Is(err, htcondor.ErrCredentialNotFound) {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete password: %v", err))
			return
		}
		if !deleted {
			s.writeError(w, http.StatusNotFound, "Password not found")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleUserCredential(w http.ResponseWriter, r *http.Request) {
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
		if err := s.credd.AddUserCred(ctx, credType, decodeCredential(req.Credential), req.User); err != nil {
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
		status, err := s.credd.QueryUserCred(ctx, credType, user)
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

func (s *Server) handleServiceCredential(w http.ResponseWriter, r *http.Request) {
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
		if req.Service == "" {
			s.writeError(w, http.StatusBadRequest, "service is required")
			return
		}
		if err := s.credd.AddUserServiceCred(ctx, credType, decodeCredential(req.Credential), req.Service, req.Handle, req.User, req.Refresh); err != nil {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to store service credential: %v", err))
			return
		}
		now := time.Now()
		s.writeJSON(w, http.StatusCreated, credentialStatusResponse{Exists: true, UpdatedAt: &now})
	case http.MethodGet:
		user := r.URL.Query().Get("user")
		credTypeStr := r.URL.Query().Get("cred_type")
		service := r.URL.Query().Get("service")
		handle := r.URL.Query().Get("handle")
		credType, err := parseCredType(credTypeStr)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		status, err := s.credd.QueryUserServiceCred(ctx, credType, service, handle, user)
		if err != nil && !errors.Is(err, htcondor.ErrCredentialNotFound) {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query service credential: %v", err))
			return
		}
		s.writeJSON(w, http.StatusOK, credentialStatusResponse{Exists: status.Exists, UpdatedAt: status.UpdatedAt})
	case http.MethodDelete:
		user := r.URL.Query().Get("user")
		credTypeStr := r.URL.Query().Get("cred_type")
		service := r.URL.Query().Get("service")
		handle := r.URL.Query().Get("handle")
		credType, err := parseCredType(credTypeStr)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.credd.DeleteUserServiceCred(ctx, credType, service, handle, user); err != nil {
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

func (s *Server) handleServiceCredentialCheck(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req serviceCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	credType, err := parseCredType(req.CredType)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	serviceAds := make([]*classad.ClassAd, 0, len(req.Services))
	for _, target := range req.Services {
		ad := classad.New()
		_ = ad.Set("Service", target.Service)
		if target.Handle != "" {
			_ = ad.Set("Handle", target.Handle)
		}
		serviceAds = append(serviceAds, ad)
	}

	statuses, err := s.credd.CheckUserServiceCreds(ctx, credType, serviceAds, req.User)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to check service credentials: %v", err))
		return
	}

	resp := make([]serviceStatusResponse, 0, len(statuses))
	for _, status := range statuses {
		resp = append(resp, serviceStatusResponse{
			Service: status.Service,
			Handle:  status.Handle,
			Exists:  status.Exists,
			Updated: status.UpdatedAt,
		})
	}

	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleServiceCredentialToken(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	service := r.URL.Query().Get("service")
	handle := r.URL.Query().Get("handle")
	user := r.URL.Query().Get("user")

	credential, err := s.credd.GetOAuth2Credential(ctx, service, handle, user)
	if err != nil {
		if errors.Is(err, htcondor.ErrCredentialNotFound) {
			s.writeError(w, http.StatusNotFound, "Credential not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to fetch credential: %v", err))
		return
	}

	s.writeJSON(w, http.StatusOK, oauthCredentialResponse{Credential: credential})
}

func parseCredType(raw string) (htcondor.CredType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "password":
		return htcondor.CredTypePassword, nil
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
