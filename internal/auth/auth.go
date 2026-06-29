// Package auth handles the web UI and SMTP authentication
package auth

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/tg123/go-htpasswd"
)

// contextKey is a private type for context keys defined in this package.
type contextKey int

const (
	// AuthUsernameKey is the context key used to store the authenticated HTTP username.
	AuthUsernameKey contextKey = iota
)

// GetRequestUsername returns the authenticated HTTP username stored in the request context.
// Returns an empty string when no user is authenticated or when the user is an admin.
func GetRequestUsername(r *http.Request) string {
	username, _ := r.Context().Value(AuthUsernameKey).(string)
	return username
}

// IsUIAdminUser reports whether the given username is exempt from tag-based filtering.
func IsUIAdminUser(username string) bool {
	_, ok := UIAdminUsers[strings.ToLower(username)]
	return ok
}

var (
	// UICredentials passwords
	UICredentials *htpasswd.File
	// SendAPICredentials passwords
	SendAPICredentials *htpasswd.File
	// SMTPCredentials passwords
	SMTPCredentials *htpasswd.File
	// POP3Credentials passwords
	POP3Credentials *htpasswd.File
	// UIAdminUsers is the set of usernames exempt from tag-based filtering
	UIAdminUsers = map[string]struct{}{}
)

// SetUIAuth will set Basic Auth credentials required for the UI & API
func SetUIAuth(s string) error {
	var err error

	credentials := credentialsFromString(s)
	if len(credentials) == 0 {
		return nil
	}

	r := strings.NewReader(strings.Join(credentials, "\n"))

	UICredentials, err = htpasswd.NewFromReader(r, htpasswd.DefaultSystems, nil)
	if err != nil {
		return err
	}

	return nil
}

// SetSendAPIAuth will set Send API credentials
func SetSendAPIAuth(s string) error {
	var err error

	credentials := credentialsFromString(s)
	if len(credentials) == 0 {
		return nil
	}

	r := strings.NewReader(strings.Join(credentials, "\n"))

	SendAPICredentials, err = htpasswd.NewFromReader(r, htpasswd.DefaultSystems, nil)
	if err != nil {
		return err
	}

	return nil
}

// SetSMTPAuth will set SMTP credentials
func SetSMTPAuth(s string) error {
	var err error

	credentials := credentialsFromString(s)
	if len(credentials) == 0 {
		return nil
	}

	r := strings.NewReader(strings.Join(credentials, "\n"))

	SMTPCredentials, err = htpasswd.NewFromReader(r, htpasswd.DefaultSystems, nil)
	if err != nil {
		return err
	}

	return nil
}

// SetPOP3Auth will set POP3 server credentials
func SetPOP3Auth(s string) error {
	var err error

	credentials := credentialsFromString(s)
	if len(credentials) == 0 {
		return nil
	}

	r := strings.NewReader(strings.Join(credentials, "\n"))

	POP3Credentials, err = htpasswd.NewFromReader(r, htpasswd.DefaultSystems, nil)
	if err != nil {
		return err
	}

	return nil
}

func credentialsFromString(s string) []string {
	// split string by any whitespace character
	re := regexp.MustCompile(`\s+`)

	words := re.Split(s, -1)
	credentials := []string{}
	for _, w := range words {
		if w != "" {
			credentials = append(credentials, w)
		}
	}

	return credentials
}
