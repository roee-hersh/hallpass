package integration

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Template renders a per-user name (a Kubernetes username, a GitLab
// username, a GitHub login) from the caller's email. The placeholders are
// {email} (the whole address), {local} (the part before @) and {domain}
// (the part after @). Integrations declare the config key with
// ValidateTemplate and keep the parsed Template on the connection.
type Template string

// ParseTemplate validates a template: every "{...}" must name one of the
// three placeholders, braces must be balanced, and {email} or {local} must
// occur, otherwise every user would render to the same name.
func ParseTemplate(s string) (Template, error) {
	if err := ValidateTemplate(s); err != nil {
		return "", err
	}
	return Template(s), nil
}

// ValidateTemplate is ParseTemplate as a Field.Validate.
func ValidateTemplate(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("must not be empty")
	}
	rest := s
	for {
		i := strings.IndexAny(rest, "{}")
		if i < 0 {
			break
		}
		if rest[i] == '}' {
			return errors.New("unbalanced '}': placeholders are {email}, {local} and {domain}")
		}
		j := strings.IndexAny(rest[i+1:], "{}")
		if j < 0 || rest[i+1+j] != '}' {
			return errors.New("unclosed '{': placeholders are {email}, {local} and {domain}")
		}
		switch ph := rest[i+1 : i+1+j]; ph {
		case "email", "local", "domain":
		default:
			return fmt.Errorf("unknown placeholder {%s}; use {email}, {local} or {domain}", ph)
		}
		rest = rest[i+1+j+1:]
	}
	if !strings.Contains(s, "{email}") && !strings.Contains(s, "{local}") {
		return errors.New("must contain {email} or {local}, otherwise every user gets the same name")
	}
	return nil
}

// Render substitutes the placeholders for the email. An address without @
// is all local part and has an empty domain.
func (t Template) Render(email string) string {
	local, domain, _ := strings.Cut(email, "@")
	return strings.NewReplacer("{email}", email, "{local}", local, "{domain}", domain).Replace(string(t))
}

// emailRe is the shape of an address hallpass accepts as a user: a local
// part of the RFC 5322 atom characters and a domain of letters, digits,
// dots and hyphens. It admits no quote, backslash, space or control
// character, so a validated address is safe inside a query filter.
var emailRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}$`)

// IsEmail reports whether s has the shape of an email address.
func IsEmail(s string) bool { return emailRe.MatchString(s) }

// EmailDomain returns the lowercased domain of an address, or "" when the
// address has no domain.
func EmailDomain(email string) string {
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return ""
	}
	return strings.ToLower(domain)
}

// ParseEmailDomains parses a comma-separated email_domains value. Every
// entry is trimmed and lowercased and must be a DNS-style name (labels of
// letters, digits and hyphens joined by dots); an empty entry, an empty
// list or a malformed name is an error, and a repeated domain is kept once.
// Matching an address against the result is by whole domain, so a listed
// acme.com does not admit sub.acme.com.
func ParseEmailDomains(v string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(v, ",") {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" {
			return nil, errors.New("must be a comma-separated list of domains with no empty entries (acme.com,acme.io)")
		}
		if err := checkDomain(d); err != nil {
			return nil, fmt.Errorf("%q %v", strings.TrimSpace(raw), err)
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, errors.New("must list at least one domain")
	}
	return out, nil
}

// ValidateEmailDomains is ParseEmailDomains as a Field.Validate.
func ValidateEmailDomains(v string) error {
	_, err := ParseEmailDomains(v)
	return err
}

// checkDomain accepts one lowercased DNS name: labels of [a-z0-9-] that do
// not start or end with a hyphen, at most 63 bytes each, joined by single
// dots, at most 253 bytes in all.
func checkDomain(d string) error {
	if len(d) > 253 {
		return errors.New("is longer than 253 characters")
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return errors.New("is not a domain name (empty label)")
		}
		if len(label) > 63 {
			return errors.New("is not a domain name (label longer than 63 characters)")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("is not a domain name (label starts or ends with a hyphen)")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return errors.New("is not a domain name (letters, digits, hyphens and dots only)")
			}
		}
	}
	return nil
}
