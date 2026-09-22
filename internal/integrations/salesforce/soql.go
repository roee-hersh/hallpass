package salesforce

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

// Everything that ends up inside a SOQL statement passes through one of the
// validators in this file first. Identifiers (record ids, API names,
// permission names) are matched against strict regexes that leave no room
// for quotes, whitespace or operators; free text (an email) is validated and
// then escaped with soqlString. Nothing else is ever interpolated.

var (
	// idRe is a Salesforce record Id: 15 case-sensitive characters, or the
	// 18-character case-insensitive form the API returns.
	idRe = regexp.MustCompile(`^[a-zA-Z0-9]{15}([a-zA-Z0-9]{3})?$`)
	// apiNameRe is an sObject or field API name (Account, Invoice__c,
	// Parent.Name is not one: relationship paths are built by hallpass).
	apiNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,79}$`)
	// permNameRe is the shape of a PermissionSet permission field
	// (PermissionsApiEnabled). The describe check narrows it to fields that
	// exist.
	permNameRe = regexp.MustCompile(`^Permissions[A-Za-z0-9]+$`)
)

// validateID checks a Salesforce record Id.
func validateID(s string) error {
	if !idRe.MatchString(s) {
		return fmt.Errorf("%q is not a Salesforce Id (15 or 18 alphanumeric characters)", s)
	}
	return nil
}

// validateAPIName checks an sObject or field API name.
func validateAPIName(s string) error {
	if !apiNameRe.MatchString(s) {
		return fmt.Errorf("%q is not an API name (letters, digits and underscores, starting with a letter, at most 80 characters)", s)
	}
	return nil
}

// validatePermissionName checks the shape of a PermissionsXxx field name.
// Whether the field exists is checked against the PermissionSet describe.
func validatePermissionName(s string) error {
	if !permNameRe.MatchString(s) {
		return fmt.Errorf("%q is not a permission field name (PermissionsXxx)", s)
	}
	return nil
}

// validateEmail parses s as a bare address: it must round-trip through
// net/mail unchanged, so display names, comments and angle brackets are
// rejected, and it must carry no control characters.
func validateEmail(s string) error {
	if s == "" {
		return errors.New("email is empty")
	}
	if err := validateText(s); err != nil {
		return err
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return fmt.Errorf("%q is not an email address", s)
	}
	if a.Address != s || a.Name != "" {
		return fmt.Errorf("%q is not a bare email address", s)
	}
	return nil
}

// validateText rejects control characters and over-long values in free text
// that will be escaped into a string literal.
func validateText(s string) error {
	if len(s) > 255 {
		return errors.New("value is longer than 255 bytes")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return errors.New("value contains a control character")
		}
	}
	return nil
}

// soqlString escapes s for use inside a single-quoted SOQL string literal.
// Backslashes are doubled first, then single quotes are escaped, so an input
// of \' becomes \\\' and cannot terminate the literal. Newlines, carriage
// returns and tabs become their SOQL escape sequences. The caller still
// validates the value: this function only makes it inert.
func soqlString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// soqlIDList renders validated ids as a SOQL IN list: 'a','b'. It panics on
// an id that does not match idRe, because callers validate first and an
// unvalidated id here would be a programming error, not a runtime condition.
func soqlIDList(ids []string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if !idRe.MatchString(id) {
			panic("salesforce: unvalidated id in soqlIDList")
		}
		parts = append(parts, "'"+id+"'")
	}
	return strings.Join(parts, ",")
}
