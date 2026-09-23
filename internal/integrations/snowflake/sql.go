package snowflake

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Identifiers: Snowflake resolves unquoted identifiers to upper case and
// keeps quoted ones as written. hallpass stores every name in resolved
// form (the exact characters Snowflake compares) and renders it quoted, so
// that a name built from caller input can never change the shape of a
// statement.

var unquotedRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,254}$`)

// parseIdentifier parses one identifier part, quoted or not, into its
// resolved form.
func parseIdentifier(s string) (string, error) {
	if unquotedRe.MatchString(s) {
		return strings.ToUpper(s), nil
	}
	if len(s) >= 3 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := strings.ReplaceAll(s[1:len(s)-1], `""`, "\x00")
		if strings.Contains(inner, `"`) {
			return "", errors.New("a quoted identifier has an unescaped quote")
		}
		inner = strings.ReplaceAll(inner, "\x00", `"`)
		if inner == "" || len(inner) > 255 {
			return "", errors.New("a quoted identifier is empty or longer than 255 characters")
		}
		for _, r := range inner {
			if r < 0x20 || r == 0x7f {
				return "", errors.New("a quoted identifier carries a control character")
			}
		}
		return inner, nil
	}
	return "", fmt.Errorf("%q is not an identifier (letters, digits, _ and $, or double-quoted)", s)
}

// splitName splits a dotted name into its parts, honouring quotes.
func splitName(s string) ([]string, error) {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case c == '.' && !inQuote:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if inQuote {
		return nil, errors.New("unterminated quoted identifier")
	}
	parts = append(parts, cur.String())
	return parts, nil
}

// parseName parses a name of exactly n dotted parts into resolved parts.
func parseName(s string, n int) ([]string, error) {
	raw, err := splitName(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(raw) != n {
		return nil, fmt.Errorf("expected %d dotted part(s), found %d", n, len(raw))
	}
	out := make([]string, 0, n)
	for _, p := range raw {
		id, err := parseIdentifier(p)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// quote renders a resolved identifier for a statement.
func quote(id string) string {
	return `"` + strings.ReplaceAll(id, `"`, `""`) + `"`
}

// quoteName renders resolved parts as a dotted quoted name.
func quoteName(parts []string) string {
	q := make([]string, len(parts))
	for i, p := range parts {
		q[i] = quote(p)
	}
	return strings.Join(q, ".")
}

// sameName reports whether two resolved names are equal.
func sameName(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// stringLiteral renders s as a single-quoted SQL string literal.
func stringLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return "'" + s + "'"
}

// likeLiteral renders s for SHOW ... LIKE: the wildcards % and _ are
// escaped so the pattern is the literal name.
func likeLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return stringLiteral(s)
}
