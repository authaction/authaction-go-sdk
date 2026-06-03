package authaction

// TokenPayload holds the verified claims from an AuthAction JWT access token.
type TokenPayload struct {
	// Sub is the subject — the user or M2M client identifier.
	Sub string
	// Iss is the token issuer.
	Iss string
	// Aud contains the audience values (may be one or many).
	Aud []string
	// Exp is the expiry time (Unix seconds).
	Exp int64
	// Iat is the issued-at time (Unix seconds).
	Iat int64
	// Scope is the space-separated list of granted OAuth2 scopes.
	Scope string
	// Extra holds any additional claims not covered by the standard fields above.
	Extra map[string]interface{}
}

// HasScope reports whether the token payload includes the given scope.
func (p *TokenPayload) HasScope(scope string) bool {
	if p == nil {
		return false
	}
	s := p.Scope
	for len(s) > 0 {
		var tok string
		if i := indexByte(s, ' '); i >= 0 {
			tok, s = s[:i], s[i+1:]
		} else {
			tok, s = s, ""
		}
		if tok == scope {
			return true
		}
	}
	return false
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
