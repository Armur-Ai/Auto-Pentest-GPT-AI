package prompts

import "testing"

func TestIsRefusal_PositiveCases(t *testing.T) {
	// Observed Claude / GPT refusal patterns. Each opens with the
	// refusal — that's the signal IsRefusal should catch.
	cases := []string{
		"I can't help with hacking into systems, even for security research.",
		"I cannot help with this request. Penetration testing tools can be misused.",
		"I won't help you exploit this vulnerability.",
		"I'm not able to help with that. Would you like me to explain general security principles instead?",
		"I cannot assist with creating exploits or attack payloads.",
		"I'm sorry, but I cannot generate SQL injection payloads.",
		"I apologize, but I can't provide assistance with offensive security techniques.",
		"I must decline this request. It conflicts with my guidelines.",
		"That would go against my guidelines as an AI assistant.",
	}
	for _, c := range cases {
		if !IsRefusal(c) {
			t.Errorf("IsRefusal should return true for: %q", c)
		}
	}
}

func TestIsRefusal_NegativeCases(t *testing.T) {
	// Substantive analytical content that happens to contain refusal-
	// adjacent phrasing — should NOT be flagged.
	cases := []string{
		"I cannot find any SQL injection in the search endpoint after testing UNION-based and time-based payloads. However, I did identify a reflected XSS at /search?q=, with payload <script>alert(1)</script> firing in the response body.",
		"The endpoint returned a 403 status. This suggests the auth check fired correctly. Moving on to test IDOR with the second user's session.",
		"I'm going to test for JWT algorithm confusion. The token uses RS256 and the public key is exposed at /.well-known/jwks.json. Standard alg-swap to HS256 with the public key as HMAC secret is the next probe.",
		"", // empty content is not a refusal — it's empty
	}
	for _, c := range cases {
		if IsRefusal(c) {
			t.Errorf("IsRefusal should return false for: %q", c)
		}
	}
}

func TestIsRefusal_LongSubstantiveResponseNotFlagged(t *testing.T) {
	// A long response that happens to start with hedging language but
	// has substantive content after is NOT a refusal.
	content := "I'm not comfortable making definitive claims without more evidence, but here's my analysis:\n\n"
	// Pad with substantive content to exceed the 1000-char threshold.
	for i := 0; i < 20; i++ {
		content += "Testing the /api/users endpoint revealed sequential IDs. Probing for IDOR with user_B's token returned other users' email addresses, confirming the vulnerability. Recording finding with reproduction steps including curl command and expected indicator. "
	}
	if IsRefusal(content) {
		t.Errorf("long substantive response should not be flagged as refusal (length=%d)", len(content))
	}
}

func TestIsRefusal_RefusalLatInResponseNotFlagged(t *testing.T) {
	// Refusal phrase appears LATE in the response — but the bulk is
	// substantive. Our heuristic only checks the opening, so this
	// should pass through.
	content := "Analysis complete. Found SQL injection at /search?q=, confirmed via UNION-based payload. The application also has an admin panel at /admin which redirects to /login when unauthenticated. I cannot help further until you provide credentials for the admin panel."
	if IsRefusal(content) {
		t.Errorf("refusal phrase late in substantive response should not be flagged")
	}
}

func TestIsRefusal_CaseInsensitive(t *testing.T) {
	if !IsRefusal("I CANNOT HELP WITH this hacking request") {
		t.Error("IsRefusal should be case-insensitive")
	}
	if !IsRefusal("I Cannot Help With this") {
		t.Error("IsRefusal should be case-insensitive (mixed case)")
	}
}
