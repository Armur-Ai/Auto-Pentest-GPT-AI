package prompts

import "strings"

// IsRefusal returns true if the LLM response content looks like a
// safety-filter refusal rather than a substantive answer.
//
// The heuristic is conservative: refusal phrases must appear near the
// START of the response (first 150 chars). Refusals consistently lead
// with the refusal sentence; substantive responses that mention
// "I cannot help" later (e.g. "Analysis complete. … I cannot help
// further without admin creds.") should NOT be flagged. Long
// responses are also presumed substantive — they have actual content
// even when they open with hedging language.
//
// Patterns are bare prefixes ("i can't help" not "i can't help with")
// so we catch variants like "I can't help you", "I can't help.",
// "I can't help with X" with a single entry. The head-window check
// prevents false positives on substantive responses that happen to
// include "i cannot help" mid-text.
//
// When unsure, lean toward false negative — a missed refusal flows
// through unhandled; a false positive wastes a retry round-trip.
func IsRefusal(content string) bool {
	if content == "" {
		return false
	}

	// Substantive responses are usually >1000 chars. Refusals are short.
	if len(content) > 1000 {
		return false
	}

	lower := strings.ToLower(content)

	// Only check the opening — refusals lead with the refusal.
	const headWindow = 150
	if len(lower) > headWindow {
		lower = lower[:headWindow]
	}

	for _, phrase := range refusalPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// refusalPhrases are lowercase substrings that, when found in the
// opening 150 chars of an LLM response, strongly indicate a
// safety-filter refusal. Curated from observed Claude / GPT refusal
// templates. Bare prefixes deliberately catch variants — adding
// trailing words ("with", "you") narrows too much.
var refusalPhrases = []string{
	"i can't help",
	"i cannot help",
	"i won't help",
	"i'm not able to help",
	"i am not able to help",
	"i cannot assist",
	"i can't assist",
	"i won't assist",
	"i don't feel comfortable",
	"i'm not comfortable",
	"i cannot provide assistance",
	"i can't provide assistance",
	"i must decline",
	"i'm sorry, but i can",
	"i'm sorry, but i cannot",
	"i'm sorry, but i won't",
	"i apologize, but i can",
	"i apologize, but i cannot",
	"against my guidelines",
	"against my programming",
	"violates my guidelines",
	"goes against my",
	"i'm not going to help",
	"i am not going to help",
	"i'm not willing to",
}
