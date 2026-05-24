package llm

import (
	"context"
	"fmt"
)

// BudgetManager tracks token usage and manages context window limits.
type BudgetManager struct {
	contextWindow    int
	warningThreshold float64 // percentage of context window to warn at (0.8 = 80%)
	summarizeAt      float64 // percentage to trigger summarization (0.7 = 70%)
}

// NewBudgetManager creates a new token budget manager.
func NewBudgetManager(contextWindow int) *BudgetManager {
	return &BudgetManager{
		contextWindow:    contextWindow,
		warningThreshold: 0.80,
		summarizeAt:      0.70,
	}
}

// EstimateTokens gives a rough estimate of tokens in a message list.
// Uses ~4 chars per token as a rough heuristic for English text.
func EstimateTokens(messages []Message) int {
	total := 0
	for _, m := range messages {
		total += len(m.Content) / 4
		total += 4 // overhead per message (role tokens, formatting)
	}
	return total
}

// NeedsSummarization returns true if the messages are approaching the context limit.
func (b *BudgetManager) NeedsSummarization(messages []Message) bool {
	estimated := EstimateTokens(messages)
	threshold := int(float64(b.contextWindow) * b.summarizeAt)
	return estimated >= threshold
}

// IsNearLimit returns true if messages are at the warning threshold.
func (b *BudgetManager) IsNearLimit(messages []Message) bool {
	estimated := EstimateTokens(messages)
	threshold := int(float64(b.contextWindow) * b.warningThreshold)
	return estimated >= threshold
}

// Summarize compresses the oldest messages by asking the LLM to summarize them.
// Keeps the most recent messages intact for context continuity.
func (b *BudgetManager) Summarize(ctx context.Context, messages []Message, provider Provider) ([]Message, error) {
	if len(messages) < 4 {
		return messages, nil // nothing to summarize
	}

	// Split: summarize oldest 50%, keep newest 50%
	splitPoint := len(messages) / 2
	toSummarize := messages[:splitPoint]
	toKeep := messages[splitPoint:]

	// Build the content to summarize
	var summaryInput string
	for _, m := range toSummarize {
		summaryInput += fmt.Sprintf("[%s]: %s\n\n", m.Role, m.Content)
	}

	summaryReq := CompletionRequest{
		SystemPrompt: "You are a summarization assistant. Summarize the following conversation concisely, preserving all key facts, decisions, findings, and action items. Do not lose any technical details about targets, vulnerabilities, or commands.",
		Messages: []Message{
			{Role: "user", Content: fmt.Sprintf("Summarize this conversation:\n\n%s", summaryInput)},
		},
		MaxTokens:   2048,
		Temperature: 0,
	}

	resp, err := provider.Complete(ctx, summaryReq)
	if err != nil {
		// If summarization fails, just return original messages
		return messages, nil
	}

	// Replace old messages with summary + kept messages
	summarized := []Message{
		{Role: "user", Content: "[Previous conversation summary]: " + resp.Content},
	}
	summarized = append(summarized, toKeep...)

	return summarized, nil
}

// RemainingTokens returns the estimated remaining tokens in the budget.
func (b *BudgetManager) RemainingTokens(messages []Message) int {
	used := EstimateTokens(messages)
	remaining := b.contextWindow - used
	if remaining < 0 {
		return 0
	}
	return remaining
}
