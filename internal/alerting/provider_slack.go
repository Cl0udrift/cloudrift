package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SlackProvider struct {
	client *http.Client
}

func NewSlackProvider(client *http.Client) *SlackProvider {
	if client == nil {
		client = newSafeWebhookClient(8 * time.Second)
	}
	return &SlackProvider{client: client}
}

func (s *SlackProvider) Name() string {
	return "slack"
}

func (s *SlackProvider) Send(payload AlertPayload, target Channel) DeliveryResult {
	now := time.Now().UTC()
	webhook := strings.TrimSpace(target.SlackWebhookURL)
	if webhook == "" {
		return DeliveryResult{
			Provider:  s.Name(),
			Channel:   string(target.Type),
			Attempted: true,
			Success:   false,
			Error:     "missing slack webhook URL",
			SentAt:    now,
		}
	}
	// SSRF guard: refuse to POST to non-https or internal/metadata targets (defense in depth;
	// rule/routing validation also rejects these at write time).
	if !allowedWebhookURL(webhook) {
		return DeliveryResult{
			Provider:  s.Name(),
			Channel:   string(target.Type),
			Attempted: false,
			Success:   false,
			Error:     "blocked webhook URL (must be https and not an internal/metadata host)",
			SentAt:    now,
		}
	}
	reqBody := map[string]any{
		"blocks": formatSlackBlocks(payload),
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return DeliveryResult{
			Provider:  s.Name(),
			Channel:   string(target.Type),
			Attempted: true,
			Success:   false,
			Error:     fmt.Sprintf("slack payload marshal failed: %v", err),
			SentAt:    now,
		}
	}

	resp, err := s.client.Post(webhook, "application/json", bytes.NewReader(raw))
	if err != nil {
		return DeliveryResult{
			Provider:  s.Name(),
			Channel:   string(target.Type),
			Attempted: true,
			Success:   false,
			Error:     fmt.Sprintf("slack delivery failed: %v", err),
			SentAt:    now,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return DeliveryResult{
			Provider:  s.Name(),
			Channel:   string(target.Type),
			Attempted: true,
			Success:   false,
			Error:     fmt.Sprintf("slack returned status %d", resp.StatusCode),
			SentAt:    now,
		}
	}

	return DeliveryResult{
		Provider:  s.Name(),
		Channel:   string(target.Type),
		Attempted: true,
		Success:   true,
		SentAt:    now,
	}
}

func formatSlackBlocks(payload AlertPayload) []map[string]any {
	sevEmoji := ":large_blue_circle:"
	switch payload.Severity {
	case SeverityWarning:
		sevEmoji = ":warning:"
	case SeverityCritical:
		sevEmoji = ":rotating_light:"
	}
	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type":  "plain_text",
				"text":  fmt.Sprintf("%s %s", sevEmoji, payload.Title),
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": payload.Summary,
			},
		},
	}
	if len(payload.Bullets) > 0 {
		parts := make([]string, 0, 3)
		for _, b := range payload.Bullets {
			if len(parts) >= 3 {
				break
			}
			parts = append(parts, "• "+slackEscape(b))
		}
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": strings.Join(parts, "\n"),
			},
		})
	}
	if len(payload.Items) > 0 {
		lines := make([]string, 0, len(payload.Items))
		for _, it := range payload.Items {
			line := "• " + slackEscape(it.Title)
			if it.URL != "" {
				line = "• <" + it.URL + "|" + slackEscape(it.Title) + ">"
			}
			if it.Detail != "" {
				line += "  _" + slackEscape(it.Detail) + "_"
			}
			lines = append(lines, line)
		}
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": strings.Join(lines, "\n")},
		})
	}
	if strings.TrimSpace(payload.ActionURL) != "" {
		label := strings.TrimSpace(payload.ActionLabel)
		if label == "" {
			label = "Open in Cloudrift"
		}
		blocks = append(blocks, map[string]any{
			"type": "actions",
			"elements": []map[string]any{
				{
					"type": "button",
					"text": map[string]any{
						"type": "plain_text",
						"text": label,
					},
					"url": payload.ActionURL,
				},
			},
		})
	}
	return blocks
}

// slackEscape stops text from finding names being read as Slack markup or links.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
