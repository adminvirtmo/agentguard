package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/adminvirtmo/agentguard/internal/config"
	"github.com/adminvirtmo/agentguard/internal/policy"
)

type ToolCall struct {
	Method string          `json:"method,omitempty"`
	Name   string          `json:"name,omitempty"`
	Tool   string          `json:"tool,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
}

type Decision struct {
	Status         string   `json:"status"`
	Reason         string   `json:"reason"`
	Tool           string   `json:"tool,omitempty"`
	SensitiveFiles []string `json:"sensitive_files,omitempty"`
	MatchedRule    string   `json:"matched_rule,omitempty"`
}

func Inspect(cfg config.Config, payload []byte) (Decision, error) {
	var call ToolCall
	if err := json.Unmarshal(payload, &call); err != nil {
		return Decision{}, err
	}
	text := toolText(call)
	if strings.TrimSpace(text) == "" {
		return Decision{Status: string(policy.StatusAllowed), Reason: "no inspectable command or path arguments", Tool: toolName(call)}, nil
	}
	decision := policy.Evaluate(cfg, []string{text})
	return Decision{
		Status:         string(decision.Status),
		Reason:         decision.Reason,
		Tool:           toolName(call),
		SensitiveFiles: decision.SensitiveFiles,
		MatchedRule:    decision.MatchedRule,
	}, nil
}

func toolName(call ToolCall) string {
	switch {
	case call.Name != "":
		return call.Name
	case call.Tool != "":
		return call.Tool
	case call.Method != "":
		return call.Method
	default:
		return "unknown"
	}
}

func toolText(call ToolCall) string {
	var parts []string
	parts = append(parts, call.Name, call.Tool, call.Method)
	for _, raw := range []json.RawMessage{call.Params, call.Args} {
		if len(raw) == 0 {
			continue
		}
		parts = append(parts, flattenJSON(raw)...)
	}
	return strings.Join(parts, " ")
}

func flattenJSON(raw json.RawMessage) []string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []string{string(raw)}
	}
	var out []string
	walk(v, &out)
	return out
}

func walk(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case float64, bool, nil:
		*out = append(*out, fmt.Sprint(x))
	case []any:
		for _, item := range x {
			walk(item, out)
		}
	case map[string]any:
		for k, value := range x {
			*out = append(*out, k)
			walk(value, out)
		}
	}
}
