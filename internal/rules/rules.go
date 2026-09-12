package rules

import (
	"fmt"
	"os"
	"regexp"

	// Ensure this matches the module path in your go.mod
	"github.com/turbok12/AgentGaurd/internal/firewall"
	"gopkg.in/yaml.v3"
)

type RuleType string

const (
	TypeRegex        RuleType = "regex"
	TypeMaxThreshold RuleType = "max_threshold"
)

type Rule struct {
	ID        string   `yaml:"id"`
	Tool      string   `yaml:"tool"`
	Field     string   `yaml:"field"`
	Type      RuleType `yaml:"type"`
	Pattern   string   `yaml:"pattern,omitempty"`
	Threshold float64  `yaml:"threshold,omitempty"`
	Action    string   `yaml:"action"` // "allow" | "deny"
	Reason    string   `yaml:"reason"`

	compiledRegex *regexp.Regexp
}

type Config struct {
	Rules []Rule `yaml:"rules"`
}

type Engine struct {
	rules []Rule
}

// LoadFromFile reads and compiles a rules.yaml file.
func LoadFromFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml: %w", err)
	}

	for i := range cfg.Rules {
		if cfg.Rules[i].Type == TypeRegex {
			compiled, err := regexp.Compile(cfg.Rules[i].Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex for rule %s: %w", cfg.Rules[i].ID, err)
			}
			cfg.Rules[i].compiledRegex = compiled
		}
	}

	return &Engine{rules: cfg.Rules}, nil
}

// Evaluate checks an action against all loaded rules.
// Returns a Decision if a rule matches, or nil if no rule applies.
func (e *Engine) Evaluate(act firewall.Action) (*firewall.Decision, error) {
	for _, rule := range e.rules {
		if rule.Tool != act.Tool {
			continue
		}

		rawVal, ok := act.Args[rule.Field]
		if !ok {
			continue
		}

		switch rule.Type {
		case TypeRegex:
			strVal, ok := rawVal.(string)
			if !ok {
				continue
			}
			if rule.compiledRegex.MatchString(strVal) {
				return &firewall.Decision{
					Allow:  rule.Action == "allow",
					Reason: rule.Reason,
					Source: "rule",
					RuleID: rule.ID,
				}, nil
			}

		case TypeMaxThreshold:
			numVal, ok := toFloat64(rawVal)
			if !ok {
				continue
			}
			if numVal > rule.Threshold {
				return &firewall.Decision{
					Allow:  rule.Action == "allow",
					Reason: rule.Reason,
					Source: "rule",
					RuleID: rule.ID,
				}, nil
			}
		}
	}

	// No rule matched; delegate to next pipeline step
	return nil, nil
}

func toFloat64(val any) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	default:
		return 0, false
	}
}
