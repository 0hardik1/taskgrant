// Package config loads, interpolates, validates, and hashes the single
// taskgrant YAML configuration file (architecture section 10).
//
// Load order: env interpolation on the raw bytes, strict YAML decoding
// (unknown fields refuse to load), defaulting, then Validate. LoadFile
// and Load both return a fully validated *Config.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// Duration bounds per the architecture (sections 6 G7 and 10).
const (
	MinDurationSeconds = 900
	MaxDurationSeconds = 3600
	// LongSessionCeilingSeconds is the STS hard ceiling. Values above
	// MaxDurationSeconds require aws.allow_long_sessions and a broker
	// that does not run on session credentials.
	LongSessionCeilingSeconds = 43200
)

// Transport values for server.transport.
const (
	TransportStdio = "stdio"
	TransportHTTP  = "http"
)

// Anchor types for log.anchor.type.
const (
	AnchorS3ObjectLock   = "s3-object-lock"
	AnchorCloudWatchLogs = "cloudwatch-logs"
)

// Approval rule actions.
const (
	ActionRequireApproval = "require_approval"
	ActionAutoApprove     = "auto_approve"
)

// Config is the root of the YAML model. Field names mirror section 10.
type Config struct {
	Version    int                      `yaml:"version" json:"version"`
	Server     ServerConfig             `yaml:"server" json:"server"`
	AWS        AWSConfig                `yaml:"aws" json:"aws"`
	Agents     map[string]AgentConfig   `yaml:"agents" json:"agents"`
	Profiles   map[string]ProfileConfig `yaml:"profiles" json:"profiles"`
	Synth      SynthConfig              `yaml:"synth" json:"synth"`
	Guardrails GuardrailsConfig         `yaml:"guardrails" json:"guardrails"`
	Approvals  ApprovalsConfig          `yaml:"approvals" json:"approvals"`
	Revocation RevocationConfig         `yaml:"revocation" json:"revocation"`
	Log        LogConfig                `yaml:"log" json:"log"`
}

// ServerConfig is the server block.
type ServerConfig struct {
	Transport            string `yaml:"transport" json:"transport"`
	Listen               string `yaml:"listen" json:"listen"`
	AdminSocket          string `yaml:"admin_socket" json:"admin_socket"`
	MaxWaitSeconds       int    `yaml:"max_wait_seconds" json:"max_wait_seconds"`
	DefaultAgent         string `yaml:"default_agent" json:"default_agent"`
	CredentialRedelivery bool   `yaml:"credential_redelivery" json:"credential_redelivery"`
}

// AWSConfig is the aws block. EndpointURL is optional and points STS
// and IAM at a stand-in endpoint such as LocalStack.
type AWSConfig struct {
	STSRegion              string   `yaml:"sts_region" json:"sts_region"`
	DefaultDurationSeconds int      `yaml:"default_duration_seconds" json:"default_duration_seconds"`
	MaxDurationSeconds     int      `yaml:"max_duration_seconds" json:"max_duration_seconds"`
	AllowLongSessions      bool     `yaml:"allow_long_sessions" json:"allow_long_sessions"`
	Accounts               []string `yaml:"accounts" json:"accounts"`
	EndpointURL            string   `yaml:"endpoint_url" json:"endpoint_url"`
}

// AgentConfig is one entry of the agents block. TokenSHA256 stores only
// the SHA-256 hex of the bearer token, never the token itself. Token
// expiry is mandatory whenever a token is configured.
type AgentConfig struct {
	TokenSHA256    string    `yaml:"token_sha256" json:"token_sha256"`
	TokenExpires   time.Time `yaml:"token_expires" json:"token_expires"`
	Profiles       []string  `yaml:"profiles" json:"profiles"`
	DefaultProfile string    `yaml:"default_profile" json:"default_profile"`
}

// HasProfile reports whether the agent's allowlist contains name.
func (a AgentConfig) HasProfile(name string) bool {
	for _, p := range a.Profiles {
		if p == name {
			return true
		}
	}
	return false
}

// ProfileConfig is one entry of the profiles block.
type ProfileConfig struct {
	RoleARN            string   `yaml:"role_arn" json:"role_arn"`
	MaxDurationSeconds int      `yaml:"max_duration_seconds" json:"max_duration_seconds"`
	Region             string   `yaml:"region" json:"region"`
	ExternalID         string   `yaml:"external_id" json:"external_id"`
	PolicyARNs         []string `yaml:"policy_arns" json:"policy_arns"`
}

// SynthConfig is the synth block.
type SynthConfig struct {
	CatalogPath string     `yaml:"catalog_path" json:"catalog_path"`
	DatasetPath string     `yaml:"dataset_path" json:"dataset_path"`
	LLM         *LLMConfig `yaml:"llm" json:"llm,omitempty"`
}

// LLMConfig configures the optional classifier. Absent means the rules
// matcher runs alone.
type LLMConfig struct {
	Provider string `yaml:"provider" json:"provider"`
	Model    string `yaml:"model" json:"model"`
}

// GuardrailsConfig is the guardrails block. AccessLevels is an explicit
// set; Write must be listed to be grantable and Permissions management
// is never accepted (G2).
type GuardrailsConfig struct {
	AccessLevels      []string `yaml:"access_levels" json:"access_levels"`
	ExtraDenyServices []string `yaml:"extra_deny_services" json:"extra_deny_services"`
	FirstUseApproval  bool     `yaml:"first_use_approval" json:"first_use_approval"`
}

// ApprovalsConfig is the approvals block. Rules apply first match wins;
// no match means auto-approve.
type ApprovalsConfig struct {
	PendingTTLSeconds int            `yaml:"pending_ttl_seconds" json:"pending_ttl_seconds"`
	Rules             []ApprovalRule `yaml:"rules" json:"rules"`
}

// ApprovalRule is one approvals.rules entry.
type ApprovalRule struct {
	Match  ApprovalMatch `yaml:"match" json:"match"`
	Action string        `yaml:"action" json:"action"`
}

// ApprovalMatch selects grants for a rule. Empty fields match anything.
type ApprovalMatch struct {
	AccessLevel string `yaml:"access_level" json:"access_level"`
	Agent       string `yaml:"agent" json:"agent"`
	Profile     string `yaml:"profile" json:"profile"`
	Capability  string `yaml:"capability" json:"capability"`
}

// RevocationConfig is the revocation block.
type RevocationConfig struct {
	Enabled         bool `yaml:"enabled" json:"enabled"`
	RevokeOnRelease bool `yaml:"revoke_on_release" json:"revoke_on_release"`
}

// LogConfig is the log block.
type LogConfig struct {
	Path          string        `yaml:"path" json:"path"`
	Anchor        *AnchorConfig `yaml:"anchor" json:"anchor,omitempty"`
	MirrorJSONL   string        `yaml:"mirror_jsonl" json:"mirror_jsonl"`
	RetentionDays int           `yaml:"retention_days" json:"retention_days"`
}

// AnchorConfig configures the external tamper-evidence anchor (9.3).
type AnchorConfig struct {
	Type      string   `yaml:"type" json:"type"`
	Bucket    string   `yaml:"bucket" json:"bucket"`
	LogGroup  string   `yaml:"log_group" json:"log_group"`
	LogStream string   `yaml:"log_stream" json:"log_stream"`
	Interval  Duration `yaml:"interval" json:"interval"`
}

// Duration is a time.Duration that decodes from a YAML string such as
// "1h" or from a bare integer number of seconds.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("duration must be a string like \"1h\" or an integer of seconds: %w", err)
	}
	if secRE.MatchString(raw) {
		var sec int64
		if err := value.Decode(&sec); err != nil {
			return err
		}
		*d = Duration(time.Duration(sec) * time.Second)
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// MarshalJSON renders the duration in Go string form for the canonical
// serialization behind ConfigHash.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Std returns the plain time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

var (
	secRE         = regexp.MustCompile(`^[0-9]+$`)
	envRE         = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	hex64RE       = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	accountRE     = regexp.MustCompile(`^[0-9]{12}$`)
	profileNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	regionRE      = regexp.MustCompile(`^[a-z]{2}[a-z0-9-]{3,30}$`)
	roleARNRE     = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$`)
	policyARNRE   = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}|aws):policy/[A-Za-z0-9_+=,.@/-]+$`)
	serviceRE     = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
)

// allowedAccessLevels are the grantable dataset access levels. The
// Permissions management level is rejected unconditionally (G2).
var allowedAccessLevels = map[string]struct{}{
	"Read": {}, "List": {}, "Write": {}, "Tagging": {},
}

// LoadFile reads, interpolates, decodes, defaults, and validates the
// config file at path.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Load(data)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// Load parses config bytes. It applies env interpolation, decodes with
// unknown fields rejected, applies defaults, and validates. Secrets
// referenced as ${VAR} must be set in the environment; a missing
// variable is an error, never an empty substitution.
func Load(data []byte) (*Config, error) {
	interpolated, err := interpolateEnv(data)
	if err != nil {
		return nil, err
	}
	cfg := defaults()
	dec := yaml.NewDecoder(bytes.NewReader(interpolated))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDerivedDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaults returns a Config pre-filled with the documented defaults so
// absent YAML fields keep them.
func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			MaxWaitSeconds: 60,
		},
		AWS: AWSConfig{
			DefaultDurationSeconds: MinDurationSeconds,
			MaxDurationSeconds:     MaxDurationSeconds,
		},
		Guardrails: GuardrailsConfig{
			AccessLevels:     []string{"Read", "List"},
			FirstUseApproval: true,
		},
		Approvals: ApprovalsConfig{
			PendingTTLSeconds: 900,
		},
	}
}

// applyDerivedDefaults fills values that depend on other fields.
func (c *Config) applyDerivedDefaults() {
	for id, agent := range c.Agents {
		if agent.DefaultProfile == "" && len(agent.Profiles) == 1 {
			agent.DefaultProfile = agent.Profiles[0]
		}
		if agent.TokenSHA256 != "" {
			agent.TokenSHA256 = normalizeHex(agent.TokenSHA256)
		}
		c.Agents[id] = agent
	}
	if c.Log.Anchor != nil && c.Log.Anchor.Interval == 0 {
		c.Log.Anchor.Interval = Duration(time.Hour)
	}
}

func normalizeHex(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'F' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// interpolateEnv replaces every ${VAR} occurrence with the value of the
// environment variable VAR. Unset variables fail the load.
func interpolateEnv(data []byte) ([]byte, error) {
	var missing []string
	out := envRE.ReplaceAllFunc(data, func(m []byte) []byte {
		name := string(envRE.FindSubmatch(m)[1])
		val, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return m
		}
		return []byte(val)
	})
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("unset environment variables referenced in config: %v", missing)
	}
	return out, nil
}

// Validate checks every structural rule from the architecture. It
// collects all violations and returns them joined, so one run reports
// every problem.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if c.Version != 1 {
		fail("version must be 1, got %d", c.Version)
	}

	// Server block.
	switch c.Server.Transport {
	case TransportStdio:
		if c.Server.DefaultAgent == "" {
			fail("server.default_agent is required for the stdio transport")
		} else if _, ok := c.Agents[c.Server.DefaultAgent]; !ok {
			fail("server.default_agent %q is not a configured agent", c.Server.DefaultAgent)
		}
	case TransportHTTP:
		if c.Server.Listen == "" {
			fail("server.listen is required for the http transport")
		}
	case "":
		fail("server.transport is required (stdio or http)")
	default:
		fail("server.transport must be stdio or http, got %q", c.Server.Transport)
	}
	if c.Server.MaxWaitSeconds < 0 || c.Server.MaxWaitSeconds > 600 {
		fail("server.max_wait_seconds must be within 0..600, got %d", c.Server.MaxWaitSeconds)
	}

	// AWS block.
	if c.AWS.STSRegion == "" {
		fail("aws.sts_region is required")
	} else if !regionRE.MatchString(c.AWS.STSRegion) {
		fail("aws.sts_region %q is not a plausible region", c.AWS.STSRegion)
	}
	maxCeiling := MaxDurationSeconds
	if c.AWS.AllowLongSessions {
		maxCeiling = LongSessionCeilingSeconds
	}
	if c.AWS.MaxDurationSeconds < MinDurationSeconds || c.AWS.MaxDurationSeconds > maxCeiling {
		fail("aws.max_duration_seconds must be within %d..%d, got %d",
			MinDurationSeconds, maxCeiling, c.AWS.MaxDurationSeconds)
	}
	if c.AWS.DefaultDurationSeconds < MinDurationSeconds || c.AWS.DefaultDurationSeconds > c.AWS.MaxDurationSeconds {
		fail("aws.default_duration_seconds must be within %d..aws.max_duration_seconds (%d), got %d",
			MinDurationSeconds, c.AWS.MaxDurationSeconds, c.AWS.DefaultDurationSeconds)
	}
	for _, acct := range c.AWS.Accounts {
		if !accountRE.MatchString(acct) {
			fail("aws.accounts entry %q is not a 12-digit account id", acct)
		}
	}
	if c.AWS.EndpointURL != "" {
		u, err := url.Parse(c.AWS.EndpointURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			fail("aws.endpoint_url %q is not a valid http(s) URL", c.AWS.EndpointURL)
		}
	}

	// Profiles block.
	if len(c.Profiles) == 0 {
		fail("at least one profile is required")
	}
	for name, p := range c.Profiles {
		if !profileNameRE.MatchString(name) {
			fail("profile name %q must match %s", name, profileNameRE.String())
		}
		if p.RoleARN == "" {
			fail("profile %q: role_arn is required", name)
		} else if !roleARNRE.MatchString(p.RoleARN) {
			fail("profile %q: role_arn %q is not an IAM role ARN", name, p.RoleARN)
		}
		if p.MaxDurationSeconds != 0 &&
			(p.MaxDurationSeconds < MinDurationSeconds || p.MaxDurationSeconds > c.AWS.MaxDurationSeconds) {
			fail("profile %q: max_duration_seconds must be 0 (inherit) or within %d..%d, got %d",
				name, MinDurationSeconds, c.AWS.MaxDurationSeconds, p.MaxDurationSeconds)
		}
		if p.Region != "" && !regionRE.MatchString(p.Region) {
			fail("profile %q: region %q is not a plausible region", name, p.Region)
		}
		if len(p.PolicyARNs) > 10 {
			fail("profile %q: policy_arns holds %d entries, STS allows at most 10", name, len(p.PolicyARNs))
		}
		for _, arn := range p.PolicyARNs {
			if !policyARNRE.MatchString(arn) {
				fail("profile %q: policy_arns entry %q is not an IAM policy ARN", name, arn)
			}
		}
	}

	// Agents block.
	if len(c.Agents) == 0 {
		fail("at least one agent is required")
	}
	for id, a := range c.Agents {
		if err := domain.ValidateAgentID(id); err != nil {
			fail("agent %q: %v", id, err)
		}
		if c.Server.Transport == TransportHTTP && a.TokenSHA256 == "" {
			fail("agent %q: token_sha256 is required for the http transport", id)
		}
		if a.TokenSHA256 != "" {
			if !hex64RE.MatchString(a.TokenSHA256) {
				fail("agent %q: token_sha256 must be 64 hex characters", id)
			}
			if a.TokenExpires.IsZero() {
				fail("agent %q: token_expires is mandatory when token_sha256 is set", id)
			}
		}
		if len(a.Profiles) == 0 {
			fail("agent %q: at least one profile is required", id)
		}
		seen := map[string]bool{}
		for _, p := range a.Profiles {
			if seen[p] {
				fail("agent %q: duplicate profile %q", id, p)
			}
			seen[p] = true
			if _, ok := c.Profiles[p]; !ok {
				fail("agent %q: profile %q does not exist", id, p)
			}
		}
		if a.DefaultProfile != "" && !a.HasProfile(a.DefaultProfile) {
			fail("agent %q: default_profile %q is not in its profiles list", id, a.DefaultProfile)
		}
	}

	// Synth block.
	if c.Synth.CatalogPath == "" {
		fail("synth.catalog_path is required")
	}
	if c.Synth.DatasetPath == "" {
		fail("synth.dataset_path is required")
	}
	if c.Synth.LLM != nil {
		if c.Synth.LLM.Provider == "" || c.Synth.LLM.Model == "" {
			fail("synth.llm requires both provider and model")
		}
	}

	// Guardrails block.
	if len(c.Guardrails.AccessLevels) == 0 {
		fail("guardrails.access_levels must not be empty")
	}
	seenLevel := map[string]bool{}
	for _, lvl := range c.Guardrails.AccessLevels {
		if _, ok := allowedAccessLevels[lvl]; !ok {
			fail("guardrails.access_levels entry %q is not grantable (allowed: Read, List, Write, Tagging)", lvl)
		}
		if seenLevel[lvl] {
			fail("guardrails.access_levels lists %q twice", lvl)
		}
		seenLevel[lvl] = true
	}
	for _, svc := range c.Guardrails.ExtraDenyServices {
		if !serviceRE.MatchString(svc) {
			fail("guardrails.extra_deny_services entry %q is not a service prefix", svc)
		}
	}

	// Approvals block.
	if c.Approvals.PendingTTLSeconds < 60 || c.Approvals.PendingTTLSeconds > 86400 {
		fail("approvals.pending_ttl_seconds must be within 60..86400, got %d", c.Approvals.PendingTTLSeconds)
	}
	for i, rule := range c.Approvals.Rules {
		if rule.Action != ActionRequireApproval && rule.Action != ActionAutoApprove {
			fail("approvals.rules[%d]: action must be %s or %s, got %q",
				i, ActionRequireApproval, ActionAutoApprove, rule.Action)
		}
		if rule.Match.AccessLevel != "" {
			if _, ok := allowedAccessLevels[rule.Match.AccessLevel]; !ok {
				fail("approvals.rules[%d]: access_level %q is not one of Read, List, Write, Tagging", i, rule.Match.AccessLevel)
			}
		}
		if rule.Match.Agent != "" {
			if _, ok := c.Agents[rule.Match.Agent]; !ok {
				fail("approvals.rules[%d]: agent %q does not exist", i, rule.Match.Agent)
			}
		}
		if rule.Match.Profile != "" {
			if _, ok := c.Profiles[rule.Match.Profile]; !ok {
				fail("approvals.rules[%d]: profile %q does not exist", i, rule.Match.Profile)
			}
		}
	}

	// Log block.
	if c.Log.Path == "" {
		fail("log.path is required")
	}
	if c.Log.RetentionDays < 0 {
		fail("log.retention_days must not be negative, got %d", c.Log.RetentionDays)
	}
	if a := c.Log.Anchor; a != nil {
		switch a.Type {
		case AnchorS3ObjectLock:
			if a.Bucket == "" {
				fail("log.anchor: bucket is required for type %s", AnchorS3ObjectLock)
			}
		case AnchorCloudWatchLogs:
			if a.LogGroup == "" {
				fail("log.anchor: log_group is required for type %s", AnchorCloudWatchLogs)
			}
		default:
			fail("log.anchor.type must be %s or %s, got %q", AnchorS3ObjectLock, AnchorCloudWatchLogs, a.Type)
		}
		if a.Interval <= 0 {
			fail("log.anchor.interval must be positive")
		}
	}

	return errors.Join(errs...)
}

// ConfigHash returns the SHA-256 hex of the canonical serialized
// config. The canonical form is the JSON encoding of the parsed and
// defaulted Config: struct fields serialize in declaration order and
// map keys sort, so the hash is stable for equal configs (invariant
// I6 feeds this hash into every decision record).
func (c *Config) ConfigHash() string {
	data, err := json.Marshal(c)
	if err != nil {
		// The Config type contains only JSON-serializable fields.
		panic(fmt.Sprintf("config: canonical serialization failed: %v", err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// EffectiveMaxDurationSeconds returns the duration ceiling for a
// profile: the profile cap when set, otherwise the global cap.
func (c *Config) EffectiveMaxDurationSeconds(profile string) int {
	p, ok := c.Profiles[profile]
	if ok && p.MaxDurationSeconds != 0 && p.MaxDurationSeconds < c.AWS.MaxDurationSeconds {
		return p.MaxDurationSeconds
	}
	return c.AWS.MaxDurationSeconds
}

// ProfileRegion returns the profile's region, falling back to
// aws.sts_region when the profile does not set one.
func (c *Config) ProfileRegion(profile string) string {
	if p, ok := c.Profiles[profile]; ok && p.Region != "" {
		return p.Region
	}
	return c.AWS.STSRegion
}

// AgentIDs returns the configured agent ids, sorted.
func (c *Config) AgentIDs() []string {
	ids := make([]string, 0, len(c.Agents))
	for id := range c.Agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ProfileNames returns the configured profile names, sorted.
func (c *Config) ProfileNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
