package synthesizer

import (
	"testing"
	"time"

	"github.com/0hardik1/taskgrant/internal/synth"
)

func cacheKey(n string) CacheKey {
	return CacheKey{
		AgentID:        "agent",
		Profile:        "profile",
		IntentHash:     n,
		CatalogHash:    "cat",
		DatasetHash:    "ds",
		ConfigHash:     "cfg",
		MaxPolicyChars: 1748,
	}
}

func TestMemoryCachePutGet(t *testing.T) {
	c := NewMemoryCache(4)
	d := CachedDecision{
		PolicyJSON:        []byte(`{"Version":"2012-10-17"}`),
		PolicyArns:        []string{"arn:aws:iam::1:policy/x"},
		EffectiveDuration: 900 * time.Second,
		Capabilities:      []synth.CapabilityRef{{ID: "a", Version: 1}},
		ExpandedActions:   []string{"s3:GetObject"},
		Explanation: synth.Explanation{Statements: []synth.StatementExplanation{
			{CapabilityID: "a", CapabilityVersion: 1, Params: map[string]string{"k": "v"}, Reason: "r"},
		}},
	}
	c.Put(cacheKey("h1"), d)

	got, ok := c.Get(cacheKey("h1"))
	if !ok {
		t.Fatal("expected a hit")
	}
	if string(got.PolicyJSON) != string(d.PolicyJSON) {
		t.Fatal("policy bytes differ")
	}
	if _, ok := c.Get(cacheKey("h2")); ok {
		t.Fatal("unexpected hit for a different key")
	}

	// Mutating the returned copy must not corrupt the cache.
	got.PolicyJSON[0] = 'X'
	got.Explanation.Statements[0].Params["k"] = "mutated"
	again, _ := c.Get(cacheKey("h1"))
	if again.PolicyJSON[0] == 'X' || again.Explanation.Statements[0].Params["k"] != "v" {
		t.Fatal("cache entries must be isolated from caller mutation")
	}
}

func TestMemoryCacheEviction(t *testing.T) {
	c := NewMemoryCache(2)
	c.Put(cacheKey("h1"), CachedDecision{PolicyJSON: []byte("1")})
	c.Put(cacheKey("h2"), CachedDecision{PolicyJSON: []byte("2")})
	c.Put(cacheKey("h3"), CachedDecision{PolicyJSON: []byte("3")})
	if _, ok := c.Get(cacheKey("h1")); ok {
		t.Fatal("oldest entry must be evicted")
	}
	if _, ok := c.Get(cacheKey("h2")); !ok {
		t.Fatal("h2 must survive")
	}
	if _, ok := c.Get(cacheKey("h3")); !ok {
		t.Fatal("h3 must survive")
	}
}

func TestMemoryCacheOverwriteKeepsSingleSlot(t *testing.T) {
	c := NewMemoryCache(2)
	c.Put(cacheKey("h1"), CachedDecision{PolicyJSON: []byte("1")})
	c.Put(cacheKey("h1"), CachedDecision{PolicyJSON: []byte("1b")})
	c.Put(cacheKey("h2"), CachedDecision{PolicyJSON: []byte("2")})
	got, ok := c.Get(cacheKey("h1"))
	if !ok || string(got.PolicyJSON) != "1b" {
		t.Fatalf("overwrite lost: %v %q", ok, got.PolicyJSON)
	}
	if _, ok := c.Get(cacheKey("h2")); !ok {
		t.Fatal("h2 must fit; overwrites must not consume extra slots")
	}
}
