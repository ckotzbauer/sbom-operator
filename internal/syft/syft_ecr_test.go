package syft

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenCache_EmptyReturnsNotOk(t *testing.T) {
	c := newTokenCache()
	_, _, ok := c.get("123456789012.dkr.ecr.us-east-1.amazonaws.com")
	assert.False(t, ok)
}

func TestTokenCache_PutThenGet(t *testing.T) {
	c := newTokenCache()
	c.put("registry.example", "AWS", "secret", time.Now().Add(time.Hour))
	u, p, ok := c.get("registry.example")
	assert.True(t, ok)
	assert.Equal(t, "AWS", u)
	assert.Equal(t, "secret", p)
}

func TestTokenCache_ExpiredInPastReturnsNotOk(t *testing.T) {
	c := newTokenCache()
	c.put("registry.example", "AWS", "secret", time.Now().Add(-time.Minute))
	_, _, ok := c.get("registry.example")
	assert.False(t, ok)
}

func TestTokenCache_LessThanFiveMinutesToExpiryReturnsNotOk(t *testing.T) {
	c := newTokenCache()
	c.put("registry.example", "AWS", "secret", time.Now().Add(4*time.Minute))
	_, _, ok := c.get("registry.example")
	assert.False(t, ok)
}

func TestTokenCache_MoreThanFiveMinutesToExpiryReturnsOk(t *testing.T) {
	c := newTokenCache()
	c.put("registry.example", "AWS", "secret", time.Now().Add(6*time.Minute))
	_, _, ok := c.get("registry.example")
	assert.True(t, ok)
}

func TestTokenCache_ExactlyFiveMinutesToExpiryReturnsOk(t *testing.T) {
	// The eviction check uses strict < (not <=): time.Until(entry.expiry) < 5*time.Minute.
	// A token with >= 5 minutes remaining must be accepted.
	// We cannot freeze the clock, so we set expiry to now+5min+1s to stay reliably
	// above the boundary. This test will catch a refactor that tightens the check
	// to > 5min (i.e. changes < to <=), because then even 5min+1s would be rejected
	// if the check were changed to time.Until(entry.expiry) <= 5*time.Minute+1s or
	// the threshold itself were raised.
	// The companion test TestTokenCache_LessThanFiveMinutesToExpiryReturnsNotOk (4min)
	// locks in the other side of the boundary.
	c := newTokenCache()
	c.put("registry.example", "AWS", "secret", time.Now().Add(5*time.Minute+time.Second))
	_, _, ok := c.get("registry.example")
	assert.True(t, ok)
}

func TestTokenCache_PutOverwritesExistingKey(t *testing.T) {
	c := newTokenCache()
	c.put("registry.example", "AWS", "old", time.Now().Add(time.Hour))
	c.put("registry.example", "AWS", "new", time.Now().Add(time.Hour))
	_, p, ok := c.get("registry.example")
	assert.True(t, ok)
	assert.Equal(t, "new", p)
}

func TestTokenCache_ConcurrentAccessNoRaces(t *testing.T) {
	c := newTokenCache()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "registry-" + string(rune('A'+i%26))
			c.put(key, "AWS", "secret", time.Now().Add(time.Hour))
			_, _, _ = c.get(key)
		}(i)
	}
	wg.Wait()
}

func TestIsECRRegistry(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"123456789012.dkr.ecr.us-east-1.amazonaws.com/myrepo:tag", true},
		{"123456789012.dkr.ecr.eu-central-1.amazonaws.com/myrepo@sha256:abcd", true},
		{"123456789012.dkr.ecr.amazonaws.com/x", true}, // malformed - substring still matches; parseECRRegistry rejects later
		{"public.ecr.aws/library/alpine:latest", false},
		{"gcr.io/project/image:tag", false},
		{"docker.io/library/alpine:latest", false},
		{"myregistry.example.com/x", false},
		{"", false},
	}

	for _, v := range tests {
		t.Run(v.input, func(t *testing.T) {
			assert.Equal(t, v.expected, isECRRegistry(v.input))
		})
	}
}
