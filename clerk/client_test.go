package clerk

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNewClientRejectsIncompleteConfiguration keeps token validation fail-closed.
func TestNewClientRejectsIncompleteConfiguration(t *testing.T) {
	_, err := NewClient("", []string{"https://app.example"}, time.Minute)
	require.Error(t, err)
	_, err = NewClient("sk_test_example", nil, time.Minute)
	require.Error(t, err)
	client, err := NewClient("sk_test_example", []string{" https://app.example "}, time.Minute)
	require.NoError(t, err)
	require.Contains(t, client.parties, "https://app.example")
}
