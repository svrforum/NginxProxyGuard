package utils

import (
	"testing"
	"time"
)

// WaitForAPI waits for the API to be ready
func WaitForAPI(t *testing.T, baseURL string) {
	client := NewAPIClient(baseURL)
	maxRetries := 30

	for i := 0; i < maxRetries; i++ {
		// Try to hit health endpoint
		// Note: Using a simple req directly to avoid Auth checks if any
		resp, err := client.HTTPClient.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			t.Logf("API is ready at %s", baseURL)
			return
		}
		if resp != nil {
			resp.Body.Close()
		}

		time.Sleep(1 * time.Second)
	}

	t.Fatalf("API did not become ready at %s after %d seconds", baseURL, maxRetries)
}
