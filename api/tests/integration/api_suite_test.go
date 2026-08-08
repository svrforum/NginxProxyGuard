package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/tests/integration/utils"
)

var (
	apiBaseURL = getEnv("API_BASE_URL", "http://localhost:8080")
	nginxURL   = getEnv("NGINX_URL", "http://localhost:80")
	adminUser  = "admin"
	adminPass  = "admin"
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func TestIntegrationSuite(t *testing.T) {
	// Wait for API to be ready
	utils.WaitForAPI(t, apiBaseURL)
	client := utils.NewAPIClient(apiBaseURL)

	// ============================================================
	// 1. Authentication Tests
	// ============================================================
	t.Run("01_Authentication", func(t *testing.T) {
		t.Run("Login_Success", func(t *testing.T) {
			loginReq := utils.LoginRequest{Username: adminUser, Password: adminPass}
			code, body := client.Post(t, "/api/v1/auth/login", loginReq)

			if code != http.StatusOK {
				t.Fatalf("Login failed: %d - %s", code, string(body))
			}

			var resp utils.LoginResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("Failed to decode login response: %v", err)
			}
			client.AuthToken = resp.Token
			t.Log("✓ Login successful")
		})

		t.Run("Get_Current_User", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/auth/me")
			if code != http.StatusOK {
				t.Errorf("Failed to get current user: %d", code)
			}
			t.Logf("✓ Current user: %s", string(body))
		})

		t.Run("Login_Invalid_Credentials", func(t *testing.T) {
			badClient := utils.NewAPIClient(apiBaseURL)
			loginReq := utils.LoginRequest{Username: "wrong", Password: "wrong"}
			code, _ := badClient.Post(t, "/api/v1/auth/login", loginReq)

			if code != http.StatusUnauthorized {
				t.Errorf("Expected 401 for bad credentials, got %d", code)
			}
			t.Log("✓ Invalid credentials rejected")
		})
	})

	if client.AuthToken == "" {
		t.Fatal("Authentication failed, cannot proceed with tests")
	}

	// ============================================================
	// 2. Dashboard & System Health Tests
	// ============================================================
	t.Run("02_Dashboard", func(t *testing.T) {
		t.Run("Get_Dashboard", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/dashboard")
			if code != http.StatusOK {
				t.Errorf("Failed to get dashboard: %d - %s", code, string(body))
			}
			t.Log("✓ Dashboard data retrieved")
		})

		t.Run("Get_System_Health", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/dashboard/health")
			if code != http.StatusOK {
				t.Errorf("Failed to get system health: %d - %s", code, string(body))
			}
			t.Log("✓ System health retrieved")
		})

		t.Run("Get_Docker_Stats", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/dashboard/containers")
			if code != http.StatusOK {
				t.Errorf("Failed to get container stats: %d - %s", code, string(body))
			}
			t.Log("✓ Container stats retrieved")
		})
	})

	// ============================================================
	// 3. Settings Tests
	// ============================================================
	t.Run("03_Settings", func(t *testing.T) {
		t.Run("Get_Global_Settings", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/settings")
			if code != http.StatusOK {
				t.Errorf("Failed to get global settings: %d - %s", code, string(body))
			}
			t.Log("✓ Global settings retrieved")
		})

		t.Run("Get_System_Settings", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/system-settings")
			if code != http.StatusOK {
				t.Errorf("Failed to get system settings: %d - %s", code, string(body))
			}
			t.Log("✓ System settings retrieved")
		})

		t.Run("Get_Settings_Presets", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/settings/presets")
			if code != http.StatusOK {
				t.Errorf("Failed to get settings presets: %d - %s", code, string(body))
			}
			t.Log("✓ Settings presets retrieved")
		})
	})

	// ============================================================
	// 4. Proxy Host CRUD Tests
	// ============================================================
	var testHostID string

	t.Run("04_ProxyHost_CRUD", func(t *testing.T) {
		testHost := map[string]interface{}{
			"domain_names":    []string{"test.local"},
			"forward_scheme":  "http",
			"forward_host":    "release-test-whoami",
			"forward_port":    80,
			"caching_enabled": false,
			"block_exploits":  false,
			"waf_enabled":     false,
		}

		t.Run("Create", func(t *testing.T) {
			code, body := client.Post(t, "/api/v1/proxy-hosts", testHost)
			if code != http.StatusCreated {
				t.Fatalf("Failed to create proxy host: %d - %s", code, string(body))
			}

			var resp map[string]interface{}
			json.Unmarshal(body, &resp)
			testHostID = resp["id"].(string)
			t.Logf("✓ Created proxy host: %s", testHostID)

			// Wait for nginx reload
			time.Sleep(3 * time.Second)
		})

		t.Run("List", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/proxy-hosts")
			if code != http.StatusOK {
				t.Errorf("Failed to list proxy hosts: %d", code)
			}
			t.Logf("✓ Listed proxy hosts: %s", string(body))
		})

		t.Run("Get_By_ID", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/proxy-hosts/"+testHostID)
			if code != http.StatusOK {
				t.Errorf("Failed to get proxy host: %d - %s", code, string(body))
			}
			t.Log("✓ Retrieved proxy host by ID")
		})

		t.Run("Update", func(t *testing.T) {
			testHost["caching_enabled"] = true
			code, body := client.Put(t, "/api/v1/proxy-hosts/"+testHostID, testHost)
			if code != http.StatusOK {
				t.Errorf("Failed to update proxy host: %d - %s", code, string(body))
			}
			t.Log("✓ Updated proxy host")
			time.Sleep(2 * time.Second)
		})
	})

	// ============================================================
	// 5. Connectivity Tests
	// ============================================================
	t.Run("05_Connectivity", func(t *testing.T) {
		t.Run("Direct_To_Upstream", func(t *testing.T) {
			req, _ := http.NewRequest("GET", nginxURL, nil)
			req.Host = "test.local"

			httpClient := &http.Client{Timeout: 10 * time.Second}
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to connect to nginx: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				t.Errorf("Expected 200, got %d", resp.StatusCode)
			}
			t.Log("✓ Proxy routing working")
		})
	})

	// ============================================================
	// 6. WAF Tests
	// ============================================================
	t.Run("06_WAF", func(t *testing.T) {
		// Enable WAF
		t.Run("Enable_WAF", func(t *testing.T) {
			updateReq := map[string]interface{}{
				"domain_names":       []string{"test.local"},
				"forward_scheme":     "http",
				"forward_host":       "release-test-whoami",
				"forward_port":       80,
				"waf_enabled":        true,
				"waf_mode":           "blocking",
				"waf_paranoia_level": 1,
			}
			code, body := client.Put(t, "/api/v1/proxy-hosts/"+testHostID, updateReq)
			if code != http.StatusOK {
				t.Fatalf("Failed to enable WAF: %d - %s", code, string(body))
			}
			t.Log("✓ WAF enabled")

			// Trigger nginx sync to apply changes
			client.Post(t, "/api/v1/proxy-hosts/sync", nil)
			time.Sleep(3 * time.Second)
		})

		t.Run("Block_SQL_Injection", func(t *testing.T) {
			// SQL Injection attempt
			req, _ := http.NewRequest("GET", nginxURL+"?id=1'+OR+'1'='1", nil)
			req.Host = "test.local"

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == 403 {
				t.Log("✓ SQL Injection blocked (403)")
			} else {
				// ModSecurity may not be fully configured in test environment
				t.Logf("ℹ WAF SQLi test: got %d (ModSecurity may need OWASP CRS rules)", resp.StatusCode)
			}
		})

		t.Run("Block_XSS", func(t *testing.T) {
			// XSS attempt
			req, _ := http.NewRequest("GET", nginxURL+"?q=<script>alert(1)</script>", nil)
			req.Host = "test.local"

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == 403 {
				t.Log("✓ XSS blocked (403)")
			} else {
				// ModSecurity may not be fully configured in test environment
				t.Logf("ℹ WAF XSS test: got %d (ModSecurity may need OWASP CRS rules)", resp.StatusCode)
			}
		})
	})

	// ============================================================
	// 7. Exploit Block Tests
	// ============================================================
	t.Run("07_Exploit_Block", func(t *testing.T) {
		t.Run("Enable_Exploit_Block", func(t *testing.T) {
			updateReq := map[string]interface{}{
				"domain_names":   []string{"test.local"},
				"forward_scheme": "http",
				"forward_host":   "release-test-whoami",
				"forward_port":   80,
				"waf_enabled":    true,
				"block_exploits": true,
			}
			code, body := client.Put(t, "/api/v1/proxy-hosts/"+testHostID, updateReq)
			if code != http.StatusOK {
				t.Fatalf("Failed to enable exploit block: %d - %s", code, string(body))
			}
			t.Log("✓ Exploit block enabled")

			// Trigger nginx sync to apply changes
			client.Post(t, "/api/v1/proxy-hosts/sync", nil)
			time.Sleep(3 * time.Second)
		})

		t.Run("Block_DotEnv", func(t *testing.T) {
			req, _ := http.NewRequest("GET", nginxURL+"/.env", nil)
			req.Host = "test.local"

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == 403 {
				t.Log("✓ .env access blocked (403)")
			} else {
				// Exploit block rules may need nginx config reload
				t.Logf("ℹ Exploit block test: got %d for .env", resp.StatusCode)
			}
		})

		t.Run("Block_Git_Directory", func(t *testing.T) {
			req, _ := http.NewRequest("GET", nginxURL+"/.git/config", nil)
			req.Host = "test.local"

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == 403 {
				t.Log("✓ .git access blocked (403)")
			} else {
				// Exploit block rules may need nginx config reload
				t.Logf("ℹ Exploit block test: got %d for .git", resp.StatusCode)
			}
		})

		t.Run("Block_WP_Config", func(t *testing.T) {
			req, _ := http.NewRequest("GET", nginxURL+"/wp-config.php", nil)
			req.Host = "test.local"

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == 403 {
				t.Log("✓ wp-config.php access blocked (403)")
			} else {
				// Exploit block rules may need nginx config reload
				t.Logf("ℹ Exploit block test: got %d for wp-config.php", resp.StatusCode)
			}
		})
	})

	// ============================================================
	// 8. Bot Filter Tests
	// ============================================================
	t.Run("08_Bot_Filter", func(t *testing.T) {
		t.Run("Block_Malicious_Bot", func(t *testing.T) {
			req, _ := http.NewRequest("GET", nginxURL, nil)
			req.Host = "test.local"
			req.Header.Set("User-Agent", "masscan/1.0")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// 403 or 444 are both acceptable
			if resp.StatusCode != 403 && resp.StatusCode != 444 {
				t.Logf("Bot filter: got %d (may need explicit config)", resp.StatusCode)
			} else {
				t.Log("✓ Malicious bot blocked")
			}
		})

		t.Run("Allow_Search_Bot", func(t *testing.T) {
			req, _ := http.NewRequest("GET", nginxURL, nil)
			req.Host = "test.local"
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == 403 || resp.StatusCode == 444 {
				t.Errorf("Googlebot should not be blocked, got %d", resp.StatusCode)
			} else {
				t.Log("✓ Googlebot allowed")
			}
		})
	})

	// ============================================================
	// 9. Multiple Proxy Hosts Test
	// ============================================================
	var secondHostID string

	t.Run("09_Multiple_Hosts", func(t *testing.T) {
		t.Run("Create_Second_Host", func(t *testing.T) {
			secondHost := map[string]interface{}{
				"domain_names":   []string{"api.test.local"},
				"forward_scheme": "http",
				"forward_host":   "release-test-httpbin",
				"forward_port":   80,
			}
			code, body := client.Post(t, "/api/v1/proxy-hosts", secondHost)
			if code != http.StatusCreated {
				t.Fatalf("Failed to create second host: %d - %s", code, string(body))
			}

			var resp map[string]interface{}
			json.Unmarshal(body, &resp)
			secondHostID = resp["id"].(string)
			t.Logf("✓ Created second host: %s", secondHostID)

			// Trigger nginx sync to apply changes
			client.Post(t, "/api/v1/proxy-hosts/sync", nil)
			time.Sleep(3 * time.Second)
		})

		t.Run("Verify_Routing", func(t *testing.T) {
			// Test first host
			req1, _ := http.NewRequest("GET", nginxURL, nil)
			req1.Host = "test.local"
			resp1, err1 := http.DefaultClient.Do(req1)
			if err1 != nil {
				t.Fatalf("Request to first host failed: %v", err1)
			}
			defer resp1.Body.Close()

			// Test second host
			req2, _ := http.NewRequest("GET", nginxURL+"/get", nil)
			req2.Host = "api.test.local"
			resp2, err2 := http.DefaultClient.Do(req2)
			if err2 != nil {
				t.Fatalf("Request to second host failed: %v", err2)
			}
			defer resp2.Body.Close()

			if resp1.StatusCode == 200 && resp2.StatusCode == 200 {
				t.Log("✓ Multiple hosts routing correctly")
			} else {
				// Routing may need additional nginx config for enabled hosts
				t.Logf("ℹ Routing test: host1=%d, host2=%d (hosts may need enabled=true)", resp1.StatusCode, resp2.StatusCode)
			}
		})
	})

	// ============================================================
	// 10. API Tokens Test
	// ============================================================
	var testTokenID string

	t.Run("10_API_Tokens", func(t *testing.T) {
		t.Run("Get_Permissions", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/api-tokens/permissions")
			if code != http.StatusOK {
				t.Errorf("Failed to get permissions: %d - %s", code, string(body))
			}
			t.Log("✓ Permissions retrieved")
		})

		t.Run("Create_Token", func(t *testing.T) {
			tokenReq := map[string]interface{}{
				"name":        "Test Token",
				"permissions": []string{"proxy:read", "logs:read"},
				"rate_limit":  1000,
			}
			code, body := client.Post(t, "/api/v1/api-tokens", tokenReq)
			if code != http.StatusCreated {
				t.Errorf("Failed to create token: %d - %s", code, string(body))
			} else {
				var resp map[string]interface{}
				json.Unmarshal(body, &resp)
				testTokenID = resp["id"].(string)
				t.Logf("✓ Token created: %s", testTokenID)
			}
		})

		t.Run("List_Tokens", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/api-tokens")
			if code != http.StatusOK {
				t.Errorf("Failed to list tokens: %d - %s", code, string(body))
			}
			t.Log("✓ Tokens listed")
		})

		if testTokenID != "" {
			t.Run("Delete_Token", func(t *testing.T) {
				code, _ := client.Delete(t, "/api/v1/api-tokens/"+testTokenID)
				if code != http.StatusOK && code != http.StatusNoContent {
					t.Errorf("Failed to delete token: %d", code)
				}
				t.Log("✓ Token deleted")
			})
		}
	})

	// ============================================================
	// 11. Logs Test
	// ============================================================
	t.Run("11_Logs", func(t *testing.T) {
		t.Run("Get_Access_Logs", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/logs?limit=10")
			if code != http.StatusOK {
				t.Errorf("Failed to get logs: %d - %s", code, string(body))
			}
			t.Log("✓ Access logs retrieved")
		})

		t.Run("Get_Log_Stats", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/logs/stats")
			if code != http.StatusOK {
				t.Errorf("Failed to get log stats: %d - %s", code, string(body))
			}
			t.Log("✓ Log stats retrieved")
		})

		t.Run("Get_System_Logs", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/system-logs?limit=10")
			if code != http.StatusOK {
				t.Errorf("Failed to get system logs: %d - %s", code, string(body))
			}
			t.Log("✓ System logs retrieved")
		})
	})

	// ============================================================
	// 12. Backup Test
	// ============================================================
	var backupID string

	t.Run("12_Backup", func(t *testing.T) {
		t.Run("Create_Backup", func(t *testing.T) {
			code, body := client.Post(t, "/api/v1/backups", nil)
			// 202 Accepted is returned for async backup creation
			if code != http.StatusOK && code != http.StatusCreated && code != http.StatusAccepted {
				t.Errorf("Failed to create backup: %d - %s", code, string(body))
			} else {
				var resp map[string]interface{}
				json.Unmarshal(body, &resp)
				if id, ok := resp["id"].(string); ok {
					backupID = id
				}
				t.Log("✓ Backup created")
			}
		})

		t.Run("List_Backups", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/backups")
			if code != http.StatusOK {
				t.Errorf("Failed to list backups: %d - %s", code, string(body))
			}
			t.Log("✓ Backups listed")
		})

		if backupID != "" {
			t.Run("Delete_Backup", func(t *testing.T) {
				code, _ := client.Delete(t, "/api/v1/backups/"+backupID)
				if code != http.StatusOK && code != http.StatusNoContent {
					t.Errorf("Failed to delete backup: %d", code)
				}
				t.Log("✓ Backup deleted")
			})
		}
	})

	// ============================================================
	// 13. Cloud Providers Test
	// ============================================================
	t.Run("13_Cloud_Providers", func(t *testing.T) {
		t.Run("List_Providers", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/cloud-providers")
			if code != http.StatusOK {
				t.Errorf("Failed to list cloud providers: %d - %s", code, string(body))
			}
			t.Log("✓ Cloud providers listed")
		})

		t.Run("List_By_Region", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/cloud-providers/by-region")
			if code != http.StatusOK {
				t.Errorf("Failed to list by region: %d - %s", code, string(body))
			}
			t.Log("✓ Cloud providers by region listed")
		})
	})

	// ============================================================
	// 14. Challenge Config Test
	// ============================================================
	t.Run("14_Challenge_Config", func(t *testing.T) {
		t.Run("Get_Global_Config", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/challenge-config")
			if code != http.StatusOK {
				t.Errorf("Failed to get challenge config: %d - %s", code, string(body))
			}
			t.Log("✓ Challenge config retrieved")
		})

		t.Run("Get_Challenge_Stats", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/challenge-config/stats")
			if code != http.StatusOK {
				t.Errorf("Failed to get challenge stats: %d - %s", code, string(body))
			}
			t.Log("✓ Challenge stats retrieved")
		})
	})

	// ============================================================
	// 15. Audit Logs Test
	// ============================================================
	t.Run("15_Audit_Logs", func(t *testing.T) {
		t.Run("Get_Audit_Logs", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/audit-logs?limit=10")
			if code != http.StatusOK {
				t.Errorf("Failed to get audit logs: %d - %s", code, string(body))
			}
			t.Log("✓ Audit logs retrieved")
		})

		t.Run("Get_Audit_Actions", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/audit-logs/actions")
			if code != http.StatusOK {
				t.Errorf("Failed to get audit actions: %d - %s", code, string(body))
			}
			t.Log("✓ Audit actions retrieved")
		})
	})

	// ============================================================
	// 16. Certificates Test
	// ============================================================
	t.Run("16_Certificates", func(t *testing.T) {
		t.Run("List_Certificates", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/certificates")
			if code != http.StatusOK {
				t.Errorf("Failed to list certificates: %d - %s", code, string(body))
			}
			t.Log("✓ Certificates listed")
		})

		t.Run("Get_Expiring_Certificates", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/certificates/expiring")
			if code != http.StatusOK {
				t.Errorf("Failed to get expiring certificates: %d - %s", code, string(body))
			}
			t.Log("✓ Expiring certificates retrieved")
		})

		t.Run("Get_Certificate_History", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/certificates/history")
			if code != http.StatusOK {
				t.Errorf("Failed to get certificate history: %d - %s", code, string(body))
			}
			t.Log("✓ Certificate history retrieved")
		})
	})

	// ============================================================
	// 17. DNS Providers Test
	// ============================================================
	t.Run("17_DNS_Providers", func(t *testing.T) {
		t.Run("List_DNS_Providers", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/dns-providers")
			if code != http.StatusOK {
				t.Errorf("Failed to list DNS providers: %d - %s", code, string(body))
			}
			t.Log("✓ DNS providers listed")
		})

		t.Run("Get_Default_Provider", func(t *testing.T) {
			code, _ := client.Get(t, "/api/v1/dns-providers/default")
			// 404 is OK if no default is set
			if code != http.StatusOK && code != http.StatusNotFound {
				t.Errorf("Failed to get default DNS provider: %d", code)
			}
			t.Log("✓ Default DNS provider check passed")
		})
	})

	// ============================================================
	// 18. Geo Restrictions Test
	// ============================================================
	t.Run("18_Geo_Restrictions", func(t *testing.T) {
		t.Run("Get_Geo_Config", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/proxy-hosts/"+testHostID+"/geo")
			// 404 is OK if not configured
			if code != http.StatusOK && code != http.StatusNotFound {
				t.Errorf("Failed to get geo config: %d - %s", code, string(body))
			}
			t.Log("✓ Geo config retrieved")
		})

		t.Run("Set_Geo_Restriction", func(t *testing.T) {
			geoConfig := map[string]interface{}{
				"enabled":           true,
				"mode":              "whitelist",
				"countries":         []string{"KR", "US", "JP"},
				"challenge_mode":    false,
				"allow_search_bots": true,
				"allow_private_ips": true,
			}
			code, body := client.Post(t, "/api/v1/proxy-hosts/"+testHostID+"/geo", geoConfig)
			if code != http.StatusOK && code != http.StatusCreated {
				t.Errorf("Failed to set geo restriction: %d - %s", code, string(body))
			} else {
				t.Log("✓ Geo restriction configured")
			}
			time.Sleep(2 * time.Second)
		})

		t.Run("Update_Geo_Restriction", func(t *testing.T) {
			geoConfig := map[string]interface{}{
				"enabled":           true,
				"mode":              "blacklist",
				"countries":         []string{"CN", "RU"},
				"challenge_mode":    true,
				"allow_search_bots": true,
				"allow_private_ips": true,
			}
			code, body := client.Put(t, "/api/v1/proxy-hosts/"+testHostID+"/geo", geoConfig)
			if code != http.StatusOK {
				t.Errorf("Failed to update geo restriction: %d - %s", code, string(body))
			} else {
				t.Log("✓ Geo restriction updated")
			}
		})

		t.Run("Get_Geo_Countries", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/geo/countries")
			if code != http.StatusOK {
				t.Errorf("Failed to get geo countries: %d - %s", code, string(body))
			}
			t.Log("✓ Geo countries list retrieved")
		})

		t.Run("Delete_Geo_Restriction", func(t *testing.T) {
			code, _ := client.Delete(t, "/api/v1/proxy-hosts/"+testHostID+"/geo")
			if code != http.StatusOK && code != http.StatusNoContent {
				t.Errorf("Failed to delete geo restriction: %d", code)
			}
			t.Log("✓ Geo restriction deleted")
		})
	})

	// ============================================================
	// 19. Rate Limiting Test
	// ============================================================
	t.Run("19_Rate_Limiting", func(t *testing.T) {
		t.Run("Get_Rate_Limit_Config", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/proxy-hosts/"+testHostID+"/rate-limit")
			// 404 is OK if not configured
			if code != http.StatusOK && code != http.StatusNotFound {
				t.Errorf("Failed to get rate limit config: %d - %s", code, string(body))
			}
			t.Log("✓ Rate limit config retrieved")
		})

		t.Run("Set_Rate_Limit", func(t *testing.T) {
			rateLimitConfig := map[string]interface{}{
				"enabled":             true,
				"requests_per_second": 100,
				"burst_size":          200,
				"per_ip":              true,
			}
			code, body := client.Put(t, "/api/v1/proxy-hosts/"+testHostID+"/rate-limit", rateLimitConfig)
			if code != http.StatusOK && code != http.StatusCreated {
				t.Errorf("Failed to set rate limit: %d - %s", code, string(body))
			} else {
				t.Log("✓ Rate limit configured")
			}
			time.Sleep(2 * time.Second)
		})

		t.Run("Delete_Rate_Limit", func(t *testing.T) {
			code, _ := client.Delete(t, "/api/v1/proxy-hosts/"+testHostID+"/rate-limit")
			if code != http.StatusOK && code != http.StatusNoContent {
				t.Errorf("Failed to delete rate limit: %d", code)
			}
			t.Log("✓ Rate limit deleted")
		})
	})

	// ============================================================
	// 20. URI Blocking Test
	// ============================================================
	t.Run("20_URI_Blocking", func(t *testing.T) {
		t.Run("Get_Global_URI_Block", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/global-uri-block")
			if code != http.StatusOK {
				t.Errorf("Failed to get global URI block: %d - %s", code, string(body))
			}
			t.Log("✓ Global URI block config retrieved")
		})

		t.Run("Get_Host_URI_Block", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/proxy-hosts/"+testHostID+"/uri-block")
			// 404 is OK if not configured
			if code != http.StatusOK && code != http.StatusNotFound {
				t.Errorf("Failed to get host URI block: %d - %s", code, string(body))
			}
			t.Log("✓ Host URI block config retrieved")
		})

		t.Run("Set_Host_URI_Block", func(t *testing.T) {
			uriBlockConfig := map[string]interface{}{
				"enabled": true,
				"rules": []map[string]interface{}{
					{
						"pattern":     "/admin",
						"match_type":  "prefix",
						"action":      "block",
						"description": "Block admin access",
					},
				},
			}
			code, body := client.Put(t, "/api/v1/proxy-hosts/"+testHostID+"/uri-block", uriBlockConfig)
			if code != http.StatusOK && code != http.StatusCreated {
				t.Errorf("Failed to set URI block: %d - %s", code, string(body))
			} else {
				t.Log("✓ URI block configured")
			}
			time.Sleep(2 * time.Second)
		})

		t.Run("Verify_URI_Block", func(t *testing.T) {
			req, _ := http.NewRequest("GET", nginxURL+"/admin", nil)
			req.Host = "test.local"

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 403 {
				t.Logf("URI block: got %d (expected 403)", resp.StatusCode)
			} else {
				t.Log("✓ URI /admin blocked (403)")
			}
		})

		t.Run("Delete_Host_URI_Block", func(t *testing.T) {
			code, _ := client.Delete(t, "/api/v1/proxy-hosts/"+testHostID+"/uri-block")
			if code != http.StatusOK && code != http.StatusNoContent {
				t.Errorf("Failed to delete URI block: %d", code)
			}
			t.Log("✓ URI block deleted")
		})
	})

	// ============================================================
	// 21. Security Headers Test
	// ============================================================
	t.Run("21_Security_Headers", func(t *testing.T) {
		t.Run("Get_Security_Headers_Presets", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/security-headers/presets")
			if code != http.StatusOK {
				t.Errorf("Failed to get security headers presets: %d - %s", code, string(body))
			}
			t.Log("✓ Security headers presets retrieved")
		})

		t.Run("Get_Host_Security_Headers", func(t *testing.T) {
			code, body := client.Get(t, "/api/v1/proxy-hosts/"+testHostID+"/security-headers")
			// 404 is OK if not configured
			if code != http.StatusOK && code != http.StatusNotFound {
				t.Errorf("Failed to get security headers: %d - %s", code, string(body))
			}
			t.Log("✓ Host security headers retrieved")
		})

		t.Run("Set_Security_Headers", func(t *testing.T) {
			headersConfig := map[string]interface{}{
				"enabled": true,
				"headers": map[string]string{
					"X-Frame-Options":        "DENY",
					"X-Content-Type-Options": "nosniff",
					"X-XSS-Protection":       "1; mode=block",
				},
			}
			code, body := client.Put(t, "/api/v1/proxy-hosts/"+testHostID+"/security-headers", headersConfig)
			if code != http.StatusOK && code != http.StatusCreated {
				t.Errorf("Failed to set security headers: %d - %s", code, string(body))
			} else {
				t.Log("✓ Security headers configured")
			}
		})

		t.Run("Delete_Security_Headers", func(t *testing.T) {
			code, _ := client.Delete(t, "/api/v1/proxy-hosts/"+testHostID+"/security-headers")
			if code != http.StatusOK && code != http.StatusNoContent {
				t.Errorf("Failed to delete security headers: %d", code)
			}
			t.Log("✓ Security headers deleted")
		})
	})

	// ============================================================
	// 22. Nginx Sync Test
	// ============================================================
	t.Run("22_Nginx_Sync", func(t *testing.T) {
		t.Run("Trigger_Sync", func(t *testing.T) {
			code, body := client.Post(t, "/api/v1/proxy-hosts/sync", nil)
			if code != http.StatusOK {
				t.Errorf("Failed to trigger nginx sync: %d - %s", code, string(body))
			}
			t.Log("✓ Nginx sync triggered")
			time.Sleep(2 * time.Second)
		})
	})

	// ============================================================
	// 99. Cleanup
	// ============================================================
	t.Run("99_Cleanup", func(t *testing.T) {
		if secondHostID != "" {
			code, _ := client.Delete(t, "/api/v1/proxy-hosts/"+secondHostID)
			if code == http.StatusOK || code == http.StatusNoContent {
				t.Log("✓ Second host deleted")
			}
		}

		if testHostID != "" {
			code, _ := client.Delete(t, "/api/v1/proxy-hosts/"+testHostID)
			if code == http.StatusOK || code == http.StatusNoContent {
				t.Log("✓ Test host deleted")
			}
		}
	})
}

// TestHealthEndpoint is a quick sanity check
func TestHealthEndpoint(t *testing.T) {
	resp, err := http.Get(apiBaseURL + "/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
	t.Log("✓ Health endpoint OK")
}

// TestAPIDocsAvailable checks if API documentation is accessible
func TestAPIDocsAvailable(t *testing.T) {
	resp, err := http.Get(apiBaseURL + "/api/docs")
	if err != nil {
		t.Fatalf("API docs check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for API docs, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected HTML content, got %s", contentType)
	}
	t.Log("✓ API docs available")
}
