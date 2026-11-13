package service

import "testing"

func TestSkipErrorLogLine(t *testing.T) {
	skipped := []string{
		`2026/11/13 10:00:00 [notice] 1#1: signal process started`,
		`2026/11/13 10:00:00 [warn] 22#22: *1 an upstream response is buffered to a temporary file`,
		// error_log_level info: one line per matched rule, value and all.
		`2026/11/13 10:00:00 [info] 22#22: *9 ModSecurity: Warning. detected SQLi using libinjection against variable ` +
			"`ARGS:password' (Value: `Exmpl';--Val1' )" + ` [file "/etc/nginx/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [id "942100"] [data "Matched Data: s&1c found within ARGS:password: Exmpl';--Val1"], client: 192.0.2.10, server: app.example.com`,
	}
	for _, l := range skipped {
		if !skipErrorLogLine(l) {
			t.Errorf("stored: %s", l)
		}
	}
	kept := []string{
		// The anomaly scores, which the audit record leaves out.
		`2026/11/13 10:00:00 [info] 22#22: *9 ModSecurity: Warning. Matched "Operator ` + "`Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' )" + `" [id "980170"] [msg "Anomaly Scores: (Inbound Scores: blocking=5)"]`,
		`2026/11/13 10:00:00 [error] 22#22: *3 connect() failed (111: Connection refused) while connecting to upstream, client: 192.0.2.10, server: app.example.com`,
		`2026/11/13 10:00:00 [error] 22#22: *4 [client 192.0.2.10] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator ` + "`Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' )" + `" [id "949110"]`,
	}
	for _, l := range kept {
		if skipErrorLogLine(l) {
			t.Errorf("skipped: %s", l)
		}
	}
}
