package service

import (
	"bufio"
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/redact"
	"nginx-proxy-guard/internal/repository"
)

// Fake credentials. None of them may reach anything a failed delivery reports.
const (
	webhookPathSecret  = "hook-path-secret-3f9a"
	webhookQuerySecret = "query-secret-7c21"
	discordWebhookID   = "112233445566778899"
	discordToken       = "discord-token-Xy9_Ab8-Cd7"
	telegramBotToken   = "123456789:AAH-telegram_secret-Zz"
	// hostCredential is the first label of a receiver's host name, which is
	// where a service such as Pipedream (https://<credential>.m.pipedream.net)
	// puts the credential.
	hostCredential = "eo1a2b3c4d5e6f7g"
)

// boundArg is a sqlmock argument matcher that matches anything and keeps the
// value, so the assertion is about what would have been written to the row.
type boundArg struct{ into *string }

func (b boundArg) Match(v driver.Value) bool {
	switch s := v.(type) {
	case string:
		*b.into = s
	case []byte:
		*b.into = string(s)
	default:
		*b.into = fmt.Sprint(v)
	}
	return true
}

// closedLoopbackURL is a receiver that cannot be reached: a loopback port
// nothing listens on.
func closedLoopbackURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

// echoingReceiverURL is a receiver that answers with the request target in the
// status line. That is malformed, so net/http quotes it back in its error, the
// way it would for a confused proxy in front of a real receiver.
func echoingReceiverURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				fmt.Fprintf(c, "HTTP/1.1 %s\r\n\r\n", req.RequestURI)
			}(conn)
		}
	}()
	return "http://" + ln.Addr().String()
}

// telegramEchoURL stands in for api.telegram.org and refuses every request
// with a description that quotes the request path, bot token included.
func telegramEchoURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error_code": 400,
			"description": "Bad Request: no such method " + r.URL.Path})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

type dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

// refusingDial reaches a loopback port nothing listens on whatever host it is
// asked for, so a receiver of any name is refused without a lookup.
func refusingDial(t *testing.T) dialFunc {
	closed := strings.TrimPrefix(closedLoopbackURL(t), "http://")
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, closed)
	}
}

// unresolvableDial looks names up with a resolver that has no server to ask:
// nothing leaves the machine, and the lookup fails naming the host.
func unresolvableDial(*testing.T) dialFunc {
	noServer := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("no DNS server in this test")
	}
	return (&net.Dialer{Resolver: &net.Resolver{PreferGo: true, Dial: noServer}}).DialContext
}

type deliveryCase struct {
	name    string
	channel func(t *testing.T) *model.NotificationChannel
	// telegramBase points the Telegram adapter at a stand-in; nil for the
	// other channel types.
	telegramBase func(t *testing.T) string
	// webhookDial replaces how the webhook adapter connects; nil keeps it.
	webhookDial func(t *testing.T) dialFunc
	secrets     []string
	want        string // the diagnosis that must survive
	// terminal: the receiver answered and refused, so the outbox fails the
	// row at once instead of scheduling a retry.
	terminal bool
}

func deliveryCases() []deliveryCase {
	webhook := func(base func(*testing.T) string) func(*testing.T) *model.NotificationChannel {
		return func(t *testing.T) *model.NotificationChannel {
			return &model.NotificationChannel{ID: "chan-webhook", Name: "ntfy", Type: model.NotificationTypeWebhook,
				AllowPrivateTarget: true, Language: "en",
				Config: map[string]string{"url": base(t) + "/" + webhookPathSecret + "?token=" + webhookQuerySecret}}
		}
	}
	discord := func(base func(*testing.T) string) func(*testing.T) *model.NotificationChannel {
		return func(t *testing.T) *model.NotificationChannel {
			return &model.NotificationChannel{ID: "chan-discord", Name: "discord", Type: model.NotificationTypeDiscord,
				AllowPrivateTarget: true, Language: "en",
				Config: map[string]string{"url": base(t) + "/api/webhooks/" + discordWebhookID + "/" + discordToken}}
		}
	}
	telegram := func(t *testing.T) *model.NotificationChannel {
		return &model.NotificationChannel{ID: "chan-telegram", Name: "telegram", Type: model.NotificationTypeTelegram,
			Language: "en", Config: map[string]string{"bot_token": telegramBotToken, "chat_id": "-100123"}}
	}
	namedByHost := func(t *testing.T) *model.NotificationChannel {
		return &model.NotificationChannel{ID: "chan-host", Name: "by-host", Type: model.NotificationTypeWebhook,
			Language: "en", Config: map[string]string{"url": "http://" + hostCredential + ".m.example.com"}}
	}
	webhookSecrets := []string{webhookPathSecret, webhookQuerySecret}
	discordSecrets := []string{discordWebhookID, discordToken}
	telegramSecrets := []string{telegramBotToken, url.QueryEscape(telegramBotToken), strings.SplitN(telegramBotToken, ":", 2)[1]}
	return []deliveryCase{
		{name: "webhook unreachable", channel: webhook(closedLoopbackURL), secrets: webhookSecrets, want: "connection refused"},
		{name: "webhook echoes the request", channel: webhook(echoingReceiverURL), secrets: webhookSecrets, want: "malformed HTTP status code"},
		{name: "discord unreachable", channel: discord(closedLoopbackURL), secrets: discordSecrets, want: "connection refused"},
		{name: "discord echoes the request", channel: discord(echoingReceiverURL), secrets: discordSecrets, want: "malformed HTTP status code"},
		{name: "telegram unreachable", channel: telegram, telegramBase: closedLoopbackURL, secrets: telegramSecrets, want: "connection refused"},
		{name: "telegram echoes the request", channel: telegram, telegramBase: echoingReceiverURL, secrets: telegramSecrets, want: "malformed HTTP status code"},
		{name: "telegram quotes the path", channel: telegram, telegramBase: telegramEchoURL, secrets: telegramSecrets, want: "Bad Request: no such method /bot", terminal: true},
		{name: "webhook named by its host refused", channel: namedByHost, webhookDial: refusingDial, secrets: []string{hostCredential}, want: "connection refused"},
		{name: "webhook named by its host unresolvable", channel: namedByHost, webhookDial: unresolvableDial, secrets: []string{hostCredential}, want: "lookup [redacted].m.example.com"},
	}
}

// newSecretsDispatcher is the real dispatcher over a mocked database, with the
// Telegram adapter pointed at a loopback stand-in when the case needs one.
func newSecretsDispatcher(t *testing.T, tc deliveryCase) (*NotificationDispatcher, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	d := NewNotificationDispatcher(repository.NewNotificationRepository(&database.DB{DB: db}), nil)
	if tc.telegramBase != nil {
		d.adapters[model.NotificationTypeTelegram] = newTelegramAdapterWithBase(tc.telegramBase(t), nil)
	}
	if tc.webhookDial != nil {
		client := notifyHTTPClient()
		client.Transport = &http.Transport{DialContext: tc.webhookDial(t)}
		d.adapters[model.NotificationTypeWebhook] = &webhookAdapter{client: client}
	}
	return d, mock
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func assertNoSecrets(t *testing.T, tc deliveryCase, reported map[string]string) {
	t.Helper()
	for where, text := range reported {
		for _, secret := range tc.secrets {
			if strings.Contains(text, secret) {
				t.Errorf("%q reaches the %s: %s", secret, where, text)
			}
		}
	}
}

// The Test button sends at once and reports the result three ways: the error
// it answers with, the channel's last_error and a delivery-log row, plus the
// container log line. A webhook or Discord URL is the credential as a whole
// and the Telegram bot token sits in the request path, so net/http's
// `Post "<URL>": ...` and anything a receiver quotes back carried them into
// all four. They must still say which receiver failed and why.
func TestSendTestKeepsChannelCredentialsOutOfWhatItReports(t *testing.T) {
	for _, tc := range deliveryCases() {
		t.Run(tc.name, func(t *testing.T) {
			d, mock := newSecretsDispatcher(t, tc)
			ch := tc.channel(t)
			logs := captureLog(t)

			var channelErr, attemptErr string
			mock.ExpectQuery(regexp.QuoteMeta(`WITH prev AS (SELECT enabled FROM notification_channels WHERE id = $1)`)).
				WithArgs(ch.ID, boundArg{&channelErr}).
				WillReturnRows(sqlmock.NewRows([]string{"prev_enabled", "enabled"}).AddRow(true, true))
			mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO notification_outbox (channel_id, event_key, payload, status, attempts, last_error, sent_at)`)).
				WithArgs(ch.ID, sqlmock.AnyArg(), sqlmock.AnyArg(), "failed", boundArg{&attemptErr}).
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := d.SendTest(context.Background(), ch, "")
			if err == nil {
				t.Fatal("expected the test delivery to fail")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("expectations: %v", err)
			}
			for where, text := range map[string]string{"response": err.Error(), "channel last_error": channelErr, "delivery log": attemptErr} {
				if !strings.Contains(text, tc.want) {
					t.Errorf("the %s lost the diagnosis %q: %s", where, tc.want, text)
				}
			}
			if host := receiverHost(ch, tc); host != "" && !strings.Contains(err.Error(), host) {
				t.Errorf("the response no longer names the receiver %s: %s", host, err)
			}
			assertNoSecrets(t, tc, map[string]string{
				"response": err.Error(), "channel last_error": channelErr,
				"delivery log": attemptErr, "container log": logs.String(),
			})
		})
	}
}

func claimDueColumns() []string {
	cols := make([]string, 30)
	for i := range cols {
		cols[i] = fmt.Sprintf("col%d", i)
	}
	return cols
}

// receiverHost is the host:port of the receiver a case delivers to, which a
// redacted error must still name — with the first label of the name masked when
// nothing follows the host, as redact.URL does.
func receiverHost(ch *model.NotificationChannel, tc deliveryCase) string {
	if tc.telegramBase != nil {
		return "" // the stand-in's address is only known inside the adapter
	}
	_, rest, _ := strings.Cut(redact.URL(ch.Config["url"]), "://")
	host, _, _ := strings.Cut(rest, "/")
	return host
}

// The outbox path stores the same text twice more: the row's last_error while
// it waits for a retry, the channel's last_error, and — once the attempts run
// out — "gave up after ..." with a container log line.
func TestDispatchOnceKeepsChannelCredentialsOutOfWhatItStores(t *testing.T) {
	for _, attempts := range []int{0, maxAttempts - 1} {
		for _, tc := range deliveryCases() {
			t.Run(fmt.Sprintf("%s after %d attempts", tc.name, attempts), func(t *testing.T) {
				d, mock := newSecretsDispatcher(t, tc)
				ch := tc.channel(t)
				logs := captureLog(t)

				config, _ := json.Marshal(ch.Config)
				payload, _ := json.Marshal(model.RenderedMessage{Event: "cert.renewal_failed", Severity: "error",
					Text: "renewal failed", Fields: map[string]string{"host": "a.example.com"}})
				now := time.Now()
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT to_regclass('public.notification_channels')`)).
					WillReturnRows(sqlmock.NewRows([]string{"ok"}).AddRow(true))
				mock.ExpectQuery(regexp.QuoteMeta(`FROM notification_outbox o`)).
					WithArgs(25).
					WillReturnRows(sqlmock.NewRows(claimDueColumns()).AddRow(
						int64(7), ch.ID, "cert.renewal_failed", payload, "queued", int64(attempts), now, "", now, nil,
						ch.ID, ch.Name, ch.Type, true, config, "{}", "{}", ch.RichFormat, ch.Language, "", false, int64(9),
						ch.AllowPrivateTarget, "", nil, nil, "", int64(0), now, now))

				var outboxErr, channelErr string
				if tc.terminal || attempts+1 >= maxAttempts {
					mock.ExpectExec(regexp.QuoteMeta(`UPDATE notification_outbox SET status='failed', attempts=attempts+1, last_error=$2 WHERE id=$1`)).
						WithArgs(int64(7), boundArg{&outboxErr}).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectQuery(regexp.QuoteMeta(`WITH prev AS (SELECT enabled FROM notification_channels WHERE id = $1)`)).
						WithArgs(ch.ID, boundArg{&channelErr}).
						WillReturnRows(sqlmock.NewRows([]string{"prev_enabled", "enabled"}).AddRow(true, true))
				} else {
					mock.ExpectExec(regexp.QuoteMeta(`SET attempts = attempts + 1, next_attempt_at = now() + $2::interval, last_error = $3`)).
						WithArgs(int64(7), sqlmock.AnyArg(), boundArg{&outboxErr}).
						WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectExec(regexp.QuoteMeta(`UPDATE notification_channels SET last_error_at = now(), last_error = $2 WHERE id = $1`)).
						WithArgs(ch.ID, boundArg{&channelErr}).
						WillReturnResult(sqlmock.NewResult(0, 1))
				}

				if _, err := d.DispatchOnce(context.Background()); err != nil {
					t.Fatalf("DispatchOnce: %v", err)
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatalf("expectations: %v", err)
				}
				for where, text := range map[string]string{"outbox last_error": outboxErr, "channel last_error": channelErr} {
					if !strings.Contains(text, tc.want) {
						t.Errorf("the %s lost the diagnosis %q: %s", where, tc.want, text)
					}
				}
				assertNoSecrets(t, tc, map[string]string{
					"outbox last_error": outboxErr, "channel last_error": channelErr, "container log": logs.String(),
				})
			})
		}
	}
}

// "Detect" asks getUpdates with the bot token in the path and answers with the
// error when that fails — also when the token is the stored one, which the API
// otherwise never reads back.
func TestDetectTelegramChatsKeepsTheTokenOutOfItsError(t *testing.T) {
	for name, base := range map[string]func(*testing.T) string{
		"unreachable":        closedLoopbackURL,
		"echoes the request": echoingReceiverURL,
		"quotes the path":    telegramEchoURL,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := detectTelegramChatsAt(context.Background(), base(t), telegramBotToken)
			if err == nil {
				t.Fatal("expected detection to fail")
			}
			for _, secret := range []string{telegramBotToken, url.QueryEscape(telegramBotToken), strings.SplitN(telegramBotToken, ":", 2)[1]} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the token reaches the response: %v", err)
				}
			}
			if !strings.Contains(err.Error(), "127.0.0.1") && !strings.Contains(err.Error(), "Bad Request") {
				t.Errorf("the error no longer says what failed: %v", err)
			}
		})
	}
}
