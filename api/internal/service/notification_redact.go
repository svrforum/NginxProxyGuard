package service

import (
	"strings"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/redact"
)

// redactDeliveryError takes a channel's credentials out of a delivery error
// before anything stores, logs or returns it.
//
// The credentials are what the API never reads back (handler.secretKeysFor):
// a Discord or generic webhook URL, which is the credential as a whole, the
// Telegram bot token, which sits in the request path, and every header_* value.
// net/http renders a failed request as `Post "<full URL>": <cause>`, and that
// text was stored in notification_channels.last_error and
// notification_outbox.last_error, returned by the Test button and written to
// the container log. Whatever URL net/http quotes keeps its scheme and host, so
// the operator can still tell which receiver failed, and the cause is kept — save
// the first label of a host name with nothing after it, which redact.URL treats
// as the credential.
func redactDeliveryError(ch *model.NotificationChannel, err error) error {
	if err == nil {
		return nil
	}
	secrets := &redact.Secrets{}
	if ch != nil {
		secrets.AddURL(ch.Config["url"])
		secrets.Add(ch.Config["bot_token"])
		for key, value := range ch.Config {
			if strings.HasPrefix(key, "header_") {
				secrets.Add(value)
			}
		}
	}
	return secrets.RequestError(err)
}
