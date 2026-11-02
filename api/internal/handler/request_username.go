package handler

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"
)

// requestUsernameKey carries the caller's username on the request context.
type requestUsernameKey struct{}

// WithUsername wraps a net/http handler the way echo.WrapHandler does and also
// puts the authenticated username (a session's or an API token's) on the
// request context. A wrapped handler sees only the request, while the auth
// middleware keeps the caller on the echo context, so without this the
// exploit rule exclusions always stored an empty disabled_by.
func WithUsername(h http.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := c.Request()
		if name, ok := c.Get("username").(string); ok && name != "" {
			r = r.WithContext(context.WithValue(r.Context(), requestUsernameKey{}, name))
		}
		h(c.Response(), r)
		return nil
	}
}

// requestUsername returns the username WithUsername put on the context, or "".
func requestUsername(ctx context.Context) string {
	name, _ := ctx.Value(requestUsernameKey{}).(string)
	return name
}
