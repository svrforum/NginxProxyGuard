package handler

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

type instanceSettingsReader interface {
	Get(ctx context.Context) (*model.SystemSettings, error)
}

type nginxVersionReader interface {
	Version(ctx context.Context) (string, error)
}

// InstanceHandler answers GET /api/v1/instance: what the header shows about
// this NPG to anyone signed in, whatever their role (#369).
type InstanceHandler struct {
	settings instanceSettingsReader
	nginx    nginxVersionReader
}

func NewInstanceHandler(settings *repository.SystemSettingsRepository, nginxManager *nginx.Manager) *InstanceHandler {
	h := &InstanceHandler{}
	if settings != nil {
		h.settings = settings
	}
	if nginxManager != nil {
		h.nginx = nginxManager
	}
	return h
}

// Get returns NPG's version, nginx's version and the instance name. A part
// that cannot be read is left empty rather than failing the header.
func (h *InstanceHandler) Get(c echo.Context) error {
	ctx := c.Request().Context()
	info := model.InstanceInfo{Version: config.AppVersion}
	if h.settings != nil {
		if s, err := h.settings.Get(ctx); err == nil && s != nil {
			info.InstanceName = s.InstanceName
		}
	}
	if h.nginx != nil {
		if v, err := h.nginx.Version(ctx); err == nil {
			info.NginxVersion = v
		}
	}
	return c.JSON(http.StatusOK, info)
}
