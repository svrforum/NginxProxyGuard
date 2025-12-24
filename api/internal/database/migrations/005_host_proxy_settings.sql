-- Add host-level proxy settings columns to proxy_hosts
-- These allow per-host override of global proxy settings

ALTER TABLE proxy_hosts
ADD COLUMN IF NOT EXISTS proxy_connect_timeout INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS proxy_send_timeout INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS proxy_read_timeout INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS proxy_buffering VARCHAR(10) DEFAULT '',
ADD COLUMN IF NOT EXISTS client_max_body_size VARCHAR(20) DEFAULT '';

COMMENT ON COLUMN proxy_hosts.proxy_connect_timeout IS 'Host-level proxy connect timeout in seconds (0 = use global)';
COMMENT ON COLUMN proxy_hosts.proxy_send_timeout IS 'Host-level proxy send timeout in seconds (0 = use global)';
COMMENT ON COLUMN proxy_hosts.proxy_read_timeout IS 'Host-level proxy read timeout in seconds (0 = use global)';
COMMENT ON COLUMN proxy_hosts.proxy_buffering IS 'Host-level proxy buffering (on/off, empty = use global)';
COMMENT ON COLUMN proxy_hosts.client_max_body_size IS 'Host-level client max body size (e.g. 100m, empty = use global)';
