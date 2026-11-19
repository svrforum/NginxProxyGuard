package service

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Stream host connections (#392). nginx writes one stream_main line per TCP or
// UDP session of a stream host to stream_raw.log, next to access_raw.log, and
// the collector stores each as a log_type "stream" row. The line names the
// listener that took the session (sp=$server_port and $protocol), and the
// stream host is the one listening there. Stream rows skip everything built
// for HTTP: fail2ban, WAF auto-ban and the host log rules never see them, and
// the traffic statistics read access rows only.
//
// A stream row reuses the access columns: the transport goes in
// request_method and request_protocol, $bytes_sent in body_bytes_sent and
// $session_time in request_time. $bytes_received has no column and is not
// kept.

// stream_main is `$remote_addr [$time_local] $protocol $status $bytes_sent
// $bytes_received $session_time "$upstream_addr" "$upstream_bytes_sent"
// "$upstream_bytes_received" "$upstream_connect_time" sp=$server_port`. Lines
// written before the port was added end without it and are stored without a
// host.
var streamLineRegex = regexp.MustCompile(`^(\S+) \[([^\]]+)\] (TCP|UDP) (\d{3}) (\d+) (\d+) ([0-9.]+) "([^"]*)" "[^"]*" "[^"]*" "[^"]*"(?: sp=(\d{1,5}))?\s*$`)

const streamTimeLayout = "02/Jan/2006:15:04:05 -0700"

// streamRawLogName sits in the access log's directory (/etc/nginx/logs).
const streamRawLogName = "stream_raw.log"

type streamListener struct {
	hostID string
	name   string
}

func streamListenerKey(protocol string, port int) string {
	return model.NormalizeStreamProtocol(protocol) + ":" + strconv.Itoa(port)
}

// streamListeners maps each stream host's protocol and port to the host. Two
// hosts can only share both when they listen on different addresses, which
// the line does not carry; the first one keeps the key.
func streamListeners(hosts []model.ProxyHost) map[string]streamListener {
	out := make(map[string]streamListener)
	for _, h := range hosts {
		if !h.IsStream() || h.StreamListenPort <= 0 {
			continue
		}
		key := streamListenerKey(h.StreamProtocol, h.StreamListenPort)
		if _, taken := out[key]; taken {
			continue
		}
		name := ""
		if len(h.DomainNames) > 0 {
			name = h.DomainNames[0]
		}
		out[key] = streamListener{hostID: h.ID, name: name}
	}
	return out
}

// parseStreamLog turns one stream_main line into a log row, without the host.
func parseStreamLog(line string) (*model.CreateLogRequest, int, error) {
	m := streamLineRegex.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return nil, 0, fmt.Errorf("not a stream log line")
	}
	ts, err := time.Parse(streamTimeLayout, m[2])
	if err != nil {
		return nil, 0, fmt.Errorf("stream log time: %w", err)
	}
	status, _ := strconv.Atoi(m[4])
	sent, _ := strconv.ParseInt(m[5], 10, 64)
	session, _ := strconv.ParseFloat(m[7], 64)
	port := 0
	if m[9] != "" {
		if p, err := strconv.Atoi(m[9]); err == nil && p <= 65535 {
			port = p
		}
	}
	upstream := m[8]
	if upstream == "-" {
		upstream = ""
	}
	return &model.CreateLogRequest{
		LogType:         model.LogTypeStream,
		Timestamp:       ts,
		ClientIP:        m[1],
		RequestMethod:   m[3],
		RequestProtocol: m[3],
		StatusCode:      status,
		BodyBytesSent:   sent,
		RequestTime:     session,
		UpstreamAddr:    upstream,
		ServerPort:      port,
	}, port, nil
}

// handleStreamLine stores one stream_raw.log line.
func (c *LogCollector) handleStreamLine(ctx context.Context, line string) {
	logReq, port, err := parseStreamLog(line)
	if err != nil {
		return
	}
	if port > 0 {
		if l, ok := c.streamListener(ctx, logReq.RequestProtocol, port); ok {
			logReq.ProxyHostID = l.hostID
			logReq.Host = l.name
		}
	}
	c.addLog(*logReq)
}

// streamListenerRefresh is how old the host cache may be before a listener it
// does not know refreshes it. Shorter than the minute HTTP hosts wait: a
// stream host sees few sessions, so the first ones after it is created would
// otherwise all be stored without it.
const streamListenerRefresh = 10 * time.Second

// streamListener finds the stream host behind a listener, refreshing the
// host cache once when it misses and the cache is older than
// streamListenerRefresh.
func (c *LogCollector) streamListener(ctx context.Context, protocol string, port int) (streamListener, bool) {
	key := streamListenerKey(protocol, port)
	c.domainCacheMu.RLock()
	l, ok := c.streamHosts[key]
	stale := time.Since(c.domainCacheTime) > streamListenerRefresh
	c.domainCacheMu.RUnlock()
	if ok || !stale {
		return l, ok
	}
	c.refreshDomainCache(ctx)
	c.domainCacheMu.RLock()
	l, ok = c.streamHosts[key]
	c.domainCacheMu.RUnlock()
	return l, ok
}

// streamFileStreamLogs tails stream_raw.log the way streamFileAccessLogs
// tails the access log; fileTail follows it across logrotate. The file only
// appears once nginx loads a stream host, so a missing one is retried
// quietly.
func (c *LogCollector) streamFileStreamLogs(ctx context.Context) {
	if c.accessLogPath == "" {
		return
	}
	path := filepath.Join(filepath.Dir(canonicalAccessLogPath), streamRawLogName)
	tail := newFileTail(path, time.Now)
	logged := false
	for {
		// Lines already there at start-up were read by the previous run; a
		// file that shows up later is new, so it is read from the start.
		err := tail.open(!logged)
		if err == nil {
			break
		}
		if !logged {
			log.Printf("[LogCollector] stream log %s not readable yet (%v); retrying every 30s", path, err)
			logged = true
		}
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-time.After(30 * time.Second):
		}
	}
	defer tail.close()
	log.Printf("[LogCollector] starting file-tail of %s", path)

	emit := func(line string) { c.handleStreamLine(ctx, line) }
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}
		if !tail.poll(emit) {
			time.Sleep(500 * time.Millisecond)
		}
	}
}
