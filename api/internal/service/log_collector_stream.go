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
// stream host is the one listening there; when several share the port, the
// SNI (sni=$ssl_preread_server_name) or the local address (sa=$server_addr)
// picks one. Stream rows skip what is built for HTTP: fail2ban and WAF
// auto-ban never see them, and the traffic statistics read access rows only.
// The host log rules apply; only skip_all and skip_statuses can match a
// session.
//
// A stream row reuses the access columns: the transport goes in
// request_method and request_protocol, $bytes_sent in body_bytes_sent and
// $session_time in request_time. $bytes_received has no column and is not
// kept.

// stream_main is `$remote_addr [$time_local] $protocol $status $bytes_sent
// $bytes_received $session_time "$upstream_addr" "$upstream_bytes_sent"
// "$upstream_bytes_received" "$upstream_connect_time" sp=$server_port
// sa=$server_addr sni=$ssl_preread_server_name`. Lines written before the
// port was added end without those and are stored without a host.
var streamLineRegex = regexp.MustCompile(`^(\S+) \[([^\]]+)\] (TCP|UDP) (\d{3}) (\d+) (\d+) ([0-9.]+) "([^"]*)" "[^"]*" "[^"]*" "[^"]*"(?: sp=(\d{1,5}))?(?: sa=(\S*))?(?: sni=(\S*))?\s*$`)

const streamTimeLayout = "02/Jan/2006:15:04:05 -0700"

// streamRawLogName sits in the access log's directory (/etc/nginx/logs).
const streamRawLogName = "stream_raw.log"

type streamListener struct {
	hostID     string
	name       string
	domains    []string
	listenHost string // "" or "*" for every address
}

// streamSession is what a line says about the listener that took it.
type streamSession struct {
	protocol string
	port     int
	addr     string // $server_addr
	sni      string // $ssl_preread_server_name, empty without ssl_preread
}

func streamListenerKey(protocol string, port int) string {
	return model.NormalizeStreamProtocol(protocol) + ":" + strconv.Itoa(port)
}

// streamListeners maps each stream host's protocol and port to the hosts
// listening there. Several share one when ssl_preread routes them by SNI or
// when they listen on different addresses (CheckStreamListenConflicts).
func streamListeners(hosts []model.ProxyHost) map[string][]streamListener {
	out := make(map[string][]streamListener)
	for _, h := range hosts {
		if !h.IsStream() || h.StreamListenPort <= 0 {
			continue
		}
		key := streamListenerKey(h.StreamProtocol, h.StreamListenPort)
		name := ""
		if len(h.DomainNames) > 0 {
			name = h.DomainNames[0]
		}
		out[key] = append(out[key], streamListener{hostID: h.ID, name: name, domains: h.DomainNames, listenHost: h.StreamListenHost})
	}
	return out
}

// pickStreamListener chooses the host that took a session among those on its
// port: the only one, else the one whose domains hold the SNI, else the one
// listening on the session's address. A session it cannot tell apart is
// stored without a host rather than under a guess.
func pickStreamListener(cands []streamListener, s streamSession) (streamListener, bool) {
	if len(cands) == 1 {
		return cands[0], true
	}
	if s.sni != "" {
		sni := strings.ToLower(s.sni)
		var exact, wild []streamListener
		for _, c := range cands {
			for _, d := range c.domains {
				d = strings.ToLower(d)
				if d == sni {
					exact = append(exact, c)
					break
				}
				if strings.HasPrefix(d, "*.") && strings.HasSuffix(sni, d[1:]) {
					wild = append(wild, c)
					break
				}
			}
		}
		if len(exact) == 1 {
			return exact[0], true
		}
		if len(exact) == 0 && len(wild) == 1 {
			return wild[0], true
		}
	}
	if s.addr != "" {
		var found []streamListener
		for _, c := range cands {
			if c.listenHost == s.addr || strings.Trim(c.listenHost, "[]") == s.addr {
				found = append(found, c)
			}
		}
		if len(found) == 1 {
			return found[0], true
		}
	}
	return streamListener{}, false
}

// parseStreamLog turns one stream_main line into a log row, without the host,
// and the listener it names.
func parseStreamLog(line string) (*model.CreateLogRequest, streamSession, error) {
	m := streamLineRegex.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return nil, streamSession{}, fmt.Errorf("not a stream log line")
	}
	ts, err := time.Parse(streamTimeLayout, m[2])
	if err != nil {
		return nil, streamSession{}, fmt.Errorf("stream log time: %w", err)
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
	upstream := dashEmpty(m[8])
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
	}, streamSession{protocol: m[3], port: port, addr: dashEmpty(m[10]), sni: dashEmpty(m[11])}, nil
}

// dashEmpty undoes nginx's "-" for an empty variable.
func dashEmpty(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

// handleStreamLine stores one stream_raw.log line.
func (c *LogCollector) handleStreamLine(ctx context.Context, line string) {
	logReq, session, err := parseStreamLog(line)
	if err != nil {
		return
	}
	if session.port > 0 {
		if l, ok := c.streamListener(ctx, session); ok {
			logReq.ProxyHostID = l.hostID
			logReq.Host = l.name
		}
	}
	// The host's log rules (#347): skip_all, or a status it skips.
	if c.skipsStorage(logReq) {
		return
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
func (c *LogCollector) streamListener(ctx context.Context, s streamSession) (streamListener, bool) {
	key := streamListenerKey(s.protocol, s.port)
	c.domainCacheMu.RLock()
	cands := c.streamHosts[key]
	stale := time.Since(c.domainCacheTime) > streamListenerRefresh
	c.domainCacheMu.RUnlock()
	if len(cands) > 0 || !stale {
		return pickStreamListener(cands, s)
	}
	c.refreshDomainCache(ctx)
	c.domainCacheMu.RLock()
	cands = c.streamHosts[key]
	c.domainCacheMu.RUnlock()
	return pickStreamListener(cands, s)
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
