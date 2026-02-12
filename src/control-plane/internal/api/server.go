// Package api implements the HTTP REST + WebSocket control API for the scrubber.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ebpf-ddos-scrubber/control-plane/internal/bpf"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/config"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/events"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/stats"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// Server implements the HTTP REST + WebSocket API.
type Server struct {
	log       *zap.Logger
	cfg       *config.Config
	maps      *bpf.MapManager
	stats     *stats.Collector
	events    *events.Reader
	startTime time.Time

	httpServer *http.Server

	// WebSocket clients
	wsMu    sync.RWMutex
	wsConns map[*websocket.Conn]struct{}

	upgrader websocket.Upgrader
}

// NewServer creates a new API server.
func NewServer(
	log *zap.Logger,
	cfg *config.Config,
	maps *bpf.MapManager,
	statsCollector *stats.Collector,
	eventReader *events.Reader,
) *Server {
	return &Server{
		log:       log,
		cfg:       cfg,
		maps:      maps,
		stats:     statsCollector,
		events:    eventReader,
		startTime: time.Now(),
		wsConns:   make(map[*websocket.Conn]struct{}),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// Start starts the HTTP server and WebSocket broadcast loops.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// REST endpoints
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/status/enabled", s.handleSetEnabled)
	mux.HandleFunc("/api/v1/stats", s.handleStats)
	mux.HandleFunc("/api/v1/acl/blacklist", s.handleBlacklist)
	mux.HandleFunc("/api/v1/acl/whitelist", s.handleWhitelist)
	mux.HandleFunc("/api/v1/config/rate", s.handleRateConfig)
	mux.HandleFunc("/api/v1/conntrack", s.handleConntrack)
	mux.HandleFunc("/api/v1/conntrack/flush", s.handleConntrackFlush)
	mux.HandleFunc("/api/v1/signatures", s.handleSignatures)

	// WebSocket
	mux.HandleFunc("/ws/realtime", s.handleWS)

	s.httpServer = &http.Server{
		Handler: corsMiddleware(mux),
	}

	lis, err := net.Listen("tcp", s.cfg.API.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.API.Listen, err)
	}

	s.log.Info("HTTP API server starting", zap.String("listen", s.cfg.API.Listen))

	go func() {
		if err := s.httpServer.Serve(lis); err != nil && err != http.ErrServerClosed {
			s.log.Error("HTTP server error", zap.Error(err))
		}
	}()

	// Start WebSocket stats broadcast
	go s.broadcastStats()

	return nil
}

// Stop gracefully stops the HTTP server.
func (s *Server) Stop() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
		s.log.Info("HTTP API server stopped")
	}
	s.wsMu.Lock()
	for c := range s.wsConns {
		c.Close()
	}
	s.wsMu.Unlock()
}

// BroadcastEvent sends a BPF event to all connected WebSocket clients.
func (s *Server) BroadcastEvent(ev *bpf.Event) {
	msg := wsMessage{
		Type: "event",
		Data: eventToJSON(ev),
	}
	s.broadcast(msg)
}

// --- WebSocket ---

type wsMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Warn("websocket upgrade failed", zap.Error(err))
		return
	}

	s.wsMu.Lock()
	s.wsConns[conn] = struct{}{}
	s.wsMu.Unlock()

	s.log.Debug("websocket client connected", zap.String("remote", conn.RemoteAddr().String()))

	// Read loop (just drain; client doesn't send meaningful data)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}

	s.wsMu.Lock()
	delete(s.wsConns, conn)
	s.wsMu.Unlock()
	conn.Close()

	s.log.Debug("websocket client disconnected", zap.String("remote", conn.RemoteAddr().String()))
}

func (s *Server) broadcast(msg wsMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	s.wsMu.RLock()
	defer s.wsMu.RUnlock()

	for c := range s.wsConns {
		if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
			c.Close()
			go func(conn *websocket.Conn) {
				s.wsMu.Lock()
				delete(s.wsConns, conn)
				s.wsMu.Unlock()
			}(c)
		}
	}
}

func (s *Server) broadcastStats() {
	ch := s.stats.Subscribe(4)
	for snap := range ch {
		msg := wsMessage{
			Type: "stats",
			Data: snapshotToJSON(snap),
		}
		s.broadcast(msg)
	}
}

// --- REST Handlers ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enabled, _ := s.maps.GetConfig(bpf.CfgEnabled)
	escLevel, _ := s.maps.GetConfig(bpf.CfgEscalationLevel)

	resp := map[string]interface{}{
		"enabled":       enabled == 1,
		"interfaceName": s.cfg.Interface,
		"xdpMode":       s.cfg.XDPMode,
		"programId":     0,
		"uptimeSeconds": int64(time.Since(s.startTime).Seconds()),
		"version":       "0.1.0",
		"escalationLevel": escLevel,
		"pipelineStages":  18,
	}
	writeJSON(w, resp)
}

func (s *Server) handleSetEnabled(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	var val uint64
	if req.Enabled {
		val = 1
	}
	if err := s.maps.SetConfig(bpf.CfgEnabled, val); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("scrubber enabled state changed", zap.Bool("enabled", req.Enabled))
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snap := s.stats.Current()
	if snap == nil {
		writeJSON(w, map[string]interface{}{})
		return
	}
	writeJSON(w, snapshotToJSON(snap))
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Return empty list (BPF LPM trie iteration not trivially supported)
		writeJSON(w, []interface{}{})

	case http.MethodPost:
		var req struct {
			CIDR   string `json:"cidr"`
			Reason uint32 `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Reason == 0 {
			req.Reason = bpf.DropBlacklist
		}
		if err := s.maps.AddBlacklistCIDR(req.CIDR, req.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.log.Info("blacklist entry added via API", zap.String("cidr", req.CIDR))
		writeJSON(w, map[string]bool{"ok": true})

	case http.MethodDelete:
		var req struct {
			CIDR string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := s.maps.RemoveBlacklistCIDR(req.CIDR); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.log.Info("blacklist entry removed via API", zap.String("cidr", req.CIDR))
		writeJSON(w, map[string]bool{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, []interface{}{})

	case http.MethodPost:
		var req struct {
			CIDR string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := s.maps.AddWhitelistCIDR(req.CIDR); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.log.Info("whitelist entry added via API", zap.String("cidr", req.CIDR))
		writeJSON(w, map[string]bool{"ok": true})

	case http.MethodDelete:
		var req struct {
			CIDR string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := s.maps.RemoveWhitelistCIDR(req.CIDR); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.log.Info("whitelist entry removed via API", zap.String("cidr", req.CIDR))
		writeJSON(w, map[string]bool{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRateConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		synRate, _ := s.maps.GetConfig(bpf.CfgSYNRatePPS)
		udpRate, _ := s.maps.GetConfig(bpf.CfgUDPRatePPS)
		icmpRate, _ := s.maps.GetConfig(bpf.CfgICMPRatePPS)
		globalPPS, _ := s.maps.GetConfig(bpf.CfgGlobalPPSLimit)
		globalBPS, _ := s.maps.GetConfig(bpf.CfgGlobalBPSLimit)
		adaptive, _ := s.maps.GetConfig(bpf.CfgAdaptiveRate)

		writeJSON(w, map[string]interface{}{
			"synRatePps":      synRate,
			"udpRatePps":      udpRate,
			"icmpRatePps":     icmpRate,
			"globalPpsLimit":  globalPPS,
			"globalBpsLimit":  globalBPS,
			"adaptiveEnabled": adaptive == 1,
		})

	case http.MethodPut:
		var req struct {
			SYNRatePPS    uint64 `json:"synRatePps"`
			UDPRatePPS    uint64 `json:"udpRatePps"`
			ICMPRatePPS   uint64 `json:"icmpRatePps"`
			GlobalPPS     uint64 `json:"globalPpsLimit"`
			GlobalBPS     uint64 `json:"globalBpsLimit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		configs := map[uint32]uint64{
			bpf.CfgSYNRatePPS:     req.SYNRatePPS,
			bpf.CfgUDPRatePPS:     req.UDPRatePPS,
			bpf.CfgICMPRatePPS:    req.ICMPRatePPS,
			bpf.CfgGlobalPPSLimit: req.GlobalPPS,
			bpf.CfgGlobalBPSLimit: req.GlobalBPS,
		}
		for key, val := range configs {
			if err := s.maps.SetConfig(key, val); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		s.log.Info("rate config updated via API")
		writeJSON(w, map[string]bool{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleConntrack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctEnabled, _ := s.maps.GetConfig(bpf.CfgConntrackEnable)
	count, _ := s.maps.ConntrackCount()
	writeJSON(w, map[string]interface{}{
		"activeConnections": count,
		"enabled":           ctEnabled == 1,
	})
}

func (s *Server) handleConntrackFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	count, _ := s.maps.ConntrackCount()
	if err := s.maps.FlushConntrack(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"entriesRemoved": count})
}

func (s *Server) handleSignatures(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Index       uint32 `json:"index"`
			Protocol    uint8  `json:"protocol"`
			FlagsMask   uint8  `json:"flagsMask"`
			FlagsMatch  uint8  `json:"flagsMatch"`
			SrcPortMin  uint16 `json:"srcPortMin"`
			SrcPortMax  uint16 `json:"srcPortMax"`
			DstPortMin  uint16 `json:"dstPortMin"`
			DstPortMax  uint16 `json:"dstPortMax"`
			PktLenMin   uint16 `json:"pktLenMin"`
			PktLenMax   uint16 `json:"pktLenMax"`
			PayloadHash uint32 `json:"payloadHash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		sig := bpf.AttackSig{
			Protocol:    req.Protocol,
			FlagsMask:   req.FlagsMask,
			FlagsMatch:  req.FlagsMatch,
			SrcPortMin:  req.SrcPortMin,
			SrcPortMax:  req.SrcPortMax,
			DstPortMin:  req.DstPortMin,
			DstPortMax:  req.DstPortMax,
			PktLenMin:   req.PktLenMin,
			PktLenMax:   req.PktLenMax,
			PayloadHash: req.PayloadHash,
		}
		if err := s.maps.SetAttackSignature(req.Index, sig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case http.MethodDelete:
		// Clear all signatures by setting count to 0
		if err := s.maps.SetAttackSignatureCount(0); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func snapshotToJSON(snap *stats.Snapshot) map[string]interface{} {
	st := snap.Stats
	return map[string]interface{}{
		"timestampNs":           time.Now().UnixNano(),
		"rxPackets":             st.RxPackets,
		"rxBytes":               st.RxBytes,
		"txPackets":             st.TxPackets,
		"txBytes":               st.TxBytes,
		"droppedPackets":        st.DroppedPackets,
		"droppedBytes":          st.DroppedBytes,
		"synFloodDropped":       st.SYNFloodDropped,
		"udpFloodDropped":       st.UDPFloodDropped,
		"icmpFloodDropped":      st.ICMPFloodDropped,
		"ackFloodDropped":       st.ACKFloodDropped,
		"dnsAmpDropped":         st.DNSAmpDropped,
		"ntpAmpDropped":         st.NTPAmpDropped,
		"fragmentDropped":       st.FragmentDropped,
		"aclDropped":            st.ACLDropped,
		"rateLimited":           st.RateLimited,
		"conntrackNew":          st.ConntrackNew,
		"conntrackEstablished":  st.ConntrackEstablished,
		"synCookiesSent":        st.SYNCookiesSent,
		"synCookiesValidated":   st.SYNCookiesValidated,
		"synCookiesFailed":      st.SYNCookiesFailed,
		"geoipDropped":          st.GeoIPDropped,
		"reputationDropped":     st.ReputationDropped,
		"protoViolationDropped": st.ProtoViolationDropped,
		"payloadMatchDropped":   st.PayloadMatchDropped,
		"tcpStateDropped":       st.TCPStateDropped,
		"ssdpAmpDropped":        st.SSDPAmpDropped,
		"memcachedAmpDropped":   st.MemcachedAmpDropped,
		"threatIntelDropped":    st.ThreatIntelDropped,
		"reputationAutoBlocked": st.ReputationAutoBlocked,
		"dnsQueriesValidated":   st.DNSQueriesValidated,
		"dnsQueriesBlocked":     st.DNSQueriesBlocked,
		"ntpMonlistBlocked":     st.NTPMonlistBlocked,
		"tcpStateViolations":    st.TCPStateViolations,
		"portScanDetected":      st.PortScanDetected,
		// Rates
		"rxPps":   snap.RxPPS,
		"rxBps":   snap.RxBPS,
		"txPps":   snap.TxPPS,
		"txBps":   snap.TxBPS,
		"dropPps": snap.DropPPS,
		"dropBps": snap.DropBPS,
	}
}

func eventToJSON(ev *bpf.Event) map[string]interface{} {
	return map[string]interface{}{
		"timestampNs":     ev.TimestampNS,
		"srcIp":           bpf.U32BEToIP(ev.SrcIP).String(),
		"dstIp":           bpf.U32BEToIP(ev.DstIP).String(),
		"srcPort":         ntohs(ev.SrcPort),
		"dstPort":         ntohs(ev.DstPort),
		"protocol":        ev.Protocol,
		"attackType":      bpf.AttackTypeName(ev.AttackType),
		"action":          actionName(ev.Action),
		"dropReason":      bpf.DropReasonName(ev.DropReason),
		"ppsEstimate":     ev.PPSEstimate,
		"bpsEstimate":     ev.BPSEstimate,
		"reputationScore": ev.ReputationScore,
		"countryCode":     countryCodeStr(ev.CountryCode),
		"escalationLevel": ev.EscalationLevel,
	}
}

func actionName(a uint8) string {
	if a == 1 {
		return "drop"
	}
	return "pass"
}

func ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func countryCodeStr(code uint16) string {
	if code == 0 {
		return ""
	}
	return string([]byte{byte(code >> 8), byte(code & 0xFF)})
}
