// Package api implements the gRPC control API for the scrubber.
package api

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/ebpf-ddos-scrubber/control-plane/internal/bpf"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/config"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/events"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/stats"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Server implements the gRPC ScrubberService.
type Server struct {
	log       *zap.Logger
	cfg       *config.Config
	maps      *bpf.MapManager
	stats     *stats.Collector
	events    *events.Reader
	startTime time.Time

	grpcServer *grpc.Server
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
	}
}

// Start starts the gRPC server on the configured address.
func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.cfg.API.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.API.Listen, err)
	}

	s.grpcServer = grpc.NewServer()
	// Register service implementation
	registerScrubberService(s.grpcServer, s)

	s.log.Info("gRPC API server starting", zap.String("listen", s.cfg.API.Listen))

	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			s.log.Error("gRPC server error", zap.Error(err))
		}
	}()

	return nil
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
		s.log.Info("gRPC API server stopped")
	}
}

// --- Service Implementation ---

// GetStatus returns the current scrubber status.
func (s *Server) GetStatus(ctx context.Context) (*StatusResponse, error) {
	enabled, _ := s.maps.GetConfig(bpf.CfgEnabled)
	return &StatusResponse{
		Enabled:       enabled == 1,
		InterfaceName: s.cfg.Interface,
		XDPMode:       s.cfg.XDPMode,
		UptimeSeconds: uint64(time.Since(s.startTime).Seconds()),
		Version:       "0.1.0",
	}, nil
}

// SetEnabled enables or disables the scrubber.
func (s *Server) SetEnabled(ctx context.Context, enabled bool) error {
	var val uint64
	if enabled {
		val = 1
	}
	if err := s.maps.SetConfig(bpf.CfgEnabled, val); err != nil {
		return err
	}
	s.log.Info("scrubber enabled state changed", zap.Bool("enabled", enabled))
	return nil
}

// GetStats returns the current aggregated statistics.
func (s *Server) GetStats(ctx context.Context) (*StatsResponse, error) {
	snap := s.stats.Current()
	if snap == nil {
		return &StatsResponse{}, nil
	}
	return snapshotToResponse(snap), nil
}

// AddBlacklist adds a CIDR to the blacklist.
func (s *Server) AddBlacklist(ctx context.Context, cidr string, reason uint32) error {
	return s.maps.AddBlacklistCIDR(cidr, reason)
}

// RemoveBlacklist removes a CIDR from the blacklist.
func (s *Server) RemoveBlacklist(ctx context.Context, cidr string) error {
	return s.maps.RemoveBlacklistCIDR(cidr)
}

// AddWhitelist adds a CIDR to the whitelist.
func (s *Server) AddWhitelist(ctx context.Context, cidr string) error {
	return s.maps.AddWhitelistCIDR(cidr)
}

// RemoveWhitelist removes a CIDR from the whitelist.
func (s *Server) RemoveWhitelist(ctx context.Context, cidr string) error {
	return s.maps.RemoveWhitelistCIDR(cidr)
}

// GetRateConfig returns the current rate limit configuration.
func (s *Server) GetRateConfig(ctx context.Context) (*RateConfigResponse, error) {
	synRate, _ := s.maps.GetConfig(bpf.CfgSYNRatePPS)
	udpRate, _ := s.maps.GetConfig(bpf.CfgUDPRatePPS)
	icmpRate, _ := s.maps.GetConfig(bpf.CfgICMPRatePPS)
	globalPPS, _ := s.maps.GetConfig(bpf.CfgGlobalPPSLimit)
	globalBPS, _ := s.maps.GetConfig(bpf.CfgGlobalBPSLimit)

	return &RateConfigResponse{
		SYNRatePPS:    synRate,
		UDPRatePPS:    udpRate,
		ICMPRatePPS:   icmpRate,
		GlobalPPSLimit: globalPPS,
		GlobalBPSLimit: globalBPS,
	}, nil
}

// SetRateConfig updates rate limit configuration in BPF maps.
func (s *Server) SetRateConfig(ctx context.Context, rc *RateConfigResponse) error {
	configs := map[uint32]uint64{
		bpf.CfgSYNRatePPS:     rc.SYNRatePPS,
		bpf.CfgUDPRatePPS:     rc.UDPRatePPS,
		bpf.CfgICMPRatePPS:    rc.ICMPRatePPS,
		bpf.CfgGlobalPPSLimit: rc.GlobalPPSLimit,
		bpf.CfgGlobalBPSLimit: rc.GlobalBPSLimit,
	}

	for key, val := range configs {
		if err := s.maps.SetConfig(key, val); err != nil {
			return fmt.Errorf("setting config key %d: %w", key, err)
		}
	}

	s.log.Info("rate config updated",
		zap.Uint64("syn_pps", rc.SYNRatePPS),
		zap.Uint64("udp_pps", rc.UDPRatePPS),
		zap.Uint64("icmp_pps", rc.ICMPRatePPS),
	)
	return nil
}

// FlushConntrack removes all conntrack entries.
func (s *Server) FlushConntrack(ctx context.Context) (int, error) {
	count, err := s.maps.ConntrackCount()
	if err != nil {
		return 0, err
	}
	if err := s.maps.FlushConntrack(); err != nil {
		return 0, err
	}
	return count, nil
}

// --- Internal types (simplified; real implementation would use protobuf generated code) ---

type StatusResponse struct {
	Enabled       bool
	InterfaceName string
	XDPMode       string
	ProgramID     uint32
	UptimeSeconds uint64
	Version       string
}

type StatsResponse struct {
	Stats  bpf.GlobalStats
	RxPPS  float64
	RxBPS  float64
	TxPPS  float64
	TxBPS  float64
	DropPPS float64
	DropBPS float64
}

type RateConfigResponse struct {
	SYNRatePPS     uint64
	UDPRatePPS     uint64
	ICMPRatePPS    uint64
	GlobalPPSLimit uint64
	GlobalBPSLimit uint64
}

func snapshotToResponse(snap *stats.Snapshot) *StatsResponse {
	return &StatsResponse{
		Stats:   snap.Stats,
		RxPPS:   snap.RxPPS,
		RxBPS:   snap.RxBPS,
		TxPPS:   snap.TxPPS,
		TxBPS:   snap.TxBPS,
		DropPPS: snap.DropPPS,
		DropBPS: snap.DropBPS,
	}
}

// registerScrubberService is a placeholder for protobuf-generated registration.
// In production, run `protoc` to generate Go stubs and register them here.
func registerScrubberService(s *grpc.Server, srv *Server) {
	// TODO: Replace with generated protobuf service registration:
	// pb.RegisterScrubberServiceServer(s, srv)
	_ = s
	_ = srv
}

// portToNetworkOrder converts a host-order port to network byte order.
func portToNetworkOrder(port uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], port)
	return binary.LittleEndian.Uint16(buf[:])
}
