// Package events reads events from the BPF ring buffer and dispatches them.
package events

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/bpf"
	"go.uber.org/zap"
)

// Handler is called for each event read from the ring buffer.
type Handler func(event *bpf.Event)

// Reader reads events from the BPF ring buffer.
type Reader struct {
	log       *zap.Logger
	eventsMap *ebpf.Map

	mu       sync.RWMutex
	handlers []Handler
}

// NewReader creates a new event reader for the given events ring buffer map.
func NewReader(log *zap.Logger, eventsMap *ebpf.Map) *Reader {
	return &Reader{
		log:       log,
		eventsMap: eventsMap,
	}
}

// OnEvent registers a handler to receive events.
func (r *Reader) OnEvent(h Handler) {
	r.mu.Lock()
	r.handlers = append(r.handlers, h)
	r.mu.Unlock()
}

// Run starts reading events. Blocks until context is cancelled.
func (r *Reader) Run(ctx context.Context) error {
	rd, err := ringbuf.NewReader(r.eventsMap)
	if err != nil {
		return err
	}
	defer rd.Close()

	r.log.Info("event reader started")

	// Close reader when context is done
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				r.log.Info("event reader stopped")
				return nil
			}
			r.log.Warn("error reading event", zap.Error(err))
			continue
		}

		event, err := parseEvent(record.RawSample)
		if err != nil {
			r.log.Warn("error parsing event", zap.Error(err))
			continue
		}

		r.dispatch(event)
	}
}

func (r *Reader) dispatch(event *bpf.Event) {
	r.mu.RLock()
	handlers := r.handlers
	r.mu.RUnlock()

	for _, h := range handlers {
		h(event)
	}
}

func parseEvent(data []byte) (*bpf.Event, error) {
	if len(data) < 40 { // sizeof(struct event)
		return nil, errors.New("event data too short")
	}

	e := &bpf.Event{
		TimestampNS: binary.LittleEndian.Uint64(data[0:8]),
		SrcIP:       binary.LittleEndian.Uint32(data[8:12]),
		DstIP:       binary.LittleEndian.Uint32(data[12:16]),
		SrcPort:     binary.LittleEndian.Uint16(data[16:18]),
		DstPort:     binary.LittleEndian.Uint16(data[18:20]),
		Protocol:    data[20],
		AttackType:  data[21],
		Action:      data[22],
		DropReason:  data[23],
		PPSEstimate: binary.LittleEndian.Uint64(data[24:32]),
		BPSEstimate: binary.LittleEndian.Uint64(data[32:40]),
	}

	return e, nil
}
