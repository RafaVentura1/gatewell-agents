package main

import (
	"sync"
	"time"
)

// EventBuffer holds security events until they can be flushed. Each entry
// carries a unique event_id so a retried flush is deduped server side. When the
// cap is reached the oldest entries are dropped, which bounds memory while the
// platform is unreachable.
type EventBuffer struct {
	mu      sync.Mutex
	items   []map[string]any
	dropped int
	log     *Logger
}

func NewEventBuffer(log *Logger) *EventBuffer {
	return &EventBuffer{log: log}
}

func (b *EventBuffer) Add(eventType, severity, description string) {
	id, err := newUUID()
	if err != nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for len(b.items) >= eventBufferCapacity {
		b.items = b.items[1:]
		b.dropped++
	}

	b.items = append(b.items, map[string]any{
		"event_id":    id,
		"event_type":  eventType,
		"severity":    severity,
		"description": description,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (b *EventBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

// TakeBatch removes up to maxEventsPerBatch entries for sending.
func (b *EventBuffer) TakeBatch() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(b.items)
	if n > maxEventsPerBatch {
		n = maxEventsPerBatch
	}
	batch := make([]map[string]any, n)
	copy(batch, b.items[:n])
	b.items = b.items[n:]
	return batch
}

// Requeue puts an unsent batch back at the head for the next flush.
func (b *EventBuffer) Requeue(batch []map[string]any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(batch, b.items...)
}

func (b *EventBuffer) LogDropStats() {
	b.mu.Lock()
	n := b.dropped
	b.dropped = 0
	b.mu.Unlock()

	if n > 0 {
		b.log.Warnf("Dropped %d buffered events (buffer at capacity).", n)
	}
}

// ---------------------------------------------------------------------------

// TelemetryBuffer keeps EDR telemetry partitioned by telemetry_type, since the
// platform accepts one type per batch.
type TelemetryBuffer struct {
	mu    sync.Mutex
	byKey map[string][]map[string]any
}

func NewTelemetryBuffer() *TelemetryBuffer {
	return &TelemetryBuffer{byKey: make(map[string][]map[string]any)}
}

func (t *TelemetryBuffer) Add(telemetryType string, event map[string]any) {
	t.mu.Lock()
	defer t.mu.Unlock()

	items := t.byKey[telemetryType]
	for len(items) >= telemetryBufferCapacity {
		items = items[1:]
	}
	t.byKey[telemetryType] = append(items, event)
}

// PendingTypes returns the telemetry types that currently have events queued.
func (t *TelemetryBuffer) PendingTypes() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	types := make([]string, 0, len(t.byKey))
	for k, v := range t.byKey {
		if len(v) > 0 {
			types = append(types, k)
		}
	}
	return types
}

// TakeBatch removes up to maxTelemetryPerBatch events of one type.
func (t *TelemetryBuffer) TakeBatch(telemetryType string) []map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()

	items := t.byKey[telemetryType]
	n := len(items)
	if n > maxTelemetryPerBatch {
		n = maxTelemetryPerBatch
	}
	batch := make([]map[string]any, n)
	copy(batch, items[:n])
	t.byKey[telemetryType] = items[n:]
	return batch
}

func (t *TelemetryBuffer) Requeue(telemetryType string, batch []map[string]any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.byKey[telemetryType] = append(batch, t.byKey[telemetryType]...)
}
