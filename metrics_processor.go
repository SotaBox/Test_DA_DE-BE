package main

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

const NumOfEvents = 100000

type MetricsProcessor struct {
	buckets     []bucket   // fix size buffer (TTL minutes)
	ttl         int        // retention (minutes)
	startTime   int64      // unix minutes
	inputChan   chan Event // buffered input channel
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	workerCount int
}

type Event struct {
	Timestamp time.Time
	UserID    string
	EventType string
	Value     float64
}
type aggregate struct {
	Sum   float64
	Count int
}
type bucket struct {
	sync.Mutex
	Data map[string]*aggregate // eventType -> aggregate
}

func NewMetricsProcessor(ttlMinutes, workerCount int) *MetricsProcessor {
	ctx, cancel := context.WithCancel(context.Background())
	buckets := make([]bucket, ttlMinutes)
	for i := range buckets {
		buckets[i].Data = make(map[string]*aggregate)
	}

	mp := &MetricsProcessor{
		buckets:     buckets,
		ttl:         ttlMinutes,
		startTime:   time.Now().Unix() / 60,
		inputChan:   make(chan Event, 1000000),
		ctx:         ctx,
		cancel:      cancel,
		workerCount: workerCount,
	}
	for i := 0; i < workerCount; i++ {
		mp.wg.Add(1)
		// n worker handle Event
		go mp.worker()
	}
	return mp
}

func (m *MetricsProcessor) bucketIndex(minute int64) int {
	return int(minute % int64(m.ttl))
}

func (m *MetricsProcessor) worker() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			// worker terminated
			return
		case evt := <-m.inputChan:
			// handle Event
			minute := evt.Timestamp.Unix() / 60
			idx := m.bucketIndex(minute)
			bkt := &m.buckets[idx]
			bkt.Lock()

			agg, ok := bkt.Data[evt.EventType]
			if !ok {
				agg = &aggregate{}
				bkt.Data[evt.EventType] = agg
			}
			agg.Sum += evt.Value
			agg.Count++
			bkt.Unlock()
		}
	}
}

func (m *MetricsProcessor) ProcessEvent(event Event) error {
	select {
	case m.inputChan <- event:
		return nil
	default:
		return fmt.Errorf("metrics processor channel full")
	}
}

// GetAggregates returns aggregate metrics over the last N minutes
func (m *MetricsProcessor) GetAggregates(minutes int) (map[string]float64, error) {
	if minutes < 0 || minutes > m.ttl {
		return nil, fmt.Errorf("requires minutes exceed retention")
	}
	now := time.Now().Unix() / 60
	res := make(map[string]float64)
	for i := 0; i < minutes; i++ {
		minute := now - int64(i)
		idx := m.bucketIndex(minute)
		bkt := &m.buckets[idx]
		bkt.Lock()
		for evt, agg := range bkt.Data {
			res[evt] += agg.Sum
		}
		bkt.Unlock()
	}
	return res, nil
}

// Stop ensures graceful shutdown within timeout
func (m *MetricsProcessor) Stop(timeout time.Duration) error {
	m.cancel()

	c := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(c)
	}()
	select {
	case <-c:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("graceful shutdown timeout")
	}
}

func printMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Memory Usage = %.5f MB\n", float64(m.Alloc)/1024/1024)
}

func main() {
	printMemUsage()
	mp := NewMetricsProcessor(10, 8)
	start := time.Now()
	for i := 0; i < NumOfEvents; i++ {
		mp.ProcessEvent(Event{
			Timestamp: time.Now(),
			UserID:    fmt.Sprintf("%d", i),
			EventType: "click",
			Value:     1.0,
		})
	}
	elapsed := time.Since(start)
	fmt.Printf("Handle 100K events in %v\n", elapsed)
	time.Sleep(1 * time.Second)
	res, _ := mp.GetAggregates(2)
	fmt.Printf("Aggregated: %v\n", res)

	err := mp.Stop(5 * time.Second)
	printMemUsage()
	if err != nil {
		fmt.Println("Shutdown error:", err)
	}
}
