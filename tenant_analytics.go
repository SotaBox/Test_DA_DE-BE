package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net/http"
	"os"
	"time"
)

type EventStats struct {
	TenantID int64   `json:"tenant_id"`
	Date     string  `json:"date"`
	Events   int64   `json:"events"`
	AvgTime  float64 `json:"avg_time"`
}

var (
	dbpool      *pgxpool.Pool
	redisClient *redis.Client
	ctx         = context.Background()
)

func main() {
	initDB()
	initRedis()
	http.HandleFunc("/stats", statsHandler)
	log.Println("Listening on :8080")
	http.ListenAndServe(":8080", nil)
}

func initDB() {
	// "postgres://user:password@host:5432/dbname"
	url := os.Getenv("DATABASE_URL")
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		log.Fatalf("failed to parse connection string: %w", err)
	}
	// Tuning connection pool
	config.MaxConns = 50
	config.MinConns = 10
	config.MaxConnIdleTime = 5 * time.Minute
	config.MaxConnLifetime = 1 * time.Hour
	config.HealthCheckPeriod = 1 * time.Minute

	// Timeouts
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	config.ConnConfig.RuntimeParams["statement_timeout"] = "30000" // seconds

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	dbpool = pool
}

func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	date := r.URL.Query().Get("date")
	if tenantID == "" || date == "" {
		http.Error(w, "Missing tenant_id or date", http.StatusBadRequest)
		return
	}

	key := fmt.Sprintf("stats:%s:%s", tenantID, date)
	val, err := redisClient.Get(ctx, key).Result()
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(val))
		return
	}

	query := `
		SELECT tenant_id, DATE(created_at), COUNT(*), AVG(processing_time)
		FROM events e
		JOIN tenants t ON e.tenant_id = t.id
		WHERE DATE(e.created_at) = $1 AND t.plan = 'enterprise' AND e.tenant_id = $2
		GROUP BY tenant_id, DATE(e.created_at)`

	row := dbpool.QueryRow(ctx, query, date, tenantID)
	var stats EventStats
	if err := row.Scan(&stats.TenantID, &stats.Date, &stats.Events, &stats.AvgTime); err != nil {
		http.Error(w, "No data found", http.StatusNotFound)
		return
	}

	jsonData, _ := json.Marshal(stats)
	redisClient.Set(ctx, key, jsonData, 10*time.Minute)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
