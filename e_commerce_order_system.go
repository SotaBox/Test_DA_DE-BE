package main

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"log"
	"net/http"
	"time"
)

type OrderStatus string

const (
	OrderCreated           OrderStatus = "CREATED"
	OrderPaymentProcessing OrderStatus = "PAYMENT_PROCESSING"
	OrderFailed            OrderStatus = "FAILED"
	OrderCancelled         OrderStatus = "CANCELED"
	OrderComplete          OrderStatus = "COMPLETED"
)

type Order struct {
	ID        string      `json:"id"`
	UserID    string      `json:"user_id"`
	ItemID    string      `json:"item_id"`
	Quantity  int         `json:"quantity"`
	Status    OrderStatus `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
}

var kafkaWriter = &kafka.Writer{
	Addr:     kafka.TCP("localhost:9092"),
	Topic:    "order-events",
	Balancer: &kafka.LeastBytes{},
}

func createOrderHandle(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var req Order
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	order := Order{
		ID:        uuid.New().String(),
		UserID:    req.UserID,
		ItemID:    req.ItemID,
		Quantity:  req.Quantity,
		Status:    OrderCreated,
		CreatedAt: time.Now(),
	}

	// Store order with CREATED status
	// db.Insert(order)

	// Publish order to Kafka
	orderBytes, _ := json.Marshal(order)
	if err := kafkaWriter.WriteMessages(ctx, kafka.Message{
		Key:   []byte(order.ID),
		Value: orderBytes,
	}); err != nil {
		log.Printf("Kafka write failed: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(order)
}

func main() {
	http.HandleFunc("/orders", createOrderHandle)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
