## Question 1: High-Performance Concurrency
**Guideline:**
```bash
go run metrics_processor.go
```
**Result:**
- Benchmark results proving performance requirements
- Memory profiling analysis

**Note:** another way to get profiling analysis is use pprof 
```bash
go run metrics_processor.go
```
```go
// Code has this line:
import _ "net/http/pprof"
go func() {log.Println(http.ListenAndServe("localhost:6060", nill))}()
```
```bash
# profile by 
go tool pprof http://localhost:6060/debug/pprof/heap
```
**Benchmark result:**

![img_1.png](img_1.png)

---
## Question 2: Microservices System Design
**System Overview**

**Architecture Diagram**
```text
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │    │   Admin     │    │  External   │
│  (Web/Mob)  │    │  Dashboard  │    │  Services   │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       ▼                  ▼                  ▼
┌───────────────────────────────────────────────────┐
│                 API Gateway                       │
│  - Routing, Auth, Rate Limiting, Request Tracing  │
└──────┬──────────────────┬──────────────────┬──────┘
       │                  │                  │
       ▼                  ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Order      │    │  Payment    │    │  Inventory  │
│  Service    │    │  Service    │    │  Service    │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       ▼                  ▼                  ▼
┌───────────────────────────────────────────────────┐
│               Message Broker (Kafka)              │
│  - Order Events, Payment Events, Inventory Updates│
└──────┬──────────────────┬──────────────────┬──────┘
       │                  │                  │
       ▼                  ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Shipping    │    │ Analytics   │    │ Notification│
│ Service     │    │ Service     │    │ Service     │
└─────────────┘    └─────────────┘    └─────────────┘
```
**Data Flow:**
1. Client -> API gateway -> Order Service (create order)
2. Order Service:
- Publishes "OrderCreated" event
- Synchronously checks inventory (reserves items)
3. Inventory Service process reservation
4. Order Service initiate payment
5. Payment Service process payment (async via queue)
6. On success:
- Order confirmed
- Inventory updated
- Shipiing scheduled
7. On failure at step:
- Compensating transaction executed
- Notification send

**API Specifications:**

Order Service
- POST /orders - create new order
    * Request: {order_id, amount, payment_method}
    * Response: 202 Accepted (async processing)
- GET /payment/{order_id} - check payment status

Payment Service
- POST /payments - process payment
    * Request: {order_id, amount, payment_method}
    * Response: 202 Accepted (async processing)
- GET /payments/{order_id} - check payment status

Inventory Service
- POST /inventory/reserve - reserve items
    * Request: {order_id, items:[{product_id, quantity}]}
    * Response: 200 OK or 409 Conflict (items not enough in stock)
- POST /inventory/release - release reservation
    * Request: {order_id}
    * Response: 200 OK

Shipping Service
- POST /shipping - create shipment
    * Request: {order_id, address, items}
    * Response: 202 Accepted (async processing)

**Database Schema:**

Order Service (PostgreSQL)

Inventory Service (PostgreSQL)

**Failure Handling Strategy:**

Order Service Failures
- Database failure: Retry with exponential backoff
- Inventory check timeout: Mark order as "pending", background job to reconcile
- Compensation failure: Dead letter queue for manual intervention

Payment Service Failures
- External API failure: Retry 3 times with backoff
- Permanent failure: Notify order service to cancel order and release inventory
- Duplicate payments: Idempotency keys in all requests

Inventory Service Failures
- Overselling prevention: Pessimistic locking during reservation
- Reservation expiry: Background job to release expired reservations
- Stock reconciliation: Periodic job to verify physical vs. system stock

Shipping Service Failures
- Carrier API failure: Retry with exponential backoff
- Address validation: Pre-validate during order creation
- Shipping failure: Notify customer service for manual resolution

**Message Queue Kafka:**

Topics:
1. orders - order events
- order.created
- order.payment_processed
- order.completed
- order.cancelled
- order.failed
2. inventory - inventory update
- inventory.reserved
- inventory.released
- inventory.updated
3. payments - payment processing
- payment.initiated
- payment.processed
- payment.failed
4. shipping - shipping event
- shipping.requested
- shipping.progress
- shipping.completed

Consumer groups:
- Order Service: Consumes payment and inventory events
- Payment Service: Consumes order events
- Inventory Service: Consumes order and payment events
- Shipping Service: Consumes order events
- Analytics Service: Consumes all events
- Notification Service: Consumes all events

Go implementation Order service details show on e_commerce_order_system.go
```bash
go run e_commerce_order_system.go 
```

---
## Question 3: Database Performance & Scaling
**Plan:**
1. Optimized Database Schema with Partitioning:
- Table events:

Schema
```sql
CREATE TABLE events (
    tenant_id       BIGINT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    processing_time FLOAT,
    payload         JSONB,
    PRIMARY KEY (tenant_id, created_at)
) PARTITION BY RANGE (created_at);
```
Automation create Index monthly by script/cron + psql.

Index on each partition:
```sql
CREATE INDEX idx_events_tenant_created_at ON events_<yyyymm> (tenant_id, created_at);
```
- Table tenants
```sql
CREATE TABLE tenants (
    id    BIGINT PRIMARY KEY,
    name  TEXT,
    plan  TEXT  -- 'enterprise', 'basic',...
);
```
2. Improved Query (with Index Usage and Planning)
```sql
SELECT 
    e.tenant_id,
    DATE(e.created_at) AS date,
    COUNT(*) AS events,
    AVG(e.processing_time) AS avg_time
FROM events e
JOIN tenants t ON e.tenant_id = t.id
WHERE e.created_at >= CURRENT_DATE - INTERVAL '30 days'
  AND t.plan = 'enterprise'
GROUP BY e.tenant_id, DATE(e.created_at)
ORDER BY date DESC;
```
3. Caching Strategy with Redis
- Cache daily event count per tenant (tenant_id + date) → JSON object.
- TTL: 10 minutes.
- Invalidate if new events arrive (via pub/sub or Redis key expire)
- Redis schema:
```text
Key: stats:{tenant_id}:{YYYY-MM-DD}
Value: {"events": 1234, "avg_time": 0.57}
TTL: 600s
```

All features details show on db_api.go
```bash
go run tenant_analytics.go
````

---
## Question 4: Production Security & Monitoring
**Verify:**
1. Access endpoints not require authenticate:
- by Web browser
```text
http://localhost:8080/health
```
- by curl command line
```bash
# health check
curl - v http://localhost:8080/health

# endpoints for authentication
curl -v -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```
2. API with JWT token
```bash
# 1. Get token
response=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}')
token=$(echo $response | jq -r '.access_token')
# 2. Call API protected with tocken
curl -v -X GET http://localhost:8080/protected \
  -H "Authorization: Bearer $token"
```
3. Rate limiting
```bash
for i in {1..20}; do
  curl -v -X GET http://localhost:8080/protected \
    -H "Authorization: Bearer $token"
  sleep 0.1
done
```
4. Prometheus metris
```bash
curl http://localhost:8080/metrics
```
5. Graceful shutdown
```bash
go run secure_API_Gateway.go
# another terminal
kill -SIGINT $(pgrep -f "secure_API_Gateway.go")
```

---
## Question 5: Practical Implementation

Null

---