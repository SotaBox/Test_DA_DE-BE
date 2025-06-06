# Senior Golang Backend Developer Assessment

**Duration:** 120 minutes 
**Target:** 4+ years Go experience  
**Format:** 4 technical questions + 1 practical coding challenge

---------------------------

## Question 1: High-Performance Concurrency (25 points)

**Scenario:** Build a real-time metrics aggregation service that processes 100K events/second.

**Requirements:**
```go
type MetricsProcessor struct {
    // Your implementation
}

type Event struct {
    Timestamp time.Time `json:"timestamp"`
    UserID    string    `json:"user_id"`
    EventType string    `json:"event_type"`
    Value     float64   `json:"value"`
}

// Must process 100K events/second with <1ms latency
func (m *MetricsProcessor) ProcessEvent(event Event) error

// Return aggregated metrics for last N minutes
func (m *MetricsProcessor) GetAggregates(minutes int) (map[string]float64, error)
```

**Specific Requirements:**
- Handle 100,000 events per second
- Memory usage under 1GB
- Sub-millisecond processing latency (99th percentile)
- Thread-safe concurrent access
- Graceful shutdown within 5 seconds

**Deliverables:**
1. Complete working implementation
2. Benchmark results proving performance requirements
3. Memory profiling analysis
4. Explanation of concurrency patterns used

---

## Question 2: Microservices System Design (30 points)

**Design a distributed e-commerce order system** handling 50K orders/day with these services:

- **Order Service**: Manages order lifecycle
- **Payment Service**: Processes payments (external API calls)
- **Inventory Service**: Manages stock levels
- **Shipping Service**: Handles delivery logistics

**Critical Requirements:**
- **Consistency**: Prevent overselling inventory
- **Reliability**: Handle payment service failures gracefully
- **Performance**: Order creation under 200ms
- **Scalability**: Support 10x traffic growth
- **Recovery**: Rollback failed orders completely

**Deliverables:**
1. **System Architecture Diagram** with data flow
2. **API Specifications** for each service (key endpoints only)
3. **Database Schema** with relationships and indexes
4. **Failure Handling Strategy** for each component failure
5. **Go Implementation** of Order Service with key business logic
6. **Message Queue Design** for async communication

---

## Question 3: Database Performance & Scaling (20 points)

**Scenario:** Optimize a PostgreSQL-based analytics system for a SaaS platform.

**Current Problems:**
```sql
-- This query takes 30+ seconds with 100M records
SELECT 
    tenant_id,
    DATE(created_at) as date,
    COUNT(*) as events,
    AVG(processing_time) as avg_time
FROM events 
WHERE created_at >= '2024-01-01' 
    AND tenant_id IN (SELECT id FROM tenants WHERE plan = 'enterprise')
GROUP BY tenant_id, DATE(created_at)
ORDER BY date DESC;
```

**Requirements:**
- Optimize query to run under 1 second
- Support 1000+ tenants with 100M+ events each
- Handle 50K writes/second during peak hours
- Implement efficient data archival (>2 years old data)

**Deliverables:**
1. **Optimized database schema** with partitioning strategy
2. **Improved queries** with execution plans
3. **Go repository implementation** with connection pooling
4. **Caching strategy** using Redis
5. **Data archival process** with cold storage integration

---

## Question 4: Production Security & Monitoring (15 points)

**Implement a secure API gateway** with comprehensive observability:

**Security Requirements:**
```go
type Gateway struct {
    // Your secure implementation
}

// Must include: JWT validation, rate limiting, audit logging
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

**Specific Features:**
- **Authentication**: JWT with refresh token rotation
- **Authorization**: Role-based access control (RBAC)
- **Rate Limiting**: 1000 req/min per user, 10K req/min per API key
- **Monitoring**: Request metrics, error rates, latency tracking
- **Security**: Input validation, CORS, audit logging

**Deliverables:**
1. **Complete middleware implementation**
2. **Prometheus metrics integration**
3. **Security configuration** (CORS, headers, validation)
4. **Audit logging system** for compliance
5. **Health check and graceful shutdown**

---

## Question 5: Practical Implementation (30 points)

**Build a real-time notification system** with WebSocket support:

### Core Requirements:
```go
type NotificationServer interface {
    // WebSocket endpoint for client connections
    HandleWebSocket(w http.ResponseWriter, r *http.Request)
    
    // Send notification to specific users
    SendToUsers(userIDs []string, notification Notification) error
    
    // Broadcast to all users in a group
    BroadcastToGroup(groupID string, notification Notification) error
    
    // Get user's notification history
    GetHistory(userID string, limit int) ([]Notification, error)
}

type Notification struct {
    ID        string                 `json:"id"`
    Type      string                 `json:"type"`
    Title     string                 `json:"title"`
    Message   string                 `json:"message"`
    Data      map[string]interface{} `json:"data,omitempty"`
    Timestamp time.Time              `json:"timestamp"`
}
```

### Technical Specifications:
- **Concurrency**: Support 5,000+ simultaneous WebSocket connections
- **Persistence**: Store notifications in PostgreSQL
- **Real-time**: Sub-100ms notification delivery
- **Authentication**: JWT validation for WebSocket connections
- **Reliability**: Handle client disconnections gracefully
- **Scaling**: Design for horizontal scaling across multiple servers

### Deliverables:
1. **Complete working implementation** (all interfaces)
2. **WebSocket connection management** with proper cleanup
3. **Database schema and queries** for notification storage
4. **Load testing results** demonstrating 5K concurrent connections
5. **Docker Compose setup** with all dependencies
6. **API documentation** with WebSocket protocol specification

---

## Evaluation Criteria (120 points total)

### Technical Excellence (40 points)
- **Performance**: Solutions meet specified performance requirements
- **Code Quality**: Clean, idiomatic Go with proper error handling
- **Architecture**: Well-designed, scalable solutions
- **Testing**: Comprehensive test coverage with realistic scenarios

### System Design (35 points)
- **Scalability**: Handles specified load and growth requirements  
- **Reliability**: Proper failure handling and recovery mechanisms
- **Security**: Comprehensive security implementations
- **Operations**: Production-ready deployment and monitoring

### Problem Solving (25 points)
- **Analysis**: Deep understanding of requirements and constraints
- **Trade-offs**: Clear reasoning for technical decisions
- **Innovation**: Creative and efficient solutions
- **Completeness**: All requirements fully addressed

### Communication (20 points)
- **Documentation**: Clear explanations of complex systems
- **Code Comments**: Well-documented implementation details
- **Architecture Decisions**: Justified technical choices
- **Presentation**: Clear communication of solutions

---

## Submission Requirements

**Code Repository:**
- Complete Git repository with commit history
- All code must compile and pass provided tests
- Include performance benchmarks and results
- Docker setup for easy evaluation

**Documentation:**
- README with setup and running instructions
- Architecture decision records (ADRs) for major choices
- API documentation with examples
- Performance analysis and optimization notes

