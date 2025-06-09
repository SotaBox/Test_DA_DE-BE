package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	RateReqPerMinutePerUser   = 1000
	RateReqPerMinutePerApiKey = 10000
)

// Gateway represents our secure API gateway
type Gateway struct {
	router            *mux.Router
	logger            *zap.Logger
	rateLimiters      map[string]*rate.Limiter
	mu                sync.Mutex
	jwtSecret         []byte
	refreshSecret     []byte
	allowedOrigins    []string
	allowedRoles      map[string][]string // endpoint -> roles
	prometheusMetrics *PrometheusMetrics
}

// PrometheusMetrics holds all our metrics
type PrometheusMetrics struct {
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec
	httpRequestSize     *prometheus.SummaryVec
	httpResponseSize    *prometheus.SummaryVec
	httpErrorsTotal     *prometheus.CounterVec
	rateLimitedRequests prometheus.Counter
	authenticatedUsers  prometheus.Gauge
	activeConnections   prometheus.Gauge
}

// Claims represents the JWT claims
type Claims struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

// RefreshClaims represents refresh token claims
type RefreshClaims struct {
	UserID string `json:"userId"`
	jwt.StandardClaims
}

// AuditLog represents an audit log entry
type AuditLog struct {
	Timestamp  time.Time `json:"timestamp"`
	UserID     string    `json:"userId,omitempty"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StatusCode int       `json:"statusCode"`
	ClientIP   string    `json:"clientIp"`
	UserAgent  string    `json:"userAgent"`
}

// NewGateway creates a new Gateway instance
func NewGateway(jwtSecret, refreshSecret string, allowedOrigins []string) *Gateway {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}

	metrics := initPrometheusMetrics()

	return &Gateway{
		router:            mux.NewRouter(),
		logger:            logger,
		rateLimiters:      make(map[string]*rate.Limiter),
		jwtSecret:         []byte(jwtSecret),
		refreshSecret:     []byte(refreshSecret),
		allowedOrigins:    allowedOrigins,
		allowedRoles:      make(map[string][]string),
		prometheusMetrics: metrics,
	}
}

func initPrometheusMetrics() *PrometheusMetrics {
	return &PrometheusMetrics{
		httpRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Count of all HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		httpRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Duration of all HTTP requests",
				Buckets: []float64{0.1, 0.3, 0.5, 0.7, 1, 1.5, 2, 3, 5},
			},
			[]string{"path", "method"},
		),
		httpRequestSize: promauto.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_request_size_bytes",
				Help: "Size of HTTP requests",
			},
			[]string{"method", "path"},
		),
		httpResponseSize: promauto.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_response_size_bytes",
				Help: "Size of HTTP responses",
			},
			[]string{"method", "path"},
		),
		httpErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_errors_total",
				Help: "Count of HTTP errors",
			},
			[]string{"type"},
		),
		rateLimitedRequests: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "rate_limited_requests_total",
				Help: "Count of rate limited requests",
			},
		),
		authenticatedUsers: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "authenticated_users_total",
				Help: "Number of authenticated users",
			},
		),
		activeConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "active_connections_total",
				Help: "Number of active connections",
			},
		),
	}
}

// ServeHTTP implements the http.Handler interface
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.prometheusMetrics.activeConnections.Inc()
	defer g.prometheusMetrics.activeConnections.Dec()

	start := time.Now()
	wrappedWriter := newResponseWriter(w)

	// Chain middleware
	handler := g.chainMiddleware(g.router)

	// Serve the request
	handler.ServeHTTP(wrappedWriter, r)

	// Record metrics
	duration := time.Since(start).Seconds()
	g.prometheusMetrics.httpRequestDuration.WithLabelValues(
		r.URL.Path, r.Method,
	).Observe(duration)

	g.prometheusMetrics.httpRequestsTotal.WithLabelValues(
		r.Method, r.URL.Path, fmt.Sprintf("%d", wrappedWriter.statusCode),
	).Inc()

	// Audit logging
	g.logAudit(r, wrappedWriter.statusCode)
}

func (g *Gateway) chainMiddleware(next http.Handler) http.Handler {
	return handlers.CORS(
		handlers.AllowedOrigins(g.allowedOrigins),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)(
		g.securityHeaders(
			g.loggingMiddleware(
				g.rateLimiterMiddleware(
					g.authenticationMiddleware(
						g.authorizationMiddleware(next),
					),
				),
			),
		),
	)
}

// securityHeaders adds security-related headers
func (g *Gateway) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs request details
func (g *Gateway) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.logger.Info("incoming request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("ip", r.RemoteAddr),
			zap.String("user-agent", r.UserAgent()),
		)

		next.ServeHTTP(w, r)
	})
}

// rateLimiterMiddleware implements rate limiting
func (g *Gateway) rateLimiterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identifier := g.getRateLimitIdentifier(r)

		limiter := g.getLimiter(identifier, r)

		if !limiter.Allow() {
			g.prometheusMetrics.rateLimitedRequests.Inc()
			g.logger.Warn("rate limit exceeded",
				zap.String("identifier", identifier),
				zap.String("ip", r.RemoteAddr),
			)
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) getRateLimitIdentifier(r *http.Request) string {
	// Check for API key first
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "api-key:" + apiKey
	}

	// Then check for JWT
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return g.jwtSecret, nil
		})

		if err == nil && token.Valid {
			if claims, ok := token.Claims.(*Claims); ok {
				return "user:" + claims.UserID
			}
		}
	}

	// Fall back to IP address
	return "ip:" + strings.Split(r.RemoteAddr, ":")[0]
}

func (g *Gateway) getLimiter(identifier string, r *http.Request) *rate.Limiter {
	g.mu.Lock()
	defer g.mu.Unlock()

	if limiter, exists := g.rateLimiters[identifier]; exists {
		return limiter
	}

	// Configure rate limits based on identifier type
	var limiter *rate.Limiter
	if strings.HasPrefix(identifier, "api-key:") {
		// 10K req/min for API keys
		limiter = rate.NewLimiter(rate.Limit(RateReqPerMinutePerApiKey/60), RateReqPerMinutePerApiKey)
	} else if strings.HasPrefix(identifier, "user:") {
		// 1000 req/min for users
		limiter = rate.NewLimiter(rate.Limit(RateReqPerMinutePerUser/60), RateReqPerMinutePerUser)
	} else {
		// Default rate limit for IPs
		limiter = rate.NewLimiter(rate.Limit(100000/60), 100000)
	}

	g.rateLimiters[identifier] = limiter
	return limiter
}

// authenticationMiddleware validates JWT tokens
func (g *Gateway) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for certain paths
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" || r.URL.Path == "/auth/login" || r.URL.Path == "/auth/refresh" {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			g.prometheusMetrics.httpErrorsTotal.WithLabelValues("unauthorized").Inc()
			http.Error(w, "authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			g.prometheusMetrics.httpErrorsTotal.WithLabelValues("invalid_token").Inc()
			http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return g.jwtSecret, nil
		})

		if err != nil {
			g.prometheusMetrics.httpErrorsTotal.WithLabelValues("invalid_token").Inc()
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			g.prometheusMetrics.httpErrorsTotal.WithLabelValues("invalid_token").Inc()
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(ctx)

		g.prometheusMetrics.authenticatedUsers.Inc()
		next.ServeHTTP(w, r)
	})
}

// authorizationMiddleware implements RBAC
func (g *Gateway) authorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authorization for certain paths
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		claims, ok := r.Context().Value("claims").(*Claims)
		if !ok {
			g.prometheusMetrics.httpErrorsTotal.WithLabelValues("unauthorized").Inc()
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		allowedRoles, exists := g.allowedRoles[r.URL.Path]
		if !exists {
			// No specific roles required for this endpoint
			next.ServeHTTP(w, r)
			return
		}

		// Check if user has one of the allowed roles
		for _, role := range allowedRoles {
			if claims.Role == role {
				next.ServeHTTP(w, r)
				return
			}
		}

		g.prometheusMetrics.httpErrorsTotal.WithLabelValues("forbidden").Inc()
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

// logAudit creates an audit log entry
func (g *Gateway) logAudit(r *http.Request, statusCode int) {
	var userID string
	if claims, ok := r.Context().Value("claims").(*Claims); ok {
		userID = claims.UserID
	}

	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}

	auditLog := AuditLog{
		Timestamp:  time.Now().UTC(),
		UserID:     userID,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: statusCode,
		ClientIP:   clientIP,
		UserAgent:  r.UserAgent(),
	}

	logData, _ := json.Marshal(auditLog)
	g.logger.Info("audit_log", zap.String("entry", string(logData)))
}

// AddRoute adds a new route with required roles
func (g *Gateway) AddRoute(path string, handler http.HandlerFunc, methods []string, roles []string) {
	g.router.HandleFunc(path, handler).Methods(methods...)
	if len(roles) > 0 {
		g.allowedRoles[path] = roles
	}
}

// GenerateJWT creates a new JWT token
func (g *Gateway) GenerateJWT(userID, role string) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute) // Short-lived access token
	claims := &Claims{
		UserID: userID,
		Role:   role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(g.jwtSecret)
}

// GenerateRefreshToken creates a new refresh token
func (g *Gateway) GenerateRefreshToken(userID string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour * 7) // Long-lived refresh token
	claims := &RefreshClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(g.refreshSecret)
}

// ValidateRefreshToken validates a refresh token
func (g *Gateway) ValidateRefreshToken(tokenString string) (*RefreshClaims, error) {
	claims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return g.refreshSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// healthCheckHandler handles health checks
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// loginHandler handles user login and token generation
func (g *Gateway) loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Mock authentication - replace with real auth logic
	if creds.Username != "admin" || creds.Password != "password" {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate tokens
	accessToken, err := g.GenerateJWT("123", "admin")
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := g.GenerateRefreshToken("123")
	if err != nil {
		http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Return tokens
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// refreshHandler handles token refresh
func (g *Gateway) refreshHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	claims, err := g.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Generate new access token
	accessToken, err := g.GenerateJWT(claims.UserID, "admin")
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token": accessToken,
	})
}

// protectedHandler demonstrates a protected endpoint
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Hello, %s (role: %s)", claims.UserID, claims.Role)))
}

// Start starts the gateway server with graceful shutdown
func (g *Gateway) Start(addr string) error {
	// Setup routes
	g.AddRoute("/health", healthCheckHandler, []string{"GET"}, nil)
	g.AddRoute("/metrics", promhttp.Handler().ServeHTTP, []string{"GET"}, nil)
	g.AddRoute("/auth/login", g.loginHandler, []string{"POST"}, nil)
	g.AddRoute("/auth/refresh", g.refreshHandler, []string{"POST"}, nil)
	g.AddRoute("/protected", protectedHandler, []string{"GET"}, []string{"admin"})

	server := &http.Server{
		Addr:    addr,
		Handler: g,
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)

	go func() {
		g.logger.Info("starting server", zap.String("addr", addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			g.logger.Fatal("server error", zap.Error(err))
		}
	}()

	<-stop
	g.logger.Info("shutting down server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return server.Shutdown(ctx)
}

func main() {
	jwtSecret := "256-bit-secret"
	refreshSecret := "refresh-secret"
	allowedOrigins := []string{"https://example.com", "http://localhost:3000"}

	gateway := NewGateway(jwtSecret, refreshSecret, allowedOrigins)

	// Start the server
	if err := gateway.Start(":8080"); err != nil {
		gateway.logger.Fatal("server shutdown error", zap.Error(err))
	}
}
