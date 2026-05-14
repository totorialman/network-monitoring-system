package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
	"network-monitor-backend/internal/config"
	"network-monitor-backend/internal/handler"
	"network-monitor-backend/internal/middleware"
	chrepo "network-monitor-backend/internal/repository/clickhouse"
	pgrepo "network-monitor-backend/internal/repository/postgres"
	"network-monitor-backend/internal/service"
)

func main() {
	cfg := config.Load()
	logger, _ := zap.NewProduction()
	if cfg.App.Env == "development" {
		logger, _ = zap.NewDevelopment()
	}
	defer logger.Sync()
	pg, err := connectPostgres(cfg.Postgres.DSN())
	if err != nil {
		logger.Fatal("postgres connection failed", zap.Error(err))
	}
	defer pg.Close()
	if err := runMigrations(pg); err != nil {
		logger.Fatal("postgres migrations failed", zap.Error(err))
	}
	clickhouse, err := chrepo.New(cfg.ClickHouse)
	if err != nil {
		logger.Fatal("clickhouse connection failed", zap.Error(err))
	}
	defer clickhouse.Close()
	if err := initClickHouseSchema(context.Background(), clickhouse); err != nil {
		logger.Fatal("clickhouse schema init failed", zap.Error(err))
	}
	users := pgrepo.NewUserRepo(pg)
	agents := pgrepo.NewAgentRepo(pg)
	incidents := pgrepo.NewIncidentRepo(pg)
	alerts := pgrepo.NewAlertRepo(pg)
	authSvc := service.NewAuthService(users, cfg.JWT.Secret, cfg.JWT.Expiration)
	if err := authSvc.EnsureInitialAdmin(context.Background(), cfg.InitialAdmin.Login, cfg.InitialAdmin.Password); err != nil {
		logger.Fatal("initial admin failed", zap.Error(err))
	}
	mlClient := service.NewMLClient(cfg.ML.ServiceURL, cfg.ML.Timeout)
	notifications := service.NewNotificationService(cfg.Telegram, alerts, logger)

	// WebSocket-хаб для broadcast'а событий фронтенду
	wsHub := handler.NewWsHub(logger)

	ingest := service.NewLogIngestService(clickhouse, incidents, mlClient, notifications, wsHub, logger, cfg.ML.WindowSizeSeconds)

	authH := handler.NewAuthHandler(authSvc)
	agentH := handler.NewAgentHandler(agents, ingest)
	incH := handler.NewIncidentHandler(incidents, clickhouse)
	telegramH := handler.NewTelegramHandler(incidents, cfg.Telegram, logger)
	statsH := handler.NewStatsHandler(incidents, clickhouse)
	healthH := handler.NewHealthHandler(pg, clickhouse, mlClient, cfg.App.Version)

	r := mux.NewRouter()
	r.Use(mux.MiddlewareFunc(middleware.Recover(logger)))
	r.Use(mux.MiddlewareFunc(middleware.Logging(logger)))

	// Регистрация webhook в Telegram Bot API
	go handler.RegisterWebhook(cfg.Telegram, logger)

	r.HandleFunc("/healthz", healthH.Healthz).Methods(http.MethodGet)

	api := r.PathPrefix("/api").Subrouter()

	// WebSocket endpoint (JWT-защищён)
	wsRouter := api.PathPrefix("/ws").Subrouter()
	wsRouter.Use(mux.MiddlewareFunc(middleware.JWT(cfg.JWT.Secret)))
	wsRouter.HandleFunc("", wsHub.ServeWs).Methods(http.MethodGet)

	// Публичный эндпоинт для вебхуков Telegram
	r.HandleFunc("/api/telegram/webhook", telegramH.Webhook).Methods(http.MethodPost)

	api.HandleFunc("/auth/login", authH.Login).Methods(http.MethodPost)

	agentAPI := api.PathPrefix("/agent").Subrouter()
	agentAPI.Use(mux.MiddlewareFunc(middleware.AgentAuth(agents)))
	agentAPI.HandleFunc("/logs", agentH.UploadLogs).Methods(http.MethodPost)

	admin := api.PathPrefix("").Subrouter()
	admin.Use(mux.MiddlewareFunc(middleware.JWT(cfg.JWT.Secret)))
	admin.HandleFunc("/admin/agents/tokens", agentH.CreateToken).Methods(http.MethodPost)
	admin.HandleFunc("/agents", agentH.List).Methods(http.MethodGet)
	admin.HandleFunc("/agents/{agent_id}/logs", statsH.AgentLogs).Methods(http.MethodGet)
	admin.HandleFunc("/incidents", incH.List).Methods(http.MethodGet)
	admin.HandleFunc("/incidents/{id}", incH.Get).Methods(http.MethodGet)
	admin.HandleFunc("/incidents/{id}/status", incH.UpdateStatus).Methods(http.MethodPut)
	admin.HandleFunc("/stats", statsH.Stats).Methods(http.MethodGet)

	srv := &http.Server{Addr: ":" + cfg.App.Port, Handler: r, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		logger.Info("backend started", zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server error", zap.Error(err))
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger.Info("shutting down")
	_ = srv.Shutdown(ctx)
}

func connectPostgres(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	var last error
	for i := 0; i < 20; i++ {
		if err := db.Ping(); err == nil {
			return db, nil
		} else {
			last = err
			time.Sleep(2 * time.Second)
		}
	}
	return nil, last
}
func runMigrations(db *sql.DB) error {
	goose.SetBaseFS(pgrepo.MigrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, "migrations")
}

func initClickHouseSchema(ctx context.Context, repo interface{ InitSchema(context.Context) error }) error {
	var last error
	for i := 0; i < 20; i++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := repo.InitSchema(attemptCtx)
		cancel()
		if err == nil {
			return nil
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return last
}