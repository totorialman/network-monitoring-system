package handler

import (
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"net/http"
	"network-monitor-backend/internal/ws"
	"time"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true }, // nginx уже фильтрует
}

// WsHandler обслуживает WebSocket-подключения.
// JWT-авторизация выполняется middleware, поэтому здесь просто апгрейдим соединение.
type WsHandler struct {
	hub    *ws.Hub
	logger *zap.Logger
}

func NewWsHandler(hub *ws.Hub, logger *zap.Logger) *WsHandler {
	return &WsHandler{hub: hub, logger: logger}
}

func (h *WsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Debug("ws upgrade failed", zap.Error(err))
		return
	}

	client := h.hub.Register()
	defer h.hub.Unregister(client)

	// Читаем из хаба и пишем в WebSocket
	go func() {
		for msg := range client.Send() {
			if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				break
			}
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				h.logger.Debug("ws write failed", zap.Error(err))
				break
			}
		}
	}()

	// Читаем из WebSocket (ждём close/pong)
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
	conn.Close()
}