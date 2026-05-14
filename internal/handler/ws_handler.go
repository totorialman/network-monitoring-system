package handler

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// WsHub управляет WebSocket-подключениями и broadcast'ом событий.
type WsHub struct {
	mu       sync.RWMutex
	conns    map[*websocket.Conn]struct{}
	logger   *zap.Logger
	upgrader websocket.Upgrader
}

// NewWsHub создаёт новый WebSocket-хаб.
func NewWsHub(logger *zap.Logger) *WsHub {
	return &WsHub{
		conns:  make(map[*websocket.Conn]struct{}),
		logger: logger,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Nginx уже проверяет same-origin
			},
		},
	}
}

// Broadcast рассылает событие всем подключённым клиентам.
// Реализует интерфейс service.WsBroadcaster.
func (h *WsHub) Broadcast(event interface{}) {
	data, err := json.Marshal(event)
	if err != nil {
		h.logger.Error("ws broadcast marshal error", zap.Error(err))
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for conn := range h.conns {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			h.logger.Warn("ws write error, removing connection", zap.Error(err))
			go h.removeConn(conn)
		}
	}
}

func (h *WsHub) removeConn(conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	conn.Close()
	delete(h.conns, conn)
}

// ServeWs обрабатывает WebSocket-подключение (JWT-аутентификация уже выполнена middleware).
func (h *WsHub) ServeWs(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Warn("ws upgrade failed", zap.Error(err))
		return
	}
	h.mu.Lock()
	h.conns[conn] = struct{}{}
	h.mu.Unlock()
	h.logger.Info("ws client connected", zap.Int("total", len(h.conns)))

	// Читаем сообщения (ping/pong) для поддержания соединения, но не обрабатываем их
	go func() {
		defer func() {
			h.mu.Lock()
			delete(h.conns, conn)
			h.mu.Unlock()
			conn.Close()
			h.logger.Info("ws client disconnected", zap.Int("total", len(h.conns)))
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}