package ws

import (
	"encoding/json"
	"go.uber.org/zap"
	"sync"
)

// Message — сообщение, рассылаемое всем подключённым WebSocket-клиентам.
type Message struct {
	Type    string `json:"type"`              // stats_update, incident_new, incident_update
	Payload any    `json:"payload,omitempty"` // данные события
}

// Hub управляет WebSocket-подключениями и рассылкой сообщений.
type Hub struct {
	mu      sync.RWMutex
	clients map[*Client]struct{}
	logger  *zap.Logger
}

// Client — одно WebSocket-подключение.
type Client struct {
	send chan []byte
	hub  *Hub
}

func NewHub(logger *zap.Logger) *Hub {
	return &Hub{
		clients: make(map[*Client]struct{}),
		logger:  logger,
	}
}

// Register добавляет клиента в хаб. Возвращает канал, в который хаб будет писать сообщения.
func (h *Hub) Register() *Client {
	c := &Client{
		send: make(chan []byte, 32),
		hub:  h,
	}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	h.logger.Debug("ws client connected", zap.Int("total", len(h.clients)))
	return c
}

// Unregister удаляет клиента из хаба и закрывает его канал.
func (h *Hub) Unregister(c *Client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
	}
	total := len(h.clients)
	h.mu.Unlock()
	h.logger.Debug("ws client disconnected", zap.Int("total", total))
}

// Broadcast рассылает сообщение всем подключённым клиентам.
func (h *Hub) Broadcast(msg Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		h.logger.Error("ws marshal failed", zap.Error(err))
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		select {
		case c.send <- data:
		default:
			// клиент не читает — скипаем, чтобы не блокировать хаб
		}
	}
}

// Send возвращает канал для чтения сообщений этим клиентом.
func (c *Client) Send() <-chan []byte {
	return c.send
}