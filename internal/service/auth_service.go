package service

import (
	"context"
	"errors"
	"network-monitor-backend/internal/domain"
	"network-monitor-backend/internal/pkg/hash"
	jwtutil "network-monitor-backend/internal/pkg/jwt"
	"time"
)

type UserRepository interface {
	FindByLogin(context.Context, string) (*domain.User, error)
	EnsureAdmin(context.Context, string, string) error
}
type AuthService struct {
	users  UserRepository
	secret string
	ttl    time.Duration
}

func NewAuthService(users UserRepository, secret string, ttl time.Duration) *AuthService {
	return &AuthService{users: users, secret: secret, ttl: ttl}
}
func (s *AuthService) Login(ctx context.Context, login, password string) (string, time.Time, *domain.User, error) {
	u, err := s.users.FindByLogin(ctx, login)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	if u == nil || !hash.CheckPassword(password, u.PasswordHash) {
		return "", time.Time{}, nil, errors.New("invalid credentials")
	}
	token, exp, err := jwtutil.Generate(u.ID, u.Login, u.Role, s.secret, s.ttl)
	return token, exp, u, err
}
func (s *AuthService) EnsureInitialAdmin(ctx context.Context, login, password string) error {
	ph, err := hash.Password(password)
	if err != nil {
		return err
	}
	return s.users.EnsureAdmin(ctx, login, ph)
}
