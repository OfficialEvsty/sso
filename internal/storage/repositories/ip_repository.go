package repositories

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net"
	"sso/internal/storage"
	"sso/internal/storage/postgres"
)

type IPRepository struct {
	db *postgres.ExtPool
}

// NewIPRepository creates new instance of IPRepository
func NewIPRepository(db *postgres.ExtPool) *IPRepository {
	return &IPRepository{
		db: db,
	}
}

// SaveTrustedIPv4 saves user's ip in db
func (r *IPRepository) SaveTrustedIPv4(ctx context.Context, trustedIP string, userID int64) error {
	var id interface{}
	err := r.db.QueryRow(
		ctx,
		`INSERT INTO user_trusted_ips (ipv4, user_id) VALUES ($1, $2) RETURNING id`,
		trustedIP,
		userID,
	).Scan(&id)
	if err != nil {
		return err
	}
	return nil
}

// GetAllUserTrustedIPv4 gets all trusted user's ips
func (r *IPRepository) GetAllUserTrustedIPv4(ctx context.Context, userID int64) (trustedIPs []net.IP, err error) {
	rows, err := r.db.Query(
		ctx,
		`SELECT ipv4 FROM user_trusted_ips WHERE user_id = $1`,
		userID,
	)
	defer rows.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to query trusted ips: %w: ", err)
	}
	for rows.Next() {
		var trustedIP net.IP
		if err := rows.Scan(&trustedIP); err != nil {
			return nil, fmt.Errorf("failed to scan trusted ips: %w", err)
		}
		trustedIPs = append(trustedIPs, trustedIP)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return trustedIPs, nil
}

// CheckUserTrustedIPv4 checks whether ipv4 trusted by specified user
func (r *IPRepository) CheckUserTrustedIPv4(ctx context.Context, ipv4 string) error {
	var id interface{}
	err := r.db.QueryRow(
		ctx,
		`SELECT id FROM user_trusted_ips WHERE ipv4 = $1`,
		ipv4,
	).Scan(&id)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("failed to query trusted ip: %w: ", err)
		}
		return storage.InfoTrustedIPNotFound
	}
	return nil
}
