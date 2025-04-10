package repositories

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IPRepository struct {
	db *pgxpool.Pool
}

// NewIPRepository creates new instance of ip repository
func NewIPRepository(db *pgxpool.Pool) *IPRepository {
	return &IPRepository{
		db: db,
	}
}

// SaveTrustedIPv4 saves user's ip in db
func (r *IPRepository) SaveTrustedIPv4(ctx context.Context, trustedIP string) error {
	var id interface{}
	err := r.db.QueryRow(
		ctx,
		`INSERT INTO user_trusted_ips (ipv4, user_id) VALUES ($1, $2) RETURNING id`,
		trustedIP,
	).Scan(&id)
	if err != nil {
		return err
	}
	return nil
}

// GetAllUserTrustedIPv4 gets all trusted user's ips
func (r *IPRepository) GetAllUserTrustedIPv4(ctx context.Context, userID int64) (trustedIPs []string, err error) {
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
		var trustedIP string
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
