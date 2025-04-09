package interfaces

import "context"

// RoleProvider gets list of user's role currently assigned on him
type RoleProvider interface {
	UserRoles(ctx context.Context, userID int64) (*[]string, error)
	HasRole(ctx context.Context, userID int64, roleID int32) (bool, error)
}

// RoleController provides manipulation with user's role, allow assigns and revokes role groups
type RoleController interface {
	AssignRole(ctx context.Context, userID int64, roleId int32) (bool, error)
	RevokeRole(ctx context.Context, userID int64, roleId int32) (bool, error)
}
