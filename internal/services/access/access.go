package access

import "log/slog"

type Access struct {
	log            *slog.Logger
	roleProvider   RoleProvider
	roleController RoleController
}

// RoleProvider gets list of user's role currently assigned on him
type RoleProvider interface {
	UserRoles(userID int64, appID int32) ([]string, error)
	HasRole(userID int64, roleID int32) (bool, error)
}

// RoleController provides manipulation with user's role, allow assigns and revokes role groups
type RoleController interface {
	AssignRole(userID int64, roleId int32) (bool, error)
	RevokeRole(userID int64, roleId int32) (bool, error)
}
