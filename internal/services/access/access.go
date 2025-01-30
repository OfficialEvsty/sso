package access

import (
	"context"
	"log/slog"
	interfaces2 "sso/internal/services/access/interfaces"
	"sso/internal/services/auth/interfaces"
	"sso/internal/storage"
)

type Access struct {
	log            *slog.Logger
	roleProvider   interfaces2.RoleProvider
	roleController interfaces2.RoleController
	userProvider   interfaces.UserProvider
}

func New(log *slog.Logger, roleProvider interfaces2.RoleProvider, roleController interfaces2.RoleController) *Access {
	return &Access{
		log:            log,
		roleProvider:   roleProvider,
		roleController: roleController,
	}
}

// AssignRoleToUser adds user role
// Throws InfoUserAlreadyHasRole if user has specified role
// Throws ErrRoleNotFound if role by specified id doesn't exist
// TODO обработать ошибку ErrNoROlesFound в контроллере
func (a *Access) AssignRoleToUser(ctx context.Context, userID int64, roleID int32) (bool, error) {
	_, err := a.userProvider.UserById(ctx, userID)
	if err != nil {
		return false, err
	}

	hasRole, err := a.roleProvider.HasRole(ctx, userID, roleID)
	if err != nil {
		return false, err
	}
	if !hasRole {
		result, err := a.roleController.AssignRole(ctx, userID, roleID)
		if err != nil {
			return false, err
		}
		return result, nil
	}
	return false, storage.InfoUserAlreadyHasRole
}

// RevokeRoleFromUser revokes current active role from user
// Throws InfoUserHasNoSpecifiedRole if user has no specified role
// Throws ErrRoleNotFound if role by specified id doesn't exist
func (a *Access) RevokeRoleFromUser(ctx context.Context, userID int64, roleID int32) (bool, error) {
	hasRole, err := a.roleProvider.HasRole(ctx, userID, roleID)
	if err != nil {
		return false, err
	}
	if hasRole {
		result, err := a.roleController.RevokeRole(ctx, userID, roleID)
		if err != nil {
			return false, err
		}
		return result, nil
	}
	return false, storage.InfoUserHasNoSpecifiedRole
}

func (a *Access) ValidateAccessToken(ctx context.Context, userID int64, roleID int32) (bool, error) {}
