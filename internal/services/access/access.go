package access

import (
	"context"
	"log/slog"
	"sso/internal/lib/jwt"
	interfaces2 "sso/internal/services/access/interfaces"
	"sso/internal/services/auth/interfaces"
	"sso/internal/storage"
)

type Access struct {
	log            *slog.Logger
	roleProvider   interfaces2.RoleProvider
	roleController interfaces2.RoleController
	userProvider   interfaces.UserProvider
	appProvider    interfaces.AppProvider
}

func New(log *slog.Logger, roleProvider interfaces2.RoleProvider, roleController interfaces2.RoleController, appProvider interfaces.AppProvider, userProvider interfaces.UserProvider) *Access {
	return &Access{
		log:            log,
		roleProvider:   roleProvider,
		roleController: roleController,
		appProvider:    appProvider,
		userProvider:   userProvider,
	}
}

func (a *Access) isAdminValidate(ctx context.Context, appID int32, token string) (bool, error) {
	const op = "access.isAdminValidate"
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return false, err
	}

	tokenData, err := jwt.ValidateAccessToken(token, app.Secret)

	if err != nil {
		a.log.Error("error validating a token", op, err.Error())
		return false, err
	}

	if tokenData == nil {
		a.log.Error("token is empty", op, tokenData)
		return false, nil
	}

	isAdmin, err := a.userProvider.IsAdmin(ctx, tokenData.UserID)
	if err != nil {
		a.log.Error("error checking is user admin", op, tokenData)
		return false, err
	}

	return isAdmin, nil
}

// AssignRoleToUser adds user role
// Throws InfoUserAlreadyHasRole if user has specified role
// Throws ErrRoleNotFound if role by specified id doesn't exist
func (a *Access) AssignRoleToUser(ctx context.Context, token string, userID int64, roleID int32, appID int32) (bool, error) {
	const op = "access.AssignRoleToUser"
	isAdmin, err := a.isAdminValidate(ctx, appID, token)
	if err != nil {
		return false, err
	}
	if !isAdmin {
		a.log.Info("user has no admin permissions", op, userID)
		return false, storage.ErrPermissionDenied
	}

	_, err = a.userProvider.UserById(ctx, userID)
	if err != nil {
		a.log.Error("error user not found", op, userID, err)
		return false, err
	}

	hasRole, err := a.roleProvider.HasRole(ctx, userID, roleID)
	if err != nil {
		a.log.Error("error getting user's role", op, userID, err)
		return false, err
	}
	if !hasRole {
		result, err := a.roleController.AssignRole(ctx, userID, roleID)
		if err != nil {
			a.log.Error("error assigning role", op, userID, roleID, err)
			return false, err
		}
		a.log.Info("successfully assigned role to user", op, userID, result)
		return result, nil
	}
	a.log.Info("user already has specified role", op, userID)
	return false, storage.InfoUserAlreadyHasRole
}

// RevokeRoleFromUser revokes current active role from user
// Throws InfoUserHasNoSpecifiedRole if user has no specified role
// Throws ErrRoleNotFound if role by specified id doesn't exist
func (a *Access) RevokeRoleFromUser(ctx context.Context, token string, userID int64, roleID int32, appID int32) (bool, error) {
	const op = "access.RevokeRoleFromUser"
	isAdmin, err := a.isAdminValidate(ctx, appID, token)
	if err != nil {
		return false, err
	}
	if !isAdmin {
		a.log.Info("user has no admin permissions", op, userID)
		return false, storage.ErrPermissionDenied
	}

	_, err = a.userProvider.UserById(ctx, userID)
	if err != nil {
		a.log.Error("error user not found", op, userID, err)
		return false, err
	}

	hasRole, err := a.roleProvider.HasRole(ctx, userID, roleID)
	if err != nil {
		a.log.Error("error getting user's role", op, userID, err)
		return false, err
	}
	if hasRole {
		result, err := a.roleController.RevokeRole(ctx, userID, roleID)
		if err != nil {
			a.log.Error("error revoking role", op, userID, roleID, err)
			return false, err
		}
		a.log.Info("successfully revoked role from user", op, userID, result)
		return result, nil
	}
	a.log.Info("user has no specified role", op, userID)
	return false, storage.InfoUserHasNoSpecifiedRole
}
