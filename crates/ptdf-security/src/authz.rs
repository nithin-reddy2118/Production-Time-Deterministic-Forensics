//! Authorization (architecture §18): role-based access control. Three
//! roles cover the access patterns the Query API/CLI/agents actually need
//! — `Admin` (full control, including managing other principals'
//! credentials), `Operator` (can start recordings/replays and read
//! everything), `Viewer` (read-only: query sessions, view metrics). This
//! is a fixed, small role set by design — architecture §18 doesn't call
//! for arbitrary custom roles/policies (that would be a much larger
//! policy-engine undertaking), just role-gated access to a known set of
//! operations.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    ViewMetrics,
    QuerySessions,
    StartRecording,
    StartReplay,
    ManageAgents,
    ManagePrincipals,
}

const ADMIN_PERMISSIONS: &[Permission] = &[
    Permission::ViewMetrics,
    Permission::QuerySessions,
    Permission::StartRecording,
    Permission::StartReplay,
    Permission::ManageAgents,
    Permission::ManagePrincipals,
];

const OPERATOR_PERMISSIONS: &[Permission] = &[
    Permission::ViewMetrics,
    Permission::QuerySessions,
    Permission::StartRecording,
    Permission::StartReplay,
    Permission::ManageAgents,
];

const VIEWER_PERMISSIONS: &[Permission] = &[Permission::ViewMetrics, Permission::QuerySessions];

impl Role {
    pub fn permissions(self) -> &'static [Permission] {
        match self {
            Role::Admin => ADMIN_PERMISSIONS,
            Role::Operator => OPERATOR_PERMISSIONS,
            Role::Viewer => VIEWER_PERMISSIONS,
        }
    }

    pub fn has_permission(self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("role {role:?} does not have permission {permission:?}")]
pub struct AuthzError {
    pub role: Role,
    pub permission: Permission,
}

/// Enforce that `role` has `permission`, for use directly in a request
/// handler's control flow (`authorize(role, Permission::StartReplay)?`).
pub fn authorize(role: Role, permission: Permission) -> Result<(), AuthzError> {
    if role.has_permission(permission) {
        Ok(())
    } else {
        Err(AuthzError { role, permission })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_every_defined_permission() {
        for permission in [
            Permission::ViewMetrics,
            Permission::QuerySessions,
            Permission::StartRecording,
            Permission::StartReplay,
            Permission::ManageAgents,
            Permission::ManagePrincipals,
        ] {
            assert!(authorize(Role::Admin, permission).is_ok());
        }
    }

    #[test]
    fn viewer_can_only_read() {
        assert!(authorize(Role::Viewer, Permission::ViewMetrics).is_ok());
        assert!(authorize(Role::Viewer, Permission::QuerySessions).is_ok());
        assert!(authorize(Role::Viewer, Permission::StartReplay).is_err());
        assert!(authorize(Role::Viewer, Permission::ManageAgents).is_err());
        assert!(authorize(Role::Viewer, Permission::ManagePrincipals).is_err());
    }

    #[test]
    fn operator_can_operate_but_not_manage_principals() {
        assert!(authorize(Role::Operator, Permission::StartRecording).is_ok());
        assert!(authorize(Role::Operator, Permission::StartReplay).is_ok());
        assert!(authorize(Role::Operator, Permission::ManageAgents).is_ok());
        assert!(authorize(Role::Operator, Permission::ManagePrincipals).is_err());
    }

    #[test]
    fn denied_authorization_reports_both_role_and_permission() {
        let err = authorize(Role::Viewer, Permission::StartReplay).unwrap_err();
        assert_eq!(err.role, Role::Viewer);
        assert_eq!(err.permission, Permission::StartReplay);
    }
}
