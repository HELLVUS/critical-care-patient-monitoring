# Конфигурация RBAC
RBAC_ROLES = {
    'doctor': {
        'can_access_assigned': True,
        'can_access_ward': False,
        'can_decrypt': True,
        'can_manage_users': False
    },
    'nurse': {
        'can_access_assigned': False,
        'can_access_ward': True,
        'can_decrypt': True,
        'can_manage_users': False
    },
    'admin': {
        'can_access_assigned': False,
        'can_access_ward': False,
        'can_decrypt': False,
        'can_manage_users': True
    },
    'analyst': {
        'can_access_assigned': False,
        'can_access_ward': False,
        'can_decrypt': False,
        'can_manage_users': False
    }
}