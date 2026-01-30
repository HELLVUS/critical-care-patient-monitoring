from cache_config import CACHE_CONFIG
from integrity_config import INTEGRITY_CONFIG
from rbac_roles import RBAC_ROLES
from ueba_config import UEBA_CONFIG

def validate_config():
    errors = []
    
    if not isinstance(INTEGRITY_CONFIG, dict):
        errors.append("INTEGRITY_CONFIG должен быть dict")
    
    if INTEGRITY_CONFIG['heart_rate_min'] >= INTEGRITY_CONFIG['heart_rate_max']:
        errors.append("heart_rate_min должен быть < heart_rate_max")
    
    if not (0 < INTEGRITY_CONFIG['ewma_alpha'] <= 1):
        errors.append("ewma_alpha должен быть от 0 до 1")
    
    if CACHE_CONFIG['level2_max_records'] <= 0:
        errors.append("level2_max_records должен быть > 0")
    
    if 'doctor' not in RBAC_ROLES:
        errors.append("Отсутствует роль 'doctor'")
    
    if UEBA_CONFIG['max_patients_per_session'] <= 0:
        errors.append("max_patients_per_session должен быть > 0")
    
    return len(errors) == 0, errors