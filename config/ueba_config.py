# Конфигурация UEBA
UEBA_CONFIG = {
    'max_patients_per_session': 10,
    'max_accesses_per_hour': 50,
    'working_hours': (6, 22),
    'mass_access_threshold': 15,  # Разных пациентов за T минут
    'mass_access_window_minutes': 10
}