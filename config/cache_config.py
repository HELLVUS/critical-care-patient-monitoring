# Конфигурация кеширования
CACHE_CONFIG = {
    'level1_max_records': 10,  # На мониторе пациента
    'level2_max_records': 1000,  # В шлюзе отделения
    'level2_ttl_minutes': 60,  # TTL для уровня 2
    'level3_ttl_minutes': None  # Без TTL для центрального сервера
}