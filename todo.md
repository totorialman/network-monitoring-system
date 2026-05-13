# TODO

- [x] Исправить только ошибку Docker-сборки frontend: `pnpm install --frozen-lockfile` ищет отсутствующий файл `patches/wouter@3.7.1.patch`.

- [x] Исправить только ошибку Docker Compose: контейнер `nm-clickhouse` становится `unhealthy`, из-за чего зависимость `clickhouse` failed to start.

- [x] Исправить только ошибку Docker Compose: backend не стартует, потому что host-порт `8080` уже занят (`Bind for 0.0.0.0:8080 failed: port is already allocated`).

- [x] Откатить предыдущее изменение host-порта backend и вернуть публикацию `8080:8080` в `docker-compose.yml`.

- [x] Исправить только новую ошибку Docker Compose: контейнер `nm-backend` становится `unhealthy`, из-за чего frontend не стартует (`dependency backend failed to start`).

- [x] Объяснить, когда именно отправляются Telegram-уведомления и какие настройки на это влияют.
- [x] Найти причину ошибки PostgreSQL `inconsistent types deduced for parameter $1 (SQLSTATE 42P08)` при изменении статуса/комментария инцидента.
- [x] Объяснить, почему при первом запуске в ClickHouse могла отсутствовать таблица и как это связано с миграциями/инициализацией backend.
