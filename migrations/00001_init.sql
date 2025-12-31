-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL,
    record_type TEXT DEFAULT 'A'
);

CREATE TABLE IF NOT EXISTS upstreams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL UNIQUE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS records;
DROP TABLE IF EXISTS upstreams;
-- +goose StatementEnd
