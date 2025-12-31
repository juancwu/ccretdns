-- +goose Up
-- +goose StatementBegin
CREATE TABLE records_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    ip TEXT NOT NULL,
    record_type TEXT DEFAULT 'A',
    UNIQUE(domain, record_type)
);

INSERT INTO records_new (id, domain, ip, record_type)
SELECT id, domain, ip, record_type FROM records;

DROP TABLE records;

ALTER TABLE records_new RENAME TO records;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE records_old (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL,
    record_type TEXT DEFAULT 'A'
);

INSERT INTO records_old (id, domain, ip, record_type)
SELECT id, domain, ip, record_type FROM records;

DROP TABLE records;
ALTER TABLE records_old RENAME TO records;
-- +goose StatementEnd
