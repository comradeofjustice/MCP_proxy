CREATE TABLE IF NOT EXISTS mcp_audit_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT NOT NULL,
    total_tools INTEGER,
    vulnerable_count INTEGER,
    raw_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
