namespace SecurityGuard.Storage.Database;

public sealed class DatabaseInitializer
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public DatabaseInitializer(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task InitializeAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL;";
            await pragma.ExecuteScalarAsync(cancellationToken);
        }

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            CREATE TABLE IF NOT EXISTS security_events
            (
                id TEXT PRIMARY KEY,
                created_at_utc TEXT NOT NULL,
                module INTEGER NOT NULL,
                type INTEGER NOT NULL,
                severity INTEGER NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                action INTEGER NOT NULL,
                correlation_id TEXT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_security_events_created
            ON security_events(created_at_utc DESC);

            CREATE TABLE IF NOT EXISTS rules
            (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                module INTEGER NOT NULL,
                decision INTEGER NOT NULL,
                scope INTEGER NOT NULL,
                value TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS rule_conditions
            (
                rule_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                scope INTEGER NOT NULL,
                value TEXT NOT NULL,

                PRIMARY KEY (rule_id, position),

                FOREIGN KEY (rule_id)
                    REFERENCES rules(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS ix_rule_conditions_rule_id
            ON rule_conditions(rule_id);

            CREATE INDEX IF NOT EXISTS idx_rules_module
            ON rules(module);

            CREATE INDEX IF NOT EXISTS idx_rules_enabled
            ON rules(enabled);

            CREATE TABLE IF NOT EXISTS quarantine
            (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                original_file_name TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                source_module TEXT NOT NULL,
                reason TEXT NOT NULL,
                quarantined_at_utc TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_quarantine_sha256
            ON quarantine(sha256);

            CREATE TABLE IF NOT EXISTS protected_objects
            (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                extension TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                trust_status INTEGER NOT NULL,
                first_seen_at_utc TEXT NOT NULL,
                last_seen_at_utc TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_protected_objects_sha256
            ON protected_objects(sha256);

            CREATE INDEX IF NOT EXISTS idx_protected_objects_path
            ON protected_objects(path);

            CREATE TABLE IF NOT EXISTS decision_requests
            (
                id TEXT PRIMARY KEY,
                module INTEGER NOT NULL,
                event_type INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                file_path TEXT NULL,
                process_name TEXT NULL,
                available_actions_json TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS decision_request_contexts
            (
                request_id TEXT PRIMARY KEY,
                context_json TEXT NOT NULL,

                FOREIGN KEY (request_id)
                    REFERENCES decision_requests(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS decision_request_identities
            (
                request_id TEXT NOT NULL PRIMARY KEY,
                identity TEXT NOT NULL UNIQUE,

                FOREIGN KEY (request_id)
                    REFERENCES decision_requests(id)
                    ON DELETE CASCADE
            );

            CREATE UNIQUE INDEX IF NOT EXISTS
            ix_decision_request_identities_identity
            ON decision_request_identities(identity);

            CREATE INDEX IF NOT EXISTS idx_decision_requests_created
            ON decision_requests(created_at_utc);

            CREATE TABLE IF NOT EXISTS scan_results
            (
                id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                verdict INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                started_at_utc TEXT NOT NULL,
                completed_at_utc TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scan_results_sha256
            ON scan_results(sha256);

            CREATE INDEX IF NOT EXISTS idx_scan_results_completed
            ON scan_results(completed_at_utc DESC);

            CREATE TABLE IF NOT EXISTS settings
            (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );
            """;

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}