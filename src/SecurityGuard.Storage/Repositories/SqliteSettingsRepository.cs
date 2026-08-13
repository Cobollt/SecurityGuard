using SecurityGuard.Core.Contracts;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteSettingsRepository
    : ISettingsRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteSettingsRepository(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<string?> GetAsync(
        string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            SELECT value
            FROM settings
            WHERE key = $key
            LIMIT 1;
            """;

        command.Parameters.AddWithValue(
            "$key",
            key);

        var result =
            await command.ExecuteScalarAsync(cancellationToken);

        return result is null ||
               result is DBNull
            ? null
            : Convert.ToString(result);
    }

    public async Task SetAsync(
        string key,
        string value,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(value);

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            INSERT INTO settings
            (
                key,
                value,
                updated_at_utc
            )
            VALUES
            (
                $key,
                $value,
                $updated
            )
            ON CONFLICT(key)
            DO UPDATE SET
                value = excluded.value,
                updated_at_utc = excluded.updated_at_utc;
            """;

        command.Parameters.AddWithValue(
            "$key",
            key);

        command.Parameters.AddWithValue(
            "$value",
            value);

        command.Parameters.AddWithValue(
            "$updated",
            DateTimeOffset.UtcNow.ToString("O"));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}