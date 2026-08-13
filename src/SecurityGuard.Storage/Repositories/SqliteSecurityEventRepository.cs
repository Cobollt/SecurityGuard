using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteSecurityEventRepository
    : ISecurityEventRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteSecurityEventRepository(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task AddAsync(
        SecurityEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            INSERT INTO security_events
            (
                id,
                created_at_utc,
                module,
                type,
                severity,
                title,
                details,
                action,
                correlation_id
            )
            VALUES
            (
                $id,
                $created,
                $module,
                $type,
                $severity,
                $title,
                $details,
                $action,
                $correlation
            );
            """;

        command.Parameters.AddWithValue(
            "$id",
            securityEvent.Id.ToString());

        command.Parameters.AddWithValue(
            "$created",
            securityEvent.CreatedAtUtc.ToString("O"));

        command.Parameters.AddWithValue(
            "$module",
            (int)securityEvent.Module);

        command.Parameters.AddWithValue(
            "$type",
            (int)securityEvent.Type);

        command.Parameters.AddWithValue(
            "$severity",
            (int)securityEvent.Severity);

        command.Parameters.AddWithValue(
            "$title",
            securityEvent.Title);

        command.Parameters.AddWithValue(
            "$details",
            securityEvent.Details);

        command.Parameters.AddWithValue(
            "$action",
            (int)securityEvent.Action);

        command.Parameters.AddWithValue(
            "$correlation",
            securityEvent.CorrelationId?.ToString() ??
            (object)DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<SecurityEvent>> GetRecentAsync(
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                id,
                created_at_utc,
                module,
                type,
                severity,
                title,
                details,
                action,
                correlation_id
            FROM security_events
            ORDER BY created_at_utc DESC
            LIMIT $limit;
            """;

        command.Parameters.AddWithValue(
            "$limit",
            limit);

        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken);

        var results = new List<SecurityEvent>();

        while (await reader.ReadAsync(cancellationToken))
        {
            Guid? correlation =
            reader.IsDBNull(8)
            ? null
            : Guid.Parse(reader.GetString(8));

            results.Add(
                new SecurityEvent(
                    Guid.Parse(reader.GetString(0)),
                    DateTimeOffset.Parse(reader.GetString(1)),
                    (SecurityModuleKind)reader.GetInt32(2),
                    (SecurityEventType)reader.GetInt32(3),
                    (SecuritySeverity)reader.GetInt32(4),
                    reader.GetString(5),
                    reader.GetString(6),
                    (SecurityAction)reader.GetInt32(7),
                    correlation));
        }

        return results;
    }
}