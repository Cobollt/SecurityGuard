using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteDecisionRequestRepository
    : IDecisionRequestRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteDecisionRequestRepository(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory =
            connectionFactory;
    }

    public async Task AddAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken = default)
    {
        var added =
            await TryAddAsync(
                request,
                cancellationToken);

        if (!added)
        {
            throw new InvalidOperationException(
                $"Pending decision with identity '{request.Identity}' already exists.");
        }
    }

    public async Task<bool> TryAddAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var transaction =
            await connection.BeginTransactionAsync(
                cancellationToken);

        try
        {
            await using (var command =
                         connection.CreateCommand())
            {
                command.Transaction =
                    (SqliteTransaction)transaction;

                command.CommandText =
                    """
                    INSERT INTO decision_requests
                    (
                        id,
                        module,
                        event_type,
                        title,
                        description,
                        file_path,
                        process_name,
                        available_actions_json,
                        created_at_utc
                    )
                    VALUES
                    (
                        $id,
                        $module,
                        $eventType,
                        $title,
                        $description,
                        $filePath,
                        $processName,
                        $actions,
                        $created
                    );
                    """;

                command.Parameters.AddWithValue(
                    "$id",
                    request.Id.ToString());

                command.Parameters.AddWithValue(
                    "$module",
                    (int)request.Module);

                command.Parameters.AddWithValue(
                    "$eventType",
                    (int)request.EventType);

                command.Parameters.AddWithValue(
                    "$title",
                    request.Title);

                command.Parameters.AddWithValue(
                    "$description",
                    request.Description);

                command.Parameters.AddWithValue(
                    "$filePath",
                    request.FilePath ??
                    (object)DBNull.Value);

                command.Parameters.AddWithValue(
                    "$processName",
                    request.ProcessName ??
                    (object)DBNull.Value);

                command.Parameters.AddWithValue(
                    "$actions",
                    JsonSerializer.Serialize(
                        request.AvailableActions));

                command.Parameters.AddWithValue(
                    "$created",
                    request.CreatedAtUtc.ToString("O"));

                await command.ExecuteNonQueryAsync(
                    cancellationToken);
            }

            if (request.RuleContext is not null)
            {
                await using var contextCommand =
                    connection.CreateCommand();

                contextCommand.Transaction =
                    (SqliteTransaction)transaction;

                contextCommand.CommandText =
                    """
                    INSERT INTO decision_request_contexts
                    (
                        request_id,
                        context_json
                    )
                    VALUES
                    (
                        $requestId,
                        $context
                    );
                    """;

                contextCommand.Parameters.AddWithValue(
                    "$requestId",
                    request.Id.ToString());

                contextCommand.Parameters.AddWithValue(
                    "$context",
                    JsonSerializer.Serialize(
                        request.RuleContext));

                await contextCommand.ExecuteNonQueryAsync(
                    cancellationToken);
            }

            if (!string.IsNullOrWhiteSpace(
                    request.Identity))
            {
                await using var identityCommand =
                    connection.CreateCommand();

                identityCommand.Transaction =
                    (SqliteTransaction)transaction;

                identityCommand.CommandText =
                    """
                    INSERT OR IGNORE INTO decision_request_identities
                    (
                        request_id,
                        identity
                    )
                    VALUES
                    (
                        $requestId,
                        $identity
                    );
                    """;

                identityCommand.Parameters.AddWithValue(
                    "$requestId",
                    request.Id.ToString());

                identityCommand.Parameters.AddWithValue(
                    "$identity",
                    request.Identity);

                var affected =
                    await identityCommand.ExecuteNonQueryAsync(
                        cancellationToken);

                if (affected == 0)
                {
                    await transaction.RollbackAsync(
                        cancellationToken);

                    return false;
                }
            }

            await transaction.CommitAsync(
                cancellationToken);

            return true;
        }
        catch
        {
            await transaction.RollbackAsync(
                cancellationToken);

            throw;
        }
    }

    public async Task<IReadOnlyList<SecurityDecisionRequest>> GetPendingAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            BuildSelectSql() +
            """
            ORDER BY d.created_at_utc ASC;
            """;

        return await ReadAsync(
            command,
            cancellationToken);
    }

    public async Task<SecurityDecisionRequest?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            BuildSelectSql() +
            """
            WHERE d.id = $id
            LIMIT 1;
            """;

        command.Parameters.AddWithValue(
            "$id",
            id.ToString());

        var results =
            await ReadAsync(
                command,
                cancellationToken);

        return results.FirstOrDefault();
    }

    public async Task<SecurityDecisionRequest?> GetByIdentityAsync(
        string identity,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            identity);

        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            BuildSelectSql() +
            """
            WHERE i.identity = $identity
            LIMIT 1;
            """;

        command.Parameters.AddWithValue(
            "$identity",
            identity);

        var results =
            await ReadAsync(
                command,
                cancellationToken);

        return results.FirstOrDefault();
    }

    public async Task<int> RemoveOlderThanAsync(
        DateTimeOffset cutoffUtc,
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            """
            DELETE FROM decision_requests
            WHERE created_at_utc < $cutoff;
            """;

        command.Parameters.AddWithValue(
            "$cutoff",
            cutoffUtc.ToString("O"));

        return await command.ExecuteNonQueryAsync(
            cancellationToken);
    }

    public async Task RemoveAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            """
            DELETE FROM decision_requests
            WHERE id = $id;
            """;

        command.Parameters.AddWithValue(
            "$id",
            id.ToString());

        await command.ExecuteNonQueryAsync(
            cancellationToken);
    }

    private static string BuildSelectSql()
    {
        return
            """
            SELECT
                d.id,
                d.module,
                d.event_type,
                d.title,
                d.description,
                d.file_path,
                d.process_name,
                d.available_actions_json,
                d.created_at_utc,
                c.context_json,
                i.identity
            FROM decision_requests d
            LEFT JOIN decision_request_contexts c
                ON c.request_id = d.id
            LEFT JOIN decision_request_identities i
                ON i.request_id = d.id
            """ +
            Environment.NewLine;
    }

    private static async Task<IReadOnlyList<SecurityDecisionRequest>> ReadAsync(
        SqliteCommand command,
        CancellationToken cancellationToken)
    {
        await using var reader =
            await command.ExecuteReaderAsync(
                cancellationToken);

        var results =
            new List<SecurityDecisionRequest>();

        while (await reader.ReadAsync(
                   cancellationToken))
        {
            var actions =
                JsonSerializer.Deserialize<List<SecurityAction>>(
                    reader.GetString(7)) ??
                [];

            RuleMatchContext? context =
                null;

            if (!reader.IsDBNull(9))
            {
                context =
                    JsonSerializer.Deserialize<RuleMatchContext>(
                        reader.GetString(9));
            }

            var identity =
                reader.IsDBNull(10)
                    ? null
                    : reader.GetString(10);

            results.Add(
                new SecurityDecisionRequest(
                    Guid.Parse(
                        reader.GetString(0)),
                    (SecurityModuleKind)reader.GetInt32(1),
                    (SecurityEventType)reader.GetInt32(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.IsDBNull(5)
                        ? null
                        : reader.GetString(5),
                    reader.IsDBNull(6)
                        ? null
                        : reader.GetString(6),
                    actions,
                    DateTimeOffset.Parse(
                        reader.GetString(8),
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.RoundtripKind),
                    context,
                    identity));
        }

        return results;
    }
}