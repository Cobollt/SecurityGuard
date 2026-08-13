using System.Text.Json;
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
        _connectionFactory = connectionFactory;
    }

    public async Task AddAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

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
            request.FilePath ?? (object)DBNull.Value);

        command.Parameters.AddWithValue(
            "$processName",
            request.ProcessName ?? (object)DBNull.Value);

        command.Parameters.AddWithValue(
            "$actions",
            JsonSerializer.Serialize(request.AvailableActions));

        command.Parameters.AddWithValue(
            "$created",
            request.CreatedAtUtc.ToString("O"));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<SecurityDecisionRequest>>
        GetPendingAsync(
            CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                id,
                module,
                event_type,
                title,
                description,
                file_path,
                process_name,
                available_actions_json,
                created_at_utc
            FROM decision_requests
            ORDER BY created_at_utc ASC;
            """;

        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken);

        var results =
            new List<SecurityDecisionRequest>();

        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(ReadRequest(reader));
        }

        return results;
    }

    public async Task<SecurityDecisionRequest?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                id,
                module,
                event_type,
                title,
                description,
                file_path,
                process_name,
                available_actions_json,
                created_at_utc
            FROM decision_requests
            WHERE id = $id
            LIMIT 1;
            """;

        command.Parameters.AddWithValue(
            "$id",
            id.ToString());

        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return ReadRequest(reader);
    }

    public async Task RemoveAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            "DELETE FROM decision_requests WHERE id = $id;";

        command.Parameters.AddWithValue(
            "$id",
            id.ToString());

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static SecurityDecisionRequest ReadRequest(
        Microsoft.Data.Sqlite.SqliteDataReader reader)
    {
        var actions =
            JsonSerializer.Deserialize<List<SecurityAction>>(
                reader.GetString(7)) ?? [];

        return new SecurityDecisionRequest(
            Guid.Parse(reader.GetString(0)),
            (SecurityModuleKind)reader.GetInt32(1),
            (SecurityEventType)reader.GetInt32(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5),
            reader.IsDBNull(6) ? null : reader.GetString(6),
            actions,
            DateTimeOffset.Parse(reader.GetString(8)));
    }
}