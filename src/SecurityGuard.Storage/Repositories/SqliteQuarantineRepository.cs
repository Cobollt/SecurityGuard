using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteQuarantineRepository
    : IQuarantineRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteQuarantineRepository(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task AddAsync(
        QuarantineRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            INSERT INTO quarantine
            (
                id,
                original_path,
                stored_path,
                original_file_name,
                sha256,
                size_bytes,
                source_module,
                reason,
                quarantined_at_utc
            )
            VALUES
            (
                $id,
                $originalPath,
                $storedPath,
                $fileName,
                $sha256,
                $size,
                $module,
                $reason,
                $date
            );
            """;

        command.Parameters.AddWithValue("$id", record.Id.ToString());
        command.Parameters.AddWithValue("$originalPath", record.OriginalPath);
        command.Parameters.AddWithValue("$storedPath", record.StoredPath);
        command.Parameters.AddWithValue("$fileName", record.OriginalFileName);
        command.Parameters.AddWithValue("$sha256", record.Sha256);
        command.Parameters.AddWithValue("$size", record.SizeBytes);
        command.Parameters.AddWithValue("$module", record.SourceModule);
        command.Parameters.AddWithValue("$reason", record.Reason);
        command.Parameters.AddWithValue(
            "$date",
            record.QuarantinedAtUtc.ToString("O"));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                id,
                original_path,
                stored_path,
                original_file_name,
                sha256,
                size_bytes,
                source_module,
                reason,
                quarantined_at_utc
            FROM quarantine
            ORDER BY quarantined_at_utc DESC;
            """;

        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken);

        var results = new List<QuarantineRecord>();

        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(ReadRecord(reader));
        }

        return results;
    }

    public async Task<QuarantineRecord?> GetByIdAsync(
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
                original_path,
                stored_path,
                original_file_name,
                sha256,
                size_bytes,
                source_module,
                reason,
                quarantined_at_utc
            FROM quarantine
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

        return ReadRecord(reader);
    }

    public async Task DeleteAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            "DELETE FROM quarantine WHERE id = $id;";

        command.Parameters.AddWithValue(
            "$id",
            id.ToString());

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static QuarantineRecord ReadRecord(
        Microsoft.Data.Sqlite.SqliteDataReader reader)
    {
        return new QuarantineRecord(
            Guid.Parse(reader.GetString(0)),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetInt64(5),
            reader.GetString(6),
            reader.GetString(7),
            DateTimeOffset.Parse(reader.GetString(8)));
    }
}