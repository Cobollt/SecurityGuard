using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteProtectedObjectRepository
    : IProtectedObjectRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteProtectedObjectRepository(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public Task<ProtectedObject?> FindByHashAsync(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        return FindAsync(
            "sha256",
            sha256,
            cancellationToken);
    }

    public Task<ProtectedObject?> FindByPathAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        return FindAsync(
            "path",
            path,
            cancellationToken);
    }

    public async Task UpsertAsync(
        ProtectedObject protectedObject,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(protectedObject);

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            INSERT INTO protected_objects
            (
                id,
                path,
                file_name,
                extension,
                sha256,
                size_bytes,
                trust_status,
                first_seen_at_utc,
                last_seen_at_utc
            )
            VALUES
            (
                $id,
                $path,
                $fileName,
                $extension,
                $sha256,
                $size,
                $status,
                $firstSeen,
                $lastSeen
            )
            ON CONFLICT(sha256)
            DO UPDATE SET
                path = excluded.path,
                file_name = excluded.file_name,
                extension = excluded.extension,
                size_bytes = excluded.size_bytes,
                trust_status = excluded.trust_status,
                last_seen_at_utc = excluded.last_seen_at_utc;
            """;

        command.Parameters.AddWithValue(
            "$id",
            protectedObject.Id.ToString());

        command.Parameters.AddWithValue(
            "$path",
            protectedObject.Path);

        command.Parameters.AddWithValue(
            "$fileName",
            protectedObject.FileName);

        command.Parameters.AddWithValue(
            "$extension",
            protectedObject.Extension);

        command.Parameters.AddWithValue(
            "$sha256",
            protectedObject.Sha256);

        command.Parameters.AddWithValue(
            "$size",
            protectedObject.SizeBytes);

        command.Parameters.AddWithValue(
            "$status",
            (int)protectedObject.TrustStatus);

        command.Parameters.AddWithValue(
            "$firstSeen",
            protectedObject.FirstSeenAtUtc.ToString("O"));

        command.Parameters.AddWithValue(
            "$lastSeen",
            protectedObject.LastSeenAtUtc.ToString("O"));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<ProtectedObject?> FindAsync(
        string column,
        string value,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        if (column is not "sha256" and not "path")
        {
            throw new ArgumentOutOfRangeException(nameof(column));
        }

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            $"""
            SELECT
                id,
                path,
                file_name,
                extension,
                sha256,
                size_bytes,
                trust_status,
                first_seen_at_utc,
                last_seen_at_utc
            FROM protected_objects
            WHERE {column} = $value
            LIMIT 1;
            """;

        command.Parameters.AddWithValue(
            "$value",
            value);

        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new ProtectedObject(
            Guid.Parse(reader.GetString(0)),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetInt64(5),
            (ObjectTrustStatus)reader.GetInt32(6),
            DateTimeOffset.Parse(reader.GetString(7)),
            DateTimeOffset.Parse(reader.GetString(8)));
    }
}