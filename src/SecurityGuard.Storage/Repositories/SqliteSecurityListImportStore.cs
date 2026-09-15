using System.Globalization;
using Microsoft.Data.Sqlite;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Lists;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteSecurityListImportStore
    : ISecurityListImportStore
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteSecurityListImportStore(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory =
            connectionFactory;
    }

    public async Task<SecurityListStoreImportResult> ImportAsync(
        IReadOnlyList<SecurityRule> rules,
        IReadOnlyList<ThreatHashEntry> threatHashes,
        SecurityListImportMode mode,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            rules);

        ArgumentNullException.ThrowIfNull(
            threatHashes);

        if (mode !=
            SecurityListImportMode.Merge)
        {
            throw new NotSupportedException(
                $"Import mode is not supported: {mode}");
        }

        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var transaction =
            await connection.BeginTransactionAsync(
                cancellationToken);

        try
        {
            foreach (var rule in
                     rules)
            {
                await UpsertRuleAsync(
                    connection,
                    (SqliteTransaction)transaction,
                    rule,
                    cancellationToken);
            }

            foreach (var threatHash in
                     threatHashes)
            {
                await UpsertThreatHashAsync(
                    connection,
                    (SqliteTransaction)transaction,
                    threatHash,
                    cancellationToken);
            }

            await transaction.CommitAsync(
                cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(
                cancellationToken);

            throw;
        }

        return new SecurityListStoreImportResult(
            rules.Count,
            threatHashes.Count);
    }

    private static async Task UpsertRuleAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SecurityRule rule,
        CancellationToken cancellationToken)
    {
        await using (
            var command =
                connection.CreateCommand())
        {
            command.Transaction =
                transaction;

            command.CommandText =
                """
                INSERT INTO rules
                (
                    id,
                    name,
                    module,
                    decision,
                    scope,
                    value,
                    enabled,
                    priority,
                    created_at_utc,
                    expires_at_utc
                )
                VALUES
                (
                    $id,
                    $name,
                    $module,
                    $decision,
                    $scope,
                    $value,
                    $enabled,
                    $priority,
                    $created,
                    $expires
                )
                ON CONFLICT(id)
                DO UPDATE SET
                    name = excluded.name,
                    module = excluded.module,
                    decision = excluded.decision,
                    scope = excluded.scope,
                    value = excluded.value,
                    enabled = excluded.enabled,
                    priority = excluded.priority,
                    created_at_utc = excluded.created_at_utc,
                    expires_at_utc = excluded.expires_at_utc;
                """;

            command.Parameters.AddWithValue(
                "$id",
                rule.Id.ToString());

            command.Parameters.AddWithValue(
                "$name",
                rule.Name);

            command.Parameters.AddWithValue(
                "$module",
                (int)rule.Module);

            command.Parameters.AddWithValue(
                "$decision",
                (int)rule.Decision);

            command.Parameters.AddWithValue(
                "$scope",
                (int)rule.Scope);

            command.Parameters.AddWithValue(
                "$value",
                rule.Value);

            command.Parameters.AddWithValue(
                "$enabled",
                rule.Enabled
                    ? 1
                    : 0);

            command.Parameters.AddWithValue(
                "$priority",
                rule.Priority);

            command.Parameters.AddWithValue(
                "$created",
                rule.CreatedAtUtc
                    .ToUniversalTime()
                    .ToString(
                        "O",
                        CultureInfo.InvariantCulture));

            command.Parameters.AddWithValue(
                "$expires",
                rule.ExpiresAtUtc is null
                    ? DBNull.Value
                    : rule.ExpiresAtUtc.Value
                        .ToUniversalTime()
                        .ToString(
                            "O",
                            CultureInfo.InvariantCulture));

            await command.ExecuteNonQueryAsync(
                cancellationToken);
        }

        await using (
            var deleteConditions =
                connection.CreateCommand())
        {
            deleteConditions.Transaction =
                transaction;

            deleteConditions.CommandText =
                """
                DELETE FROM rule_conditions
                WHERE rule_id = $ruleId;
                """;

            deleteConditions.Parameters.AddWithValue(
                "$ruleId",
                rule.Id.ToString());

            await deleteConditions.ExecuteNonQueryAsync(
                cancellationToken);
        }

        var conditions =
            rule.Conditions ??
            [];

        for (var position = 0;
             position < conditions.Count;
             position++)
        {
            var condition =
                conditions[position];

            await using var command =
                connection.CreateCommand();

            command.Transaction =
                transaction;

            command.CommandText =
                """
                INSERT INTO rule_conditions
                (
                    rule_id,
                    position,
                    scope,
                    value
                )
                VALUES
                (
                    $ruleId,
                    $position,
                    $scope,
                    $value
                );
                """;

            command.Parameters.AddWithValue(
                "$ruleId",
                rule.Id.ToString());

            command.Parameters.AddWithValue(
                "$position",
                position);

            command.Parameters.AddWithValue(
                "$scope",
                (int)condition.Scope);

            command.Parameters.AddWithValue(
                "$value",
                condition.Value);

            await command.ExecuteNonQueryAsync(
                cancellationToken);
        }
    }

    private static async Task UpsertThreatHashAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ThreatHashEntry entry,
        CancellationToken cancellationToken)
    {
        await using var command =
            connection.CreateCommand();

        command.Transaction =
            transaction;

        command.CommandText =
            """
            INSERT INTO threat_hashes
            (
                sha256,
                source,
                description,
                enabled,
                created_at_utc,
                updated_at_utc
            )
            VALUES
            (
                $sha256,
                $source,
                $description,
                $enabled,
                $createdAtUtc,
                $updatedAtUtc
            )
            ON CONFLICT(sha256)
            DO UPDATE SET
                source = excluded.source,
                description = excluded.description,
                enabled = excluded.enabled,
                updated_at_utc = excluded.updated_at_utc;
            """;

        command.Parameters.AddWithValue(
            "$sha256",
            entry.Sha256
                .Trim()
                .ToUpperInvariant());

        command.Parameters.AddWithValue(
            "$source",
            entry.Source.Trim());

        command.Parameters.AddWithValue(
            "$description",
            (object?)entry.Description ??
            DBNull.Value);

        command.Parameters.AddWithValue(
            "$enabled",
            entry.Enabled
                ? 1
                : 0);

        command.Parameters.AddWithValue(
            "$createdAtUtc",
            entry.CreatedAtUtc
                .ToUniversalTime()
                .ToString(
                    "O",
                    CultureInfo.InvariantCulture));

        command.Parameters.AddWithValue(
            "$updatedAtUtc",
            entry.UpdatedAtUtc
                .ToUniversalTime()
                .ToString(
                    "O",
                    CultureInfo.InvariantCulture));

        await command.ExecuteNonQueryAsync(
            cancellationToken);
    }
}