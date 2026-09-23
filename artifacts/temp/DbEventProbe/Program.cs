using Microsoft.Data.Sqlite;

var connectionString =
    new SqliteConnectionStringBuilder
    {
        DataSource =
            @"C:\ProgramData\SecurityGuard\Data\securityguard.db",
        Mode = SqliteOpenMode.ReadOnly
    }.ToString();

await using var connection =
    new SqliteConnection(
        connectionString);

await connection.OpenAsync();

await using var command =
    connection.CreateCommand();

command.CommandText =
    """
    SELECT details
    FROM security_events
    WHERE title = 'Possible file transfer correlation'
      AND created_at_utc >= '2026-09-22T14:30:00+00:00'
    ORDER BY created_at_utc DESC;
    """;

await using var reader =
    await command.ExecuteReaderAsync();

var groups =
    new Dictionary<string, int>(
        StringComparer.OrdinalIgnoreCase);

while (await reader.ReadAsync())
{
    var details =
        reader.IsDBNull(0)
            ? string.Empty
            : reader.GetString(0);

    var lines =
        details.Split(
            Environment.NewLine,
            StringSplitOptions.RemoveEmptyEntries);

    var confidence =
        lines.FirstOrDefault(
            x => x.StartsWith(
                "Confidence: ",
                StringComparison.OrdinalIgnoreCase))
        ?? "Confidence: Unknown";

    var priority =
        lines.FirstOrDefault(
            x => x.StartsWith(
                "File priority: ",
                StringComparison.OrdinalIgnoreCase))
        ?? "File priority: Unknown";

    var process =
        lines.FirstOrDefault(
            x => x.StartsWith(
                "Process: ",
                StringComparison.OrdinalIgnoreCase))
        ?? "Process: Unknown";

    var file =
        lines.FirstOrDefault(
            x => x.StartsWith(
                "File: ",
                StringComparison.OrdinalIgnoreCase))
        ?? "File: Unknown";

    var key =
        $"{confidence} | {priority} | {process} | {file}";

    groups[key] =
        groups.TryGetValue(
            key,
            out var count)
            ? count + 1
            : 1;
}

foreach (var item in groups
             .OrderByDescending(x => x.Value))
{
    Console.WriteLine(
        $"{item.Value,3} | {item.Key}");
}
