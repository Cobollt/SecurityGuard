using SecurityGuard.Infrastructure.Configuration;
using SecurityGuard.Storage.Configuration;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Service.Tests;

internal sealed class TestEnvironment
    : IAsyncDisposable
{
    public string RootDirectory { get; }

    public SecurityGuardPaths Paths { get; }

    public SqliteConnectionFactory ConnectionFactory { get; }

    private TestEnvironment(
        string rootDirectory,
        SecurityGuardPaths paths,
        SqliteConnectionFactory connectionFactory)
    {
        RootDirectory = rootDirectory;
        Paths = paths;
        ConnectionFactory = connectionFactory;
    }

    public static Task<TestEnvironment> CreateAsync()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.Service.Tests",
                Guid.NewGuid().ToString("N"));

        var paths =
            new SecurityGuardPaths(root);

        var options =
            new StorageOptions(
                paths.DatabasePath);

        var connectionFactory =
            new SqliteConnectionFactory(options);

        return Task.FromResult(
            new TestEnvironment(
                root,
                paths,
                connectionFactory));
    }

    public ValueTask DisposeAsync()
    {
        if (Directory.Exists(RootDirectory))
        {
            Directory.Delete(
                RootDirectory,
                true);
        }

        return ValueTask.CompletedTask;
    }
}