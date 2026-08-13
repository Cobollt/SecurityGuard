namespace SecurityGuard.Infrastructure.Configuration;

public sealed record SecurityGuardPaths
{
    public string RootDirectory { get; }

    public string DataDirectory { get; }

    public string QuarantineDirectory { get; }

    public string LogsDirectory { get; }

    public string TempDirectory { get; }

    public string DatabasePath { get; }

    public SecurityGuardPaths(string rootDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);

        RootDirectory =
            Path.GetFullPath(rootDirectory);

        DataDirectory =
            Path.Combine(
                RootDirectory,
                "Data");

        QuarantineDirectory =
            Path.Combine(
                RootDirectory,
                "Quarantine");

        LogsDirectory =
            Path.Combine(
                RootDirectory,
                "Logs");

        TempDirectory =
            Path.Combine(
                RootDirectory,
                "Temp");

        DatabasePath =
            Path.Combine(
                DataDirectory,
                "securityguard.db");
    }

    public static SecurityGuardPaths CreateDefault()
    {
        var programData =
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);

        return new SecurityGuardPaths(
            Path.Combine(
                programData,
                "SecurityGuard"));
    }
}