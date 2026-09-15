namespace SecurityGuard.UI.Tests;

public sealed class UiProjectBoundaryTests
{
    [Fact]
    public void Ui_project_does_not_reference_privileged_projects()
    {
        var root =
            FindRepositoryRoot();

        var projectPath =
            Path.Combine(
                root,
                "src",
                "SecurityGuard.UI",
                "SecurityGuard.UI.csproj");

        var project =
            File.ReadAllText(
                projectPath);

        Assert.DoesNotContain(
            "SecurityGuard.Service.csproj",
            project,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "SecurityGuard.Storage.csproj",
            project,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "SecurityGuard.Infrastructure.csproj",
            project,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "SecurityGuard.AlgorithmGuard.csproj",
            project,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "SecurityGuard.TransferGuard.csproj",
            project,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "SecurityGuard.ArchiveGuard.csproj",
            project,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string FindRepositoryRoot()
    {
        var directory =
            new DirectoryInfo(
                AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (Directory.Exists(
                    Path.Combine(
                        directory.FullName,
                        "src")) &&
                Directory.Exists(
                    Path.Combine(
                        directory.FullName,
                        "tests")))
            {
                return directory.FullName;
            }

            directory =
                directory.Parent;
        }

        throw new DirectoryNotFoundException(
            "SecurityGuard repository root was not found.");
    }
}