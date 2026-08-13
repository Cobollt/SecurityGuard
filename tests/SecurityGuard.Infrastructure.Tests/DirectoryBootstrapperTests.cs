using SecurityGuard.Infrastructure.Configuration;
using SecurityGuard.Infrastructure.FileSystem;

namespace SecurityGuard.Infrastructure.Tests;

public sealed class DirectoryBootstrapperTests
{
    [Fact]
    public void Required_directories_are_created()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                Guid.NewGuid().ToString("N"));

        try
        {
            var paths =
                new SecurityGuardPaths(root);

            var bootstrapper =
                new DirectoryBootstrapper(
                    paths,
                    new NoOpFileAccessProtectionService());

            bootstrapper.Initialize();

            Assert.True(
                Directory.Exists(paths.RootDirectory));

            Assert.True(
                Directory.Exists(paths.DataDirectory));

            Assert.True(
                Directory.Exists(paths.QuarantineDirectory));

            Assert.True(
                Directory.Exists(paths.LogsDirectory));

            Assert.True(
                Directory.Exists(paths.TempDirectory));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(
                    root,
                    true);
            }
        }
    }
}