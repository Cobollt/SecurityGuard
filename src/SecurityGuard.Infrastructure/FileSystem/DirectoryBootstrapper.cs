using SecurityGuard.Infrastructure.Configuration;

namespace SecurityGuard.Infrastructure.FileSystem;

public sealed class DirectoryBootstrapper
{
    private readonly SecurityGuardPaths _paths;
    private readonly IFileAccessProtectionService _protectionService;

    public DirectoryBootstrapper(
        SecurityGuardPaths paths,
        IFileAccessProtectionService protectionService)
    {
        _paths = paths;
        _protectionService = protectionService;
    }

    public void Initialize()
    {
        Directory.CreateDirectory(
            _paths.RootDirectory);

        Directory.CreateDirectory(
            _paths.DataDirectory);

        Directory.CreateDirectory(
            _paths.QuarantineDirectory);

        Directory.CreateDirectory(
            _paths.LogsDirectory);

        Directory.CreateDirectory(
            _paths.TempDirectory);

        _protectionService.ProtectDirectory(
            _paths.QuarantineDirectory);
    }
}