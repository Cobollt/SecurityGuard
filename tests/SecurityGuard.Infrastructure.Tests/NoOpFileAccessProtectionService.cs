using SecurityGuard.Infrastructure.FileSystem;

namespace SecurityGuard.Infrastructure.Tests;

internal sealed class NoOpFileAccessProtectionService
    : IFileAccessProtectionService
{
    public void ProtectDirectory(string path)
    {
    }

    public void ProtectFile(string path)
    {
    }
}