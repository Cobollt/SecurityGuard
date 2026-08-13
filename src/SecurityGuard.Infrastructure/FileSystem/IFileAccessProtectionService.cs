namespace SecurityGuard.Infrastructure.FileSystem;

public interface IFileAccessProtectionService
{
    void ProtectDirectory(string path);

    void ProtectFile(string path);
}