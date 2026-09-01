using SecurityGuard.ArchiveGuard.Enums;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IFileTypeCompatibilityService
{
    bool IsCompatible(
        DetectedFileType fileType,
        string extension);
}