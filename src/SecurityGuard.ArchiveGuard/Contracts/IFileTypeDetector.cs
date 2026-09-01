using SecurityGuard.ArchiveGuard.Enums;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IFileTypeDetector
{
    DetectedFileType Detect(
        ReadOnlySpan<byte> header);
}