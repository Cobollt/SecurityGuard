using SecurityGuard.ArchiveGuard.Contracts;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardFileCandidatePolicy
    : IArchiveGuardFileCandidatePolicy
{
    private static readonly HashSet<string> TemporaryExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".crdownload",
            ".part",
            ".partial",
            ".tmp",
            ".download",
            ".opdownload",
            ".filepart"
        };

    public bool ShouldScan(
        string filePath)
    {
        if (string.IsNullOrWhiteSpace(
                filePath))
        {
            return false;
        }

        var fileName =
            Path.GetFileName(
                filePath);

        if (string.IsNullOrWhiteSpace(
                fileName))
        {
            return false;
        }

        if (fileName.StartsWith(
                "~$",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !TemporaryExtensions.Contains(
            Path.GetExtension(
                fileName));
    }
}