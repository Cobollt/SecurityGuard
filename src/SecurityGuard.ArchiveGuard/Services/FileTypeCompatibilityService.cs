using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class FileTypeCompatibilityService
    : IFileTypeCompatibilityService
{
    private static readonly HashSet<string> ZipExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".zip",
            ".docx",
            ".docm",
            ".xlsx",
            ".xlsm",
            ".pptx",
            ".pptm",
            ".jar",
            ".apk",
            ".epub",
            ".odt",
            ".ods",
            ".odp",
            ".nupkg",
            ".vsix"
        };

    private static readonly HashSet<string> PeExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".exe",
            ".dll",
            ".sys",
            ".scr",
            ".cpl",
            ".ocx",
            ".drv"
        };

    public bool IsCompatible(
        DetectedFileType fileType,
        string extension)
    {
        extension =
            NormalizeExtension(
                extension);

        return fileType switch
        {
            DetectedFileType.Unknown =>
                true,

            DetectedFileType.Zip =>
                ZipExtensions.Contains(
                    extension),

            DetectedFileType.SevenZip =>
                extension.Equals(
                    ".7z",
                    StringComparison.OrdinalIgnoreCase),

            DetectedFileType.Rar =>
                extension.Equals(
                    ".rar",
                    StringComparison.OrdinalIgnoreCase),

            DetectedFileType.Gzip =>
                extension.Equals(
                    ".gz",
                    StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(
                    ".gzip",
                    StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(
                    ".tgz",
                    StringComparison.OrdinalIgnoreCase),

            DetectedFileType.Tar =>
                extension.Equals(
                    ".tar",
                    StringComparison.OrdinalIgnoreCase),

            DetectedFileType.Pe =>
                PeExtensions.Contains(
                    extension),

            DetectedFileType.Pdf =>
                extension.Equals(
                    ".pdf",
                    StringComparison.OrdinalIgnoreCase),

            _ =>
                true
        };
    }

    private static string NormalizeExtension(
        string extension)
    {
        if (string.IsNullOrWhiteSpace(
                extension))
        {
            return string.Empty;
        }

        extension =
            extension.Trim();

        return extension.StartsWith(
                '.')
            ? extension
            : "." + extension;
    }
}