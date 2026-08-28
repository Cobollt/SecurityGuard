using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferFileClassifier
    : ITransferFileClassifier
{
    private static readonly HashSet<string> DocumentExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".pdf",
            ".doc",
            ".docx",
            ".docm",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".ppt",
            ".pptx",
            ".pptm",
            ".odt",
            ".ods",
            ".odp",
            ".rtf",
            ".txt",
            ".md",
            ".epub"
        };

    private static readonly HashSet<string> ArchiveExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".zip",
            ".7z",
            ".rar",
            ".tar",
            ".gz",
            ".bz2",
            ".xz",
            ".tgz",
            ".cab",
            ".iso"
        };

    private static readonly HashSet<string> ImageExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".webp",
            ".tif",
            ".tiff",
            ".heic",
            ".svg"
        };

    private static readonly HashSet<string> VideoExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".mp4",
            ".mkv",
            ".mov",
            ".avi",
            ".wmv",
            ".webm",
            ".m4v"
        };

    private static readonly HashSet<string> AudioExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".mp3",
            ".wav",
            ".flac",
            ".aac",
            ".m4a",
            ".ogg",
            ".opus"
        };

    private static readonly HashSet<string> SourceExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".cs",
            ".fs",
            ".vb",
            ".cpp",
            ".c",
            ".h",
            ".hpp",
            ".py",
            ".pyw",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".kt",
            ".kts",
            ".swift",
            ".go",
            ".rs",
            ".php",
            ".rb",
            ".ps1",
            ".bat",
            ".cmd",
            ".vbs",
            ".wsf",
            ".sh",
            ".sql"
        };

    private static readonly HashSet<string> StructuredDataExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".json",
            ".xml",
            ".yaml",
            ".yml",
            ".csv",
            ".tsv",
            ".toml",
            ".ini",
            ".conf",
            ".config",
            ".env"
        };

    private static readonly HashSet<string> DatabaseExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".db",
            ".sqlite",
            ".sqlite3",
            ".mdb",
            ".accdb",
            ".pst",
            ".ost"
        };

    private static readonly HashSet<string> ExecutableExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".exe",
            ".msi",
            ".msix",
            ".appx",
            ".scr",
            ".com"
        };

    private static readonly HashSet<string> LibraryExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".dll",
            ".sys",
            ".ocx",
            ".drv",
            ".cpl",
            ".pdb",
            ".mui"
        };

    private static readonly HashSet<string> LogExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".log",
            ".evtx"
        };

    private static readonly HashSet<string> TemporaryExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".tmp",
            ".temp",
            ".dmp",
            ".etl",
            ".partial",
            ".part",
            ".crdownload"
        };

    public TransferFileClassification Classify(
        string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        var path =
            filePath
                .Trim()
                .Replace(
                    '/',
                    '\\');

        var extension =
            Path.GetExtension(
                path);

        if (IsCachePath(
                path))
        {
            return new TransferFileClassification(
                TransferFileCategory.Cache,
                TransferFilePriority.Ignore,
                "Application cache path");
        }

        if (IsTemporaryPath(
                path,
                extension))
        {
            return new TransferFileClassification(
                TransferFileCategory.Temporary,
                TransferFilePriority.Ignore,
                "Temporary file");
        }

        if (IsWindowsSystemPath(
                path))
        {
            return new TransferFileClassification(
                TransferFileCategory.System,
                TransferFilePriority.Ignore,
                "Windows system path");
        }

        var category =
            GetCategory(
                extension);

        var priority =
            GetBasePriority(
                category);

        if (IsProgramLocation(
                path))
        {
            priority =
                LimitPriority(
                    priority,
                    TransferFilePriority.Low);
        }

        if (IsUserDataLocation(
                path))
        {
            priority =
                BoostUserDataPriority(
                    category,
                    priority);
        }

        return new TransferFileClassification(
            category,
            priority,
            BuildReason(
                category,
                priority,
                path));
    }

    private static TransferFileCategory GetCategory(
        string extension)
    {
        if (DocumentExtensions.Contains(
                extension))
        {
            return TransferFileCategory.Document;
        }

        if (ArchiveExtensions.Contains(
                extension))
        {
            return TransferFileCategory.Archive;
        }

        if (ImageExtensions.Contains(
                extension))
        {
            return TransferFileCategory.Image;
        }

        if (VideoExtensions.Contains(
                extension))
        {
            return TransferFileCategory.Video;
        }

        if (AudioExtensions.Contains(
                extension))
        {
            return TransferFileCategory.Audio;
        }

        if (SourceExtensions.Contains(
                extension))
        {
            return TransferFileCategory.SourceCode;
        }

        if (StructuredDataExtensions.Contains(
                extension))
        {
            return TransferFileCategory.StructuredData;
        }

        if (DatabaseExtensions.Contains(
                extension))
        {
            return TransferFileCategory.Database;
        }

        if (ExecutableExtensions.Contains(
                extension))
        {
            return TransferFileCategory.Executable;
        }

        if (LibraryExtensions.Contains(
                extension))
        {
            return TransferFileCategory.Library;
        }

        if (LogExtensions.Contains(
                extension))
        {
            return TransferFileCategory.Log;
        }

        return TransferFileCategory.Unknown;
    }

    private static TransferFilePriority GetBasePriority(
        TransferFileCategory category)
    {
        return category switch
        {
            TransferFileCategory.Document =>
                TransferFilePriority.High,

            TransferFileCategory.Archive =>
                TransferFilePriority.High,

            TransferFileCategory.Image =>
                TransferFilePriority.High,

            TransferFileCategory.Video =>
                TransferFilePriority.High,

            TransferFileCategory.Audio =>
                TransferFilePriority.High,

            TransferFileCategory.SourceCode =>
                TransferFilePriority.High,

            TransferFileCategory.StructuredData =>
                TransferFilePriority.Medium,

            TransferFileCategory.Database =>
                TransferFilePriority.Medium,

            TransferFileCategory.Executable =>
                TransferFilePriority.Medium,

            TransferFileCategory.Library =>
                TransferFilePriority.Low,

            TransferFileCategory.Log =>
                TransferFilePriority.Low,

            _ =>
                TransferFilePriority.Low
        };
    }

    private static TransferFilePriority BoostUserDataPriority(
        TransferFileCategory category,
        TransferFilePriority current)
    {
        return category switch
        {
            TransferFileCategory.Database =>
                TransferFilePriority.High,

            TransferFileCategory.StructuredData =>
                TransferFilePriority.High,

            TransferFileCategory.Unknown =>
                TransferFilePriority.Medium,

            TransferFileCategory.Executable =>
                TransferFilePriority.Medium,

            TransferFileCategory.Library =>
                TransferFilePriority.Medium,

            TransferFileCategory.Log =>
                TransferFilePriority.Medium,

            _ =>
                current
        };
    }

    private static TransferFilePriority LimitPriority(
        TransferFilePriority value,
        TransferFilePriority maximum)
    {
        return (TransferFilePriority)Math.Min(
            (int)value,
            (int)maximum);
    }

    private static bool IsWindowsSystemPath(
        string path)
    {
        return IsRootFolder(
            path,
            "Windows");
    }

    private static bool IsProgramLocation(
        string path)
    {
        return IsRootFolder(
                   path,
                   "Program Files") ||
               IsRootFolder(
                   path,
                   "Program Files (x86)") ||
               IsRootFolder(
                   path,
                   "ProgramData");
    }

    private static bool IsRootFolder(
        string path,
        string folder)
    {
        string? root;

        try
        {
            root =
                Path.GetPathRoot(
                    path);
        }
        catch
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(
                root) ||
            path.Length <=
            root.Length)
        {
            return false;
        }

        var relative =
            path[root.Length..];

        return relative.Equals(
                   folder,
                   StringComparison.OrdinalIgnoreCase) ||
               relative.StartsWith(
                   folder + "\\",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTemporaryPath(
        string path,
        string extension)
    {
        if (TemporaryExtensions.Contains(
                extension))
        {
            return true;
        }

        var name =
            Path.GetFileName(
                path);

        if (name.StartsWith(
                "~$",
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return path.Contains(
                   @"\AppData\Local\Temp\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\Windows\Temp\",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCachePath(
        string path)
    {
        if (!path.Contains(
                @"\AppData\",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return path.Contains(
                   @"\Cache\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\Code Cache\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\GPUCache\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\INetCache\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\LocalCache\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\CrashDumps\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\CacheStorage\",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUserDataLocation(
        string path)
    {
        if (!path.Contains(
                @"\Users\",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return path.Contains(
                   @"\Desktop\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\Documents\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\Downloads\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\Pictures\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\Videos\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\Music\",
                   StringComparison.OrdinalIgnoreCase) ||
               path.Contains(
                   @"\OneDrive",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildReason(
        TransferFileCategory category,
        TransferFilePriority priority,
        string path)
    {
        if (IsUserDataLocation(
                path))
        {
            return $"User data location; category={category}; priority={priority}";
        }

        if (IsProgramLocation(
                path))
        {
            return $"Program location; category={category}; priority={priority}";
        }

        return $"Category={category}; priority={priority}";
    }
}