using SecurityGuard.AlgorithmGuard.Enums;

namespace SecurityGuard.AlgorithmGuard.Services;

public static class AlgorithmEnforcementClassifier
{
    private static readonly HashSet<string> SupportedExtensions =
        new(
            [
                ".ps1",
                ".bat",
                ".cmd",
                ".vbs",
                ".js"
            ],
            StringComparer.OrdinalIgnoreCase);

    public static AlgorithmEnforcementLevel GetLevel(
        string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return AlgorithmEnforcementLevel.Unsupported;
        }

        var extension =
            Path.GetExtension(filePath);

        if (!SupportedExtensions.Contains(extension))
        {
            return AlgorithmEnforcementLevel.Unsupported;
        }

        if (string.Equals(
                extension,
                ".ps1",
                StringComparison.OrdinalIgnoreCase))
        {
            return AlgorithmEnforcementLevel.PowerShellScript;
        }

        return AlgorithmEnforcementLevel.Blocked;
    }
}