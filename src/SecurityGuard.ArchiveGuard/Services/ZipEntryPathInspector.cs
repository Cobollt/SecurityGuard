using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ZipEntryPathInspector
{
    public ZipEntryPathAssessment Inspect(
        string fullName)
    {
        fullName ??=
            string.Empty;

        var path =
            fullName.Replace(
                '\\',
                '/');

        var drivePrefix =
            path.Length >= 2 &&
            char.IsAsciiLetter(
                path[0]) &&
            path[1] == ':';

        var absolute =
            path.StartsWith(
                '/',
                StringComparison.Ordinal) ||
            drivePrefix;

        var segments =
            path.Split(
                '/',
                StringSplitOptions.RemoveEmptyEntries);

        var traversal =
            segments.Any(
                segment =>
                    segment.Equals(
                        "..",
                        StringComparison.Ordinal));

        var alternateDataStream =
            false;

        for (var index = 0;
             index < segments.Length;
             index++)
        {
            var segment =
                segments[index];

            if (!segment.Contains(
                    ':'))
            {
                continue;
            }

            if (index == 0 &&
                drivePrefix)
            {
                continue;
            }

            alternateDataStream =
                true;

            break;
        }

        var normalizedSegments =
            segments
                .Where(
                    segment =>
                        !segment.Equals(
                            ".",
                            StringComparison.Ordinal))
                .Select(
                    segment =>
                        segment.TrimEnd(
                            ' ',
                            '.'))
                .Where(
                    segment =>
                        segment.Length > 0)
                .ToArray();

        var normalized =
            string.Join(
                '/',
                normalizedSegments)
            .ToUpperInvariant();

        return new ZipEntryPathAssessment(
            normalized,
            absolute,
            traversal,
            alternateDataStream);
    }
}