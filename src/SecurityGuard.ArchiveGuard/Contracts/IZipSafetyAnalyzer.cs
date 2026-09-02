using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IZipSafetyAnalyzer
{
    Task<ZipSafetyAssessment> AnalyzeAsync(
        string filePath,
        CancellationToken cancellationToken = default);
}