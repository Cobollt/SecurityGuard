using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IPeStaticAnalyzer
{
    Task<PeStaticAnalysisResult> AnalyzeAsync(
        Stream stream,
        string logicalPath,
        CancellationToken cancellationToken = default);
}