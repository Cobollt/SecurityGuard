using SecurityGuard.Core.Models;

namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ArchiveGuardWorkflowResult(
    ArchiveGuardScanResult ScanResult,
    SecurityDecisionRequest? DecisionRequest);