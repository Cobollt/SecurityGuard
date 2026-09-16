using SecurityGuard.Core.Lists;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface ISecurityListImportStore
{
    Task<SecurityListStoreImportResult> ImportAsync(
        IReadOnlyList<SecurityRule> rules,
        IReadOnlyList<ThreatHashEntry> threatHashes,
        SecurityListImportMode mode,
        SecurityListImportRecord importRecord,
        CancellationToken cancellationToken = default);
}