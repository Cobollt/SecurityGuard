using SecurityGuard.Core.Lists;

namespace SecurityGuard.Service.Application;

public interface ISecurityListTransferService
{
    string ListsDirectory { get; }

    string ExportsDirectory { get; }

    string ImportsDirectory { get; }

    Task<SecurityListExportResult> ExportAsync(
        CancellationToken cancellationToken = default);
}