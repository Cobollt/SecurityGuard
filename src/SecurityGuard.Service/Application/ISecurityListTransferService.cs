using SecurityGuard.Core.Lists;

namespace SecurityGuard.Service.Application;

public interface ISecurityListTransferService
{
    string ListsDirectory { get; }

    string ExportsDirectory { get; }

    string ImportsDirectory { get; }

    Task<SecurityListExportResult> ExportAsync(
        CancellationToken cancellationToken = default);

    Task<SecurityListPackageValidationResult> ValidateAsync(
        string packagePath,
        CancellationToken cancellationToken = default);

    Task<SecurityListImportResult> ImportAsync(
        string packagePath,
        SecurityListImportMode mode = SecurityListImportMode.Merge,
        CancellationToken cancellationToken = default);
}