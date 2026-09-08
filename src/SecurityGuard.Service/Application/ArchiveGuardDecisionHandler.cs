using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Service.Application;

public sealed class ArchiveGuardDecisionHandler
    : ISecurityDecisionHandler
{
    private readonly IArchiveGuardDecisionExecutor _executor;

    public ArchiveGuardDecisionHandler(
        IArchiveGuardDecisionExecutor executor)
    {
        _executor =
            executor;
    }

    public SecurityModuleKind Module =>
        SecurityModuleKind.ArchiveGuard;

    public async Task HandleAsync(
        SecurityDecisionRequest request,
        SecurityAction action,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        if (request.Module !=
            SecurityModuleKind.ArchiveGuard)
        {
            throw new InvalidOperationException(
                "Decision request does not belong to ArchiveGuard.");
        }

        var result =
            await _executor.ExecuteAsync(
                request.Id,
                action,
                cancellationToken);

        if (!result.Success)
        {
            throw new InvalidOperationException(
                result.Message);
        }
    }
}