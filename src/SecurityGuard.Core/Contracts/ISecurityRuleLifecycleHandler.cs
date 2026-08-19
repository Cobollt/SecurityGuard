using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface ISecurityRuleLifecycleHandler
{
    SecurityModuleKind Module { get; }

    Task BeforeDeleteAsync(
        SecurityRule rule,
        CancellationToken cancellationToken = default);
}