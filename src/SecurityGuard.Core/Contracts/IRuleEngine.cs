using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IRuleEngine
{
    Task<RuleEvaluationResult> EvaluateAsync(
        SecurityModuleKind module,
        RuleMatchContext context,
        CancellationToken cancellationToken = default);
}