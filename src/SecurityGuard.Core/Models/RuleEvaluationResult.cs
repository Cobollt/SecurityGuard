using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record RuleEvaluationResult(
    bool Matched,
    RuleDecision? Decision,
    Guid? RuleId,
    string Reason)
{
    public static RuleEvaluationResult NoMatch()
    {
        return new RuleEvaluationResult(
            false,
            null,
            null,
            "No matching rule");
    }
}