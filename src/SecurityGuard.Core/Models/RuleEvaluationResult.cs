using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record RuleEvaluationResult(
    bool Matched,
    RuleDecision Decision,
    Guid? MatchedRuleId = null,
    string Reason)
{
    public static RuleEvaluationResult NoMatch()
    {
        return new RuleEvaluationResult(
            false,
            RuleDecision.Unknown,
            null,
            "No matching rule");
    }
}