using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.UI.ViewModels;

namespace SecurityGuard.UI.Tests;

public sealed class SecurityRuleViewModelTests
{
    [Fact]
    public void Hash_rule_has_readable_names()
    {
        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Blocked script",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Block,
                RuleScope.FileHash,
                "ABC123",
                true,
                200,
                DateTimeOffset.UtcNow,
                null);

        var viewModel =
            new SecurityRuleViewModel(
                rule,
                _ =>
                    Task.CompletedTask);

        Assert.Equal(
            "Контроль алгоритмов",
            viewModel.ModuleDisplayName);

        Assert.Equal(
            "Заблокировать",
            viewModel.DecisionDisplayName);

        Assert.Equal(
            "SHA-256",
            viewModel.ScopeDisplayName);

        Assert.Equal(
            "Включено",
            viewModel.EnabledDisplayName);
    }
}