using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferEnforcementRuleFactoryTests
{
    [Fact]
    public void Complete_block_rule_is_projected()
    {
        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Block client",
                SecurityModuleKind.TransferGuard,
                RuleDecision.Block,
                RuleScope.ProcessPath,
                @"C:\Apps\client.exe",
                true,
                200,
                DateTimeOffset.UtcNow,
                null,
                [
                    new SecurityRuleCondition(
                        RuleScope.RemoteAddress,
                        "1.1.1.1"),

                    new SecurityRuleCondition(
                        RuleScope.RemotePort,
                        "443"),

                    new SecurityRuleCondition(
                        RuleScope.Protocol,
                        "Tcp")
                ]);

        var factory =
            new TransferEnforcementRuleFactory(
                new FakePathNormalizer());

        var created =
            factory.TryCreate(
                rule,
                out var enforcement,
                out var error);

        Assert.True(
            created,
            error);

        Assert.NotNull(
            enforcement);

        Assert.Equal(
            rule.Id,
            enforcement.SecurityRuleId);

        Assert.Equal(
            @"C:\Apps\client.exe",
            enforcement.ProgramPath);

        Assert.Equal(
            "1.1.1.1",
            enforcement.RemoteAddress);

        Assert.Equal(
            443,
            enforcement.RemotePort);

        Assert.Equal(
            TransferProtocol.Tcp,
            enforcement.Protocol);
    }

    private sealed class FakePathNormalizer
        : ITransferPathNormalizer
    {
        public string? Normalize(
            string? path)
        {
            return path;
        }
    }

    [Fact]
    public void File_transfer_rule_is_not_projected_to_firewall()
    {
        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Block report",
                SecurityModuleKind.TransferGuard,
                RuleDecision.Block,
                RuleScope.FileHash,
                "ABC123",
                true,
                250,
                DateTimeOffset.UtcNow,
                null,
                [
                    new SecurityRuleCondition(
                        RuleScope.ProcessPath,
                        @"C:\Apps\client.exe"),

                    new SecurityRuleCondition(
                        RuleScope.RemoteAddress,
                        "1.1.1.1"),

                    new SecurityRuleCondition(
                        RuleScope.RemotePort,
                        "443"),

                    new SecurityRuleCondition(
                        RuleScope.Protocol,
                        "Tcp")
                ]);

        var factory =
            new TransferEnforcementRuleFactory(
                new FakePathNormalizer());

        var created =
            factory.TryCreate(
                rule,
                out var result,
                out var error);

        Assert.False(
            created);

        Assert.Null(
            result);

        Assert.NotNull(
            error);
    }
}