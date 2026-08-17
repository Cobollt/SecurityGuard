using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Service.Tests;

internal sealed class FakeSecurityDecisionHandler
    : ISecurityDecisionHandler
{
    public SecurityModuleKind Module =>
        SecurityModuleKind.AlgorithmGuard;

    public bool WasCalled { get; private set; }

    public SecurityDecision? Decision { get; private set; }

    public Task HandleAsync(
        SecurityDecisionRequest request,
        SecurityDecision decision,
        CancellationToken cancellationToken = default)
    {
        WasCalled = true;
        Decision = decision;

        return Task.CompletedTask;
    }
}