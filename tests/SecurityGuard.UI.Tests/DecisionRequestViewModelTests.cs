using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.UI.ViewModels;

namespace SecurityGuard.UI.Tests;

public sealed class DecisionRequestViewModelTests
{
    [Fact]
    public void Actions_are_created_from_request()
    {
        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Script blocked",
                "Unknown script",
                @"C:\Temp\test.ps1",
                "powershell.exe",
                [
                    SecurityAction.AllowOnce,
                    SecurityAction.Allow,
                    SecurityAction.Quarantine,
                    SecurityAction.Delete
                ],
                DateTimeOffset.UtcNow);

        var viewModel =
            new DecisionRequestViewModel(
                request,
                (_, _) =>
                    Task.CompletedTask);

        Assert.Equal(
            4,
            viewModel.Actions.Count);

        Assert.Contains(
            viewModel.Actions,
            item =>
                item.Action ==
                SecurityAction.AllowOnce);

        Assert.Contains(
            viewModel.Actions,
            item =>
                item.Action ==
                SecurityAction.Quarantine);

        Assert.Contains(
            viewModel.Actions,
            item =>
                item.Action ==
                SecurityAction.Delete);
    }

    [Fact]
    public async Task Selected_action_is_forwarded()
    {
        Guid? receivedId = null;
        SecurityAction? receivedAction = null;

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Script blocked",
                "Unknown script",
                @"C:\Temp\test.ps1",
                "powershell.exe",
                [
                    SecurityAction.Quarantine
                ],
                DateTimeOffset.UtcNow);

        var viewModel =
            new DecisionRequestViewModel(
                request,
                (id, action) =>
                {
                    receivedId = id;
                    receivedAction = action;

                    return Task.CompletedTask;
                });

        var action =
            Assert.Single(
                viewModel.Actions);

        action.Command.Execute(null);

        await Task.Delay(50);

        Assert.Equal(
            request.Id,
            receivedId);

        Assert.Equal(
            SecurityAction.Quarantine,
            receivedAction);
    }
}