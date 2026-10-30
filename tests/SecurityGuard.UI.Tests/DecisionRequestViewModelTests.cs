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

    [Fact]
    public void Execution_context_is_exposed_for_display()
    {
        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Неизвестный запуск алгоритма",
                "cmd.exe /c powershell.exe -Command Get-Process",
                null,
                "cmd.exe",
                [
                    SecurityAction.AllowOnce,
                SecurityAction.Block
                ],
                DateTimeOffset.UtcNow,
                new RuleMatchContext(
                    Process:
                        "cmd.exe",
                    ParentProcess:
                        "TestApp.exe",
                    CommandLine:
                        "cmd.exe /c powershell.exe -Command Get-Process",
                    ParentProcessPath:
                        @"C:\Program Files\TestApp\TestApp.exe",
                    ExecutionChain:
                        "explorer.exe > TestApp.exe > cmd.exe",
                    ProcessPath:
                        @"C:\Windows\System32\cmd.exe"));

        var viewModel =
            new DecisionRequestViewModel(
                request,
                (_, _) =>
                    Task.CompletedTask);

        Assert.Equal(
            @"C:\Windows\System32\cmd.exe",
            viewModel.ProcessPath);

        Assert.Equal(
            "TestApp.exe",
            viewModel.ParentProcess);

        Assert.Equal(
            @"C:\Program Files\TestApp\TestApp.exe",
            viewModel.ParentProcessPath);

        Assert.Equal(
            "explorer.exe > TestApp.exe > cmd.exe",
            viewModel.ExecutionChain);

        Assert.Equal(
            "cmd.exe /c powershell.exe -Command Get-Process",
            viewModel.CommandLine);

        Assert.True(
            viewModel.HasInitiator);

        Assert.True(
            viewModel.HasInitiatorPath);

        Assert.True(
            viewModel.HasExecutionChain);

        Assert.True(
            viewModel.HasCommandLine);
    }
}