using System.Collections.ObjectModel;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.UI.ViewModels;

public sealed class DecisionRequestViewModel
{
    public Guid Id { get; }

    public SecurityModuleKind ModuleKind { get; }

    public string Module =>
        ModuleKind.ToString();

    public string Title { get; }

    public string Description { get; }

    public string? FilePath { get; }

    public string? ProcessName { get; }

    public string? ProcessPath { get; }

    public string? ParentProcess { get; }

    public string? ParentProcessPath { get; }

    public string? ExecutionChain { get; }

    public string? CommandLine { get; }

    public string? ProcessPathText =>
        Format(
            "Путь процесса",
            ProcessPath);

    public string? InitiatorText =>
        Format(
            "Запустил",
            ParentProcess);

    public string? InitiatorPathText =>
        Format(
            "Путь инициатора",
            ParentProcessPath);

    public string? ExecutionChainText =>
        Format(
            "Цепочка запуска",
            ExecutionChain);

    public string? CommandLineText =>
        Format(
            "Команда",
            CommandLine);

    public bool HasProcessPath =>
        !string.IsNullOrWhiteSpace(
            ProcessPath);

    public bool HasInitiator =>
        !string.IsNullOrWhiteSpace(
            ParentProcess);

    public bool HasInitiatorPath =>
        !string.IsNullOrWhiteSpace(
            ParentProcessPath);

    public bool HasExecutionChain =>
        !string.IsNullOrWhiteSpace(
            ExecutionChain);

    public bool HasCommandLine =>
        !string.IsNullOrWhiteSpace(
            CommandLine);

    public DateTimeOffset CreatedAtUtc { get; }

    public ObservableCollection<DecisionActionViewModel> Actions { get; }

    public DecisionRequestViewModel(
        SecurityDecisionRequest request,
        Func<Guid, SecurityAction, Task> submitAsync)
    {
        Id =
            request.Id;

        ModuleKind =
            request.Module;

        Title =
            request.Title;

        Description =
            request.Description;

        FilePath =
            request.FilePath;

        ProcessName =
            request.ProcessName;

        ProcessPath =
            request.RuleContext?.ProcessPath;

        ParentProcess =
            request.RuleContext?.ParentProcess;

        ParentProcessPath =
            request.RuleContext?.ParentProcessPath;

        ExecutionChain =
            request.RuleContext?.ExecutionChain;

        CommandLine =
            request.RuleContext?.CommandLine;

        CreatedAtUtc =
            request.CreatedAtUtc;

        Actions =
            new ObservableCollection<DecisionActionViewModel>(
                request.AvailableActions.Select(
                    action =>
                        new DecisionActionViewModel(
                            action,
                            selectedAction =>
                                submitAsync(
                                    request.Id,
                                    selectedAction))));
    }

    private static string? Format(
        string title,
        string? value)
    {
        if (string.IsNullOrWhiteSpace(
                value))
        {
            return null;
        }

        return $"{title}: {value}";
    }
}