using System.Windows.Input;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.UI.ViewModels;

public sealed class SecurityRuleViewModel
{
    public Guid Id { get; }

    public string Name { get; }

    public SecurityModuleKind Module { get; }

    public RuleDecision Decision { get; }

    public RuleScope Scope { get; }

    public string Value { get; }

    public bool Enabled { get; }

    public int Priority { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset? ExpiresAtUtc { get; }

    public string ModuleDisplayName =>
        Module switch
        {
            SecurityModuleKind.Core =>
                "Ядро",

            SecurityModuleKind.AlgorithmGuard =>
                "Контроль алгоритмов",

            SecurityModuleKind.TransferGuard =>
                "Передача файлов",

            SecurityModuleKind.ArchiveGuard =>
                "Проверка архивов",

            _ =>
                Module.ToString()
        };

    public string DecisionDisplayName =>
        Decision switch
        {
            RuleDecision.Allow =>
                "Разрешить",

            RuleDecision.Block =>
                "Заблокировать",

            _ =>
                Decision.ToString()
        };

    public string ScopeDisplayName =>
        Scope switch
        {
            RuleScope.FileHash =>
                "SHA-256",

            RuleScope.FilePath =>
                "Путь",

            RuleScope.FileName =>
                "Имя файла",

            RuleScope.FileExtension =>
                "Расширение",

            RuleScope.Publisher =>
                "Издатель",

            RuleScope.Process =>
                "Процесс",

            RuleScope.ParentProcess =>
                "Родительский процесс",

            RuleScope.Interpreter =>
                "Интерпретатор",

            RuleScope.CommandLine =>
                "Командная строка",

            RuleScope.RemoteAddress =>
                "Удалённый адрес",

            RuleScope.RemotePort =>
                "Удалённый порт",

            RuleScope.Protocol =>
                "Протокол",

            RuleScope.DestinationProcess =>
                "Процесс назначения",

            _ =>
                Scope.ToString()
        };

    public string EnabledDisplayName =>
        Enabled
            ? "Включено"
            : "Отключено";

    public ICommand DeleteCommand { get; }

    public SecurityRuleViewModel(
        SecurityRule rule,
        Func<Guid, Task> deleteAsync)
    {
        Id =
            rule.Id;

        Name =
            rule.Name;

        Module =
            rule.Module;

        Decision =
            rule.Decision;

        Scope =
            rule.Scope;

        Value =
            rule.Value;

        Enabled =
            rule.Enabled;

        Priority =
            rule.Priority;

        CreatedAtUtc =
            rule.CreatedAtUtc;

        ExpiresAtUtc =
            rule.ExpiresAtUtc;

        DeleteCommand =
            new AsyncRelayCommand(
                () =>
                    deleteAsync(
                        rule.Id));
    }
}