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

    public string ConditionsDisplayName { get; }

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
        GetScopeDisplayName(
            Scope);

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

        ConditionsDisplayName =
            BuildConditionsDisplayName(
                rule.Conditions);

        DeleteCommand =
            new AsyncRelayCommand(
                () =>
                    deleteAsync(
                        rule.Id));
    }

    private static string BuildConditionsDisplayName(
        IReadOnlyList<SecurityRuleCondition>? conditions)
    {
        if (conditions is null ||
            conditions.Count == 0)
        {
            return "—";
        }

        return string.Join(
            Environment.NewLine,
            conditions.Select(
                condition =>
                    $"{GetScopeDisplayName(condition.Scope)} = {condition.Value}"));
    }

    private static string GetScopeDisplayName(
        RuleScope scope)
    {
        return scope switch
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

            RuleScope.UserName =>
                "Пользователь",

            RuleScope.ProcessPublisher =>
                "Издатель процесса",

            RuleScope.ParentProcessPath =>
                "Путь родительского процесса",

            RuleScope.RemoteAddress =>
                "Удалённый адрес",

            RuleScope.RemotePort =>
                "Удалённый порт",

            RuleScope.Protocol =>
                "Протокол",

            RuleScope.DestinationProcess =>
                "Процесс назначения",

            RuleScope.RootProcess =>
                "Исходный процесс",

            RuleScope.RootProcessPath =>
                "Путь исходного процесса",

            RuleScope.ExecutionChain =>
                "Цепочка запуска",

            RuleScope.ProcessPath =>
                "Путь процесса",

            RuleScope.FileCategory =>
                "Категория файла",

            RuleScope.TransferActivityKind =>
                "Тип активности",

            _ =>
                scope.ToString()
        };
    }
}