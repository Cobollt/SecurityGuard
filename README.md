# SecurityGuard

SecurityGuard — локальное приложение безопасности для Windows, предназначенное для контроля выполнения скриптов и процессов, исходящих операций передачи данных, а также проверки файлов и архивов.

Проект состоит из Windows Service, выполняющего защитную логику с системными правами, и отдельного WPF-интерфейса для пользователя.

## Возможности

SecurityGuard включает следующие основные модули:

* AlgorithmGuard — контроль выполнения скриптов и потенциально нежелательных алгоритмов.
* TransferGuard — контроль исходящих операций передачи файлов и сетевой активности.
* ArchiveGuard — проверка файлов и архивов.
* Quarantine — изоляция подозрительных объектов.
* Rules and Exceptions — правила разрешений, блокировок и исключений.
* Security Lists — импорт и экспорт списков SecurityGuard.
* Security Events — журнал событий безопасности.
* Windows Service — выполнение защитной логики независимо от пользовательского интерфейса.
* WPF UI — единый интерфейс управления SecurityGuard.

## Архитектура

Основные проекты:

```text
src/
├── SecurityGuard.Core
├── SecurityGuard.Infrastructure
├── SecurityGuard.Storage
├── SecurityGuard.AlgorithmGuard
├── SecurityGuard.TransferGuard
├── SecurityGuard.ArchiveGuard
├── SecurityGuard.Service
└── SecurityGuard.UI
```

Защитные операции выполняются в:

```text
SecurityGuard.Service
```

Пользовательский интерфейс:

```text
SecurityGuard.UI
```

UI взаимодействует со службой через IPC и не выполняет привилегированные защитные операции напрямую.

## Требования

Для разработки и сборки:

* Windows 10 или Windows 11 x64
* .NET 10 SDK
* PowerShell
* WiX Toolset SDK 7
* Git

Для установленной версии .NET Runtime отдельно не требуется, поскольку приложение публикуется как self-contained.

## Клонирование проекта

```powershell
git clone https://github.com/Cobollt/SecurityGuard.git
cd SecurityGuard
```

## Сборка проекта

Из корня репозитория:

```powershell
dotnet build .\SecurityGuard.slnx
```

## Запуск тестов

```powershell
dotnet test .\SecurityGuard.slnx
```

Текущий проверенный набор:

```text
Всего тестов: 325
Успешно: 325
Сбой: 0
Пропущено: 0
```

## Публикация Service и UI

Если выполнение PowerShell-скриптов запрещено:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Затем:

```powershell
.\scripts\publish-win-x64.ps1
```

Результаты публикации:

```text
artifacts\publish\service\win-x64
artifacts\publish\ui\win-x64
```

## Сборка установщика

Для сборки MSI версии `0.1.1`:

```powershell
.\scripts\build-installer.ps1 -Version 0.1.1
```

Готовый установщик:

```text
artifacts\installer\0.1.1\SecurityGuard-0.1.1-win-x64.msi
```

Если после изменения версии WiX не создаёт MSI, очистите промежуточные файлы установщика:

```powershell
Remove-Item `
    ".\installer\SecurityGuard.Installer\bin",
    ".\installer\SecurityGuard.Installer\obj" `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue
```

После этого повторите сборку установщика.

## Установка

Запустите PowerShell от имени администратора.

```powershell
$msi = (Resolve-Path ".\artifacts\installer\0.1.1\SecurityGuard-0.1.1-win-x64.msi").Path

$p = Start-Process msiexec.exe `
    -Verb RunAs `
    -Wait `
    -PassThru `
    -ArgumentList "/i `"$msi`" /qn /norestart"

$p.ExitCode
```

Код:

```text
0
```

означает успешную установку.

## Расположение файлов

После установки программа находится в:

```text
C:\Program Files\SecurityGuard
```

Windows Service:

```text
C:\Program Files\SecurityGuard\Service\SecurityGuard.Service.exe
```

Пользовательский интерфейс:

```text
C:\Program Files\SecurityGuard\UI\SecurityGuard.UI.exe
```

Рабочие данные SecurityGuard:

```text
C:\ProgramData\SecurityGuard
```

Данные в `ProgramData` сохраняются после удаления приложения.

## Windows Service

Имя службы:

```text
SecurityGuard
```

Проверка состояния:

```powershell
sc.exe query SecurityGuard
```

При нормальной работе:

```text
STATE : 4  RUNNING
```

Служба:

* запускается автоматически;
* работает от LocalSystem;
* может быть остановлена и перезапущена;
* автоматически перезапускается после сбоя.

Проверка конфигурации:

```powershell
sc.exe qc SecurityGuard
```

Проверка восстановления после сбоя:

```powershell
sc.exe qfailure SecurityGuard
```

Текущая конфигурация восстановления предусматривает до трёх перезапусков службы с задержкой 5 секунд.

## Проверка установки

После установки выполните:

```powershell
.\scripts\verify-installed.ps1 -ExpectedVersion 0.1.1
```

Успешная проверка выглядит примерно так:

```text
Version: 0.1.1
Service: Running
Startup: Automatic
Account: LocalSystem
ProgramData: OK
Start Menu: OK
```

## Запуск интерфейса

UI можно открыть из меню Start или вручную:

```powershell
Start-Process "C:\Program Files\SecurityGuard\UI\SecurityGuard.UI.exe"
```

Служба SecurityGuard должна быть установлена и запущена.

## AlgorithmGuard и AppLocker

AlgorithmGuard может использовать возможности Windows AppLocker.

Если PowerShell-модуль AppLocker недоступен, SecurityGuard в режиме `Monitor` с политикой `FailOpen` продолжает работу в деградированном режиме и не останавливает основную службу.

Наличие AppLocker зависит от конфигурации и редакции Windows.

## Обновление

SecurityGuard поддерживает обновление MSI поверх установленной более старой версии.

Например:

```text
0.1.0 → 0.1.1
```

Для обновления предварительное удаление `0.1.0` не требуется.

Запустите новый MSI:

```powershell
$msi = (Resolve-Path ".\artifacts\installer\0.1.1\SecurityGuard-0.1.1-win-x64.msi").Path

$p = Start-Process msiexec.exe `
    -Verb RunAs `
    -Wait `
    -PassThru `
    -ArgumentList "/i `"$msi`" /qn /norestart"

$p.ExitCode
```

После обновления:

```powershell
.\scripts\verify-installed.ps1 -ExpectedVersion 0.1.1
```

## Удаление

Получить ProductCode установленной версии:

```powershell
Get-ChildItem `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" `
    -ErrorAction SilentlyContinue |
ForEach-Object {
    $p = Get-ItemProperty $_.PSPath

    if ($p.DisplayName -eq "SecurityGuard") {
        [PSCustomObject]@{
            ProductCode = $_.PSChildName
            DisplayVersion = $p.DisplayVersion
        }
    }
} |
Format-List
```

Удаление:

```powershell
$p = Start-Process msiexec.exe `
    -Verb RunAs `
    -Wait `
    -PassThru `
    -ArgumentList "/x {PRODUCT-CODE} /qn /norestart"

$p.ExitCode
```

После удаления:

```powershell
sc.exe query SecurityGuard
```

Код `1060` означает, что служба удалена.

Папка:

```text
C:\Program Files\SecurityGuard
```

также должна быть удалена.

При этом:

```text
C:\ProgramData\SecurityGuard
```

сохраняется.

## Импорт и экспорт Security Lists

SecurityGuard позволяет экспортировать и импортировать наборы правил и списков безопасности через пользовательский интерфейс.

Экспортируемый пакет предназначен для переноса настроек между экземплярами SecurityGuard.

При работе с пакетами выполняется проверка SHA-256.

## Разработка

Основная проверка проекта перед созданием установщика:

```powershell
dotnet test .\SecurityGuard.slnx
```

Затем:

```powershell
.\scripts\build-installer.ps1 -Version 0.1.1
```

После установки:

```powershell
.\scripts\verify-installed.ps1 -ExpectedVersion 0.1.1
```

## Текущий статус

На Windows проверены:

* полная сборка решения;
* 325 автоматических тестов;
* установка MSI;
* автоматический запуск Windows Service;
* работа службы от LocalSystem;
* запуск WPF UI;
* перезапуск службы;
* восстановление службы после сбоя;
* удаление MSI;
* сохранение `ProgramData`;
* повторная установка;
* обновление `0.1.0 → 0.1.1`.

## Платформа

SecurityGuard разрабатывается исключительно для Windows x64.
