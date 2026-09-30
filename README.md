# SecurityGuard

SecurityGuard — локальное приложение безопасности для Windows, предназначенное для контроля выполнения скриптов и процессов, исходящих операций передачи данных, а также проверки файлов и архивов.

Проект состоит из Windows Service, выполняющего защитную логику с системными правами, и отдельного WPF-интерфейса для пользователя.

## Возможности

SecurityGuard включает следующие основные модули:

* AlgorithmGuard — контроль выполнения скриптов и потенциально нежелательных алгоритмов.
* TransferGuard — контроль исходящих сетевых соединений и операций передачи файлов, правила разрешения и блокировки, а также постоянное разрешение всего приложения по пути исполняемого файла.
* ArchiveGuard — проверка файлов и архивов.
* Quarantine — изоляция подозрительных объектов.
* Rules and Exceptions — правила разрешений, блокировок и исключений.
* Security Lists — импорт и экспорт списков SecurityGuard.
* Security Events — журнал событий безопасности.
* Windows Service — выполнение защитной логики независимо от пользовательского интерфейса.
* WPF UI — интерфейс управления SecurityGuard с автоматическим запуском, фоновым режимом, системным треем и защитой от запуска нескольких экземпляров.

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

Текущий набор тестов проверяется командой выше. Все тестовые проекты должны завершаться без ошибок.

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

Для сборки MSI версии `0.1.29`:

```powershell
.\scripts\build-installer.ps1 -Version 0.1.29
```

Готовый установщик:

```text
artifacts\installer\0.1.29\SecurityGuard-0.1.29-win-x64.msi
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
$msi = (Resolve-Path ".\artifacts\installer\0.1.29\SecurityGuard-0.1.29-win-x64.msi").Path

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
.\scripts\verify-installed.ps1 -ExpectedVersion 0.1.29
```

Успешная проверка выглядит примерно так:

```text
Version: 0.1.29
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

Начиная с версии `0.1.29` WPF UI автоматически запускается после входа пользователя с параметром `--background`. Главное окно при этом не открывается: UI работает через системный трей. Нажатие `X` скрывает окно, а пункт `Выход` завершает только UI. Windows Service продолжает работать независимо от UI. Повторный запуск SecurityGuard открывает уже работающий экземпляр интерфейса и не создаёт второй процесс.

## TransferGuard

TransferGuard контролирует исходящие сетевые соединения и операции передачи файлов.

Для неизвестного сетевого действия доступны `Allow`, `AllowApplication`, `Block` и `BlockApplication`. Правила уровня приложения создаются по полному `ProcessPath`.

При выборе разрешения всего приложения правило создаётся по полному пути исполняемого файла:

```text
C:\Program Files\Mozilla Firefox\firefox.exe
```

Такое правило:

* не зависит от PID процесса;
* продолжает действовать после перезапуска программы;
* применяется к новым сетевым адресам и портам;
* применяется отдельно к `NetworkConnection` и `FileTransfer`;
* не распространяется на программу с другим путём к исполняемому файлу.

После `AllowApplication` или `BlockApplication` старые ожидающие запросы этого же приложения по полному `ProcessPath` автоматически удаляются. Запросы других приложений сохраняются.

`BlockApplication` создаёт постоянную блокировку приложения. Для `NetworkConnection` в режиме `Enforce` блокировка применяется через исходящее правило Windows Firewall по полному `ProcessPath`. Последующий `AllowApplication` удаляет противоположную firewall-блокировку.

Для правил TransferGuard используются следующие уровни приоритета:

```text
Network Allow       100
FileTransfer Allow  150
Network Block       200
FileTransfer Block  250
```

При совпадении нескольких правил преимущество имеет правило с большим приоритетом. При одинаковом приоритете блокирующее правило имеет преимущество перед разрешающим.

## AlgorithmGuard и AppLocker

AlgorithmGuard может использовать возможности Windows AppLocker.

Если PowerShell-модуль AppLocker недоступен, SecurityGuard в режиме `Monitor` с политикой `FailOpen` продолжает работу в деградированном режиме и не останавливает основную службу.

Наличие AppLocker зависит от конфигурации и редакции Windows.

## Обновление

SecurityGuard поддерживает обновление MSI поверх установленной более старой версии.

Например:

```text
0.1.28 → 0.1.29
```

Для обновления предварительное удаление `0.1.28` не требуется.

Запустите новый MSI:

```powershell
$msi = (Resolve-Path ".\artifacts\installer\0.1.29\SecurityGuard-0.1.29-win-x64.msi").Path

$p = Start-Process msiexec.exe `
    -Verb RunAs `
    -Wait `
    -PassThru `
    -ArgumentList "/i `"$msi`" /qn /norestart"

$p.ExitCode
```

После обновления:

```powershell
.\scripts\verify-installed.ps1 -ExpectedVersion 0.1.29
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
.\scripts\build-installer.ps1 -Version 0.1.29
```

После установки:

```powershell
.\scripts\verify-installed.ps1 -ExpectedVersion 0.1.29
```

## Текущий статус

На Windows проверены:

* полная сборка решения;
* автоматические тесты решения без ошибок;
* установка MSI;
* автоматический запуск Windows Service;
* работа службы от LocalSystem;
* запуск WPF UI;
* автоматический запуск WPF UI после входа пользователя;
* фоновый запуск UI с `--background`;
* работа UI через системный трей;
* скрытие окна при нажатии `X`;
* защита от запуска нескольких экземпляров UI;
* перезапуск службы;
* восстановление службы после сбоя;
* удаление MSI;
* сохранение `ProgramData`;
* повторная установка;
* обновление `0.1.28 → 0.1.29`;
* обнаружение исходящих сетевых соединений TransferGuard;
* постоянное разрешение всего приложения по `ProcessPath`;
* постоянная блокировка всего приложения по `ProcessPath`;
* применение `BlockApplication` через Windows Firewall в режиме `Enforce`;
* снятие firewall-блокировки через `AllowApplication`;
* работа разрешения после перезапуска приложения и смены PID;
* автоматическая очистка старых Pending-запросов разрешённого приложения;
* сохранение Pending-запросов других приложений;
* согласованное отображение новых Pending-запросов в UI.

## Платформа

SecurityGuard разрабатывается исключительно для Windows x64.
