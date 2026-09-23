using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Ipc.ArchiveGuard;
using SecurityGuard.Core.Models;
using SecurityGuard.Service.Application;

namespace SecurityGuard.Service.Tests;

public sealed class ArchiveGuardIpcServiceTests
{
	[Fact]
	public async Task Restore_adds_sha256_exception_and_restores_file()
	{
		var quarantineId =
			Guid.NewGuid();

		var sha256 =
			new string(
				'A',
				64);

		var originalPath =
			@"C:\Users\Test\Downloads\sample.zip";

		var record =
			new QuarantineRecord(
				quarantineId,
				originalPath,
				@"C:\ProgramData\SecurityGuard\Quarantine\sample.sgq",
				"sample.zip",
				sha256,
				12345,
				SecurityModuleKind.ArchiveGuard.ToString(),
				"Suspicious archive",
				DateTimeOffset.UtcNow);

		var quarantineRepository =
			new FakeQuarantineRepository
			{
				Record =
					record
			};

		var quarantineService =
			new FakeQuarantineService
			{
				RestoredPath =
					originalPath
			};

		var exceptionService =
			new FakeArchiveGuardExceptionService();

		var service =
			new ArchiveGuardIpcService(
				new FakeArchiveGuardWorkflowService(),
				new FakeScanResultRepository(),
				quarantineRepository,
				quarantineService,
				exceptionService);

		var result =
			await service.RestoreFromQuarantineWithExceptionAsync(
				new ArchiveGuardQuarantineRestoreIpcRequest(
					quarantineId));

		Assert.Equal(
			sha256,
			exceptionService.Sha256);

		Assert.Equal(
			"sample.zip",
			exceptionService.FileName);

		Assert.Equal(
			quarantineId,
			quarantineService.RestoredQuarantineId);

		Assert.Equal(
			originalPath,
			result.RestoredPath);

		Assert.Equal(
			sha256,
			result.Sha256);

		Assert.Equal(
			quarantineId,
			result.QuarantineId);
	}

    [Fact]
    public async Task GetQuarantineItems_filters_sorts_and_applies_limit()
    {
        var now =
            DateTimeOffset.UtcNow;

        var olderArchive =
            new QuarantineRecord(
                Guid.NewGuid(),
                @"C:\older.zip",
                @"C:\quarantine\older.sgq",
                "older.zip",
                new string('A', 64),
                100,
                SecurityModuleKind.ArchiveGuard.ToString(),
                "Older",
                now.AddMinutes(-10));

        var newerArchive =
            new QuarantineRecord(
                Guid.NewGuid(),
                @"C:\newer.zip",
                @"C:\quarantine\newer.sgq",
                "newer.zip",
                new string('B', 64),
                200,
                SecurityModuleKind.ArchiveGuard.ToString(),
                "Newer",
                now);

        var otherModule =
            new QuarantineRecord(
                Guid.NewGuid(),
                @"C:\script.ps1",
                @"C:\quarantine\script.sgq",
                "script.ps1",
                new string('C', 64),
                300,
                SecurityModuleKind.AlgorithmGuard.ToString(),
                "Other module",
                now.AddMinutes(5));

        var repository =
            new FakeQuarantineRepository
            {
                Records =
                [
                    olderArchive,
                otherModule,
                newerArchive
                ]
            };

        var service =
            new ArchiveGuardIpcService(
                new FakeArchiveGuardWorkflowService(),
                new FakeScanResultRepository(),
                repository,
                new FakeQuarantineService(),
                new FakeArchiveGuardExceptionService());

        var result =
            await service.GetQuarantineItemsAsync(
                new ArchiveGuardQuarantineItemsIpcRequest(
                    1));

        var item =
            Assert.Single(
                result);

        Assert.Equal(
            newerArchive.Id,
            item.Id);

        Assert.Equal(
            "newer.zip",
            item.OriginalFileName);

        Assert.DoesNotContain(
            result,
            item =>
                item.Id ==
                otherModule.Id);
    }

    [Fact]
    public async Task Restore_rejects_quarantine_item_from_other_module()
    {
        var quarantineId =
            Guid.NewGuid();

        var record =
            new QuarantineRecord(
                quarantineId,
                @"C:\Users\Test\script.ps1",
                @"C:\ProgramData\SecurityGuard\Quarantine\script.sgq",
                "script.ps1",
                new string(
                    'C',
                    64),
                100,
                SecurityModuleKind.AlgorithmGuard.ToString(),
                "Blocked script",
                DateTimeOffset.UtcNow);

        var quarantineRepository =
            new FakeQuarantineRepository
            {
                Record =
                    record
            };

        var quarantineService =
            new FakeQuarantineService();

        var exceptionService =
            new FakeArchiveGuardExceptionService();

        var service =
            new ArchiveGuardIpcService(
                new FakeArchiveGuardWorkflowService(),
                new FakeScanResultRepository(),
                quarantineRepository,
                quarantineService,
                exceptionService);

        var exception =
            await Assert.ThrowsAsync<InvalidOperationException>(
                () =>
                    service.RestoreFromQuarantineWithExceptionAsync(
                        new ArchiveGuardQuarantineRestoreIpcRequest(
                            quarantineId)));

        Assert.Equal(
            "The quarantine item does not belong to ArchiveGuard.",
            exception.Message);

        Assert.Null(
            exceptionService.Sha256);

        Assert.Null(
            quarantineService.RestoredQuarantineId);
    }

    private sealed class FakeArchiveGuardWorkflowService
		: IArchiveGuardWorkflowService
	{
		public Task<ArchiveGuardWorkflowResult> ScanAsync(
			string filePath,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}
	}

	private sealed class FakeScanResultRepository
		: IScanResultRepository
	{
		public Task UpsertAsync(
			ScanResult result,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}

		public Task<ScanResult?> GetByIdAsync(
			Guid id,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}

		public Task<ScanResult?> GetLatestBySha256Async(
			string sha256,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}

		public Task<IReadOnlyList<ScanResult>> GetRecentAsync(
			int limit,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}

		public Task PruneAsync(
			SecurityModuleKind module,
			DateTimeOffset olderThanUtc,
			int maxEntries,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}
	}

	private sealed class FakeQuarantineRepository
		: IQuarantineRepository
	{
		public QuarantineRecord? Record { get; set; }

        public IReadOnlyList<QuarantineRecord> Records { get; set; } =
			[];

        public Task AddAsync(
			QuarantineRecord record,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
			CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Records);
        }

        public Task<QuarantineRecord?> GetByIdAsync(
			Guid id,
			CancellationToken cancellationToken = default)
		{
			return Task.FromResult(
				Record?.Id == id
					? Record
					: null);
		}

		public Task<int> CountAsync(
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}

		public Task DeleteAsync(
			Guid id,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}
	}

	private sealed class FakeQuarantineService
		: IQuarantineService
	{
		public Guid? RestoredQuarantineId { get; private set; }

		public string RestoredPath { get; set; } =
			string.Empty;

		public Task<QuarantineRecord> QuarantineAsync(
			string filePath,
			SecurityModuleKind sourceModule,
			string reason,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}

		public Task<string> RestoreAsync(
			Guid quarantineId,
			string? destinationPath = null,
			CancellationToken cancellationToken = default)
		{
			RestoredQuarantineId =
				quarantineId;

			return Task.FromResult(
				RestoredPath);
		}

		public Task DeleteAsync(
			Guid quarantineId,
			CancellationToken cancellationToken = default)
		{
			throw new NotSupportedException();
		}
	}

	private sealed class FakeArchiveGuardExceptionService
		: IArchiveGuardExceptionService
	{
		public string? Sha256 { get; private set; }

		public string? FileName { get; private set; }

		public Task AddSha256ExceptionAsync(
			string sha256,
			string fileName,
			CancellationToken cancellationToken = default)
		{
			Sha256 =
				sha256;

			FileName =
				fileName;

			return Task.CompletedTask;
		}
	}
}