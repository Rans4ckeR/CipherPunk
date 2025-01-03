﻿using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.ComponentModel;
using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.Input;

namespace CipherPunk.UI;

internal sealed class RemoteServerTestViewModel : BaseViewModel
{
    private readonly ITlsService tlsService;

    public RemoteServerTestViewModel(ILogger logger, ITlsService tlsService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.tlsService = tlsService;
        RunTestCommand = new AsyncRelayCommand(ExecuteRunTestCommandAsync, CanExecuteRunTestCommand);
        Port = 443;

        UpdateCanExecuteDefaultCommand();
    }

    public string? HostName
    {
        get;
        set
        {
            if (SetProperty(ref field, value))
                RunTestCommand.NotifyCanExecuteChanged();
        }
    }

    public ushort? Port
    {
        get;
        set
        {
            if (SetProperty(ref field, value))
                RunTestCommand.NotifyCanExecuteChanged();
        }
    }

    public IAsyncRelayCommand RunTestCommand { get; }

    public ObservableCollection<UiRemoteServerTestResult>? RemoteServerTestResults
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    protected override void BaseViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        base.BaseViewModelPropertyChanged(sender, e);

        switch (e.PropertyName)
        {
            case nameof(HostName):
                {
                    UpdateCanExecuteDefaultCommand();
                    break;
                }
        }
    }

    private async Task ExecuteRunTestCommandAsync(CancellationToken cancellationToken)
    {
        FrozenSet<(TlsVersion TlsVersion, FrozenSet<(uint CipherSuiteId, bool Supported, string? ErrorReason)>? Results)> remoteServerCipherSuites =
            await tlsService.GetRemoteServerCipherSuitesAsync(HostName!, Port!.Value, cancellationToken);
        IOrderedEnumerable<UiRemoteServerTestResult> uiRemoteServerTestResults = remoteServerCipherSuites.SelectMany(static q => q.Results!.Select(r => new UiRemoteServerTestResult(
            q.TlsVersion,
            q.TlsVersion is TlsVersion.SSL2_PROTOCOL_VERSION ? ((SslCipherSuite)r.CipherSuiteId).ToString() : ((TlsCipherSuite)r.CipherSuiteId).ToString(),
            r.Supported,
            r.ErrorReason)))
            .OrderByDescending(static q => q.Supported)
            .ThenByDescending(static q => q.TlsVersion)
            .ThenBy(static q => q.CipherSuiteId);

        RemoteServerTestResults = [.. uiRemoteServerTestResults];
    }

    private bool CanExecuteRunTestCommand() => !string.IsNullOrWhiteSpace(HostName) && Port.HasValue;
}