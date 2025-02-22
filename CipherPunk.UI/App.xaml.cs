﻿using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Threading;
using CipherPunk.CipherSuiteInfoApi;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace CipherPunk.UI;

internal sealed partial class App
{
    private readonly IHost host;

    public App()
    {
        Mouse.OverrideCursor = Cursors.AppStarting;

        TaskScheduler.UnobservedTaskException += HandleTaskSchedulerUnobservedTaskException;
        DispatcherUnhandledException += AppDispatcherUnhandledException;

        host = Host.CreateDefaultBuilder()
            .ConfigureServices(static (_, services) =>
            {
                IServiceCollection unused = services
                    .AddSingleton<ILogger, UserInterfaceLogService>()
                    .AddSingleton<IUacService, UacService>()
                    .AddSingleton<MainWindow>()
                    .AddSingleton<MainWindowViewModel>()
                    .AddSingleton<OverviewViewModel>()
                    .AddSingleton<CipherSuitesViewModel>()
                    .AddSingleton<CipherSuitesOsSettingsViewModel>()
                    .AddSingleton<CipherSuitesGroupPolicySettingsViewModel>()
                    .AddSingleton<EllipticCurvesViewModel>()
                    .AddSingleton<EllipticCurvesOsSettingsViewModel>()
                    .AddSingleton<EllipticCurvesGroupPolicySettingsViewModel>()
                    .AddSingleton<RemoteServerTestViewModel>()
                    .AddSingleton<LoggingViewModel>()
                    .AddSingleton<DefaultProtocolsViewModel>()
                    .AddSingleton<DefaultCipherSuitesViewModel>()
                    .AddSingleton<DefaultEllipticCurvesViewModel>()
                    .AddSingleton<ElevationViewModel>()
                    .AddSingleton<SchannelSettingsViewModel>()
                    .AddSingleton<SchannelProtocolSettingsViewModel>()
                    .AddCipherPunk()
                    .AddCipherSuiteInfoApi();
            }).Build();
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        Mouse.OverrideCursor = Cursors.AppStarting;

        host.Start();

        SetUiCulture();

        MainWindow mainWindow = host.Services.GetRequiredService<MainWindow>();

        PreventWpfFlashBang(mainWindow);
        mainWindow.Show();
        base.OnStartup(e);

        Mouse.OverrideCursor = null;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Mouse.OverrideCursor = Cursors.Wait;

        using (host)
        {
            host.StopAsync().GetAwaiter().GetResult();
        }

        base.OnExit(e);

        Mouse.OverrideCursor = null;
    }

    private static void PreventWpfFlashBang(Window window)
    {
        window.Loaded += static (s, _) => ((Window)s).WindowState = WindowState.Normal;
        window.WindowState = WindowState.Minimized;
    }

    private static void SetUiCulture()
        => FrameworkElement.LanguageProperty.OverrideMetadata(
            typeof(FrameworkElement),
            new FrameworkPropertyMetadata(XmlLanguage.GetLanguage(CultureInfo.CurrentCulture.IetfLanguageTag)));

    private void AppDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        ILogger logger = host.Services.GetRequiredService<ILogger>();

        e.Handled = true;

        logger.ExceptionThrown(e.Exception);
    }

    private void HandleTaskSchedulerUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        ILogger logger = host.Services.GetRequiredService<ILogger>();

        logger.ExceptionThrown(e.Exception);
    }
}