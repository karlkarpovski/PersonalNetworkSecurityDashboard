using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var verify = args.Contains("--verify", StringComparer.Ordinal);
        var application = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        application.Startup += async (_, _) => await OpenAsync(application, verify);
        return application.Run();
    }

    private static async Task OpenAsync(Application application, bool verify)
    {
        var exitCode = 0;
        try
        {
            var profile = Environment.GetEnvironmentVariable("PNS_WEBVIEW_DATA_DIR") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "PersonalNetworkSecurity", "WebView2");
            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: profile);
            await using var host = await DashboardHost.StartDesktopAsync(Path.Combine(AppContext.BaseDirectory, "wwwroot"));
            using var view = new WebView2();
            var window = new Window
            {
                Title = "Personal Network Security",
                Icon = LoadArtwork("Logo.ico"),
                Width = 1360,
                Height = 900,
                MinWidth = 380,
                MinHeight = 480,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                Background = new SolidColorBrush(Color.FromRgb(0x0d, 0x17, 0x27)),
                Content = view,
            };
            if (!verify) DesktopWindowState.Restore(window);
            var allowClose = verify;
            var checkingClose = false;
            window.Closing += async (_, eventArgs) =>
            {
                if (allowClose) return;
                eventArgs.Cancel = true;
                if (checkingClose) return;
                checkingClose = true;
                try
                {
                    var running = false;
                    if (view.CoreWebView2 is not null)
                    {
                        using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(3) };
                        client.DefaultRequestHeaders.Add("Cookie", $"{host.CookieName}={host.CookieValue}");
                        using var response = await client.GetAsync(new Uri(host.Origin, "/api/capture/status"));
                        response.EnsureSuccessStatusCode();
                        using var document = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                        running = document.RootElement.GetProperty("state").GetString() == "running";
                    }
                    if (running && MessageBox.Show(window,
                        "Closing the app stops packet capture. Close the app?",
                        "Stop capture and close", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
                    DesktopWindowState.Save(window);
                    allowClose = true;
                    window.Close();
                }
                catch
                {
                    if (MessageBox.Show(window, "Capture status is unavailable. Close the app and stop any active capture?",
                        "Close dashboard", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                    {
                        allowClose = true;
                        window.Close();
                    }
                }
                finally { checkingClose = false; }
            };
            var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            window.SourceInitialized += (_, _) => DashboardChrome.Apply(window);
            window.Closed += (_, _) => closed.TrySetResult();
            application.MainWindow = window;
            window.Show();
            try
            {
                var options = environment.CreateCoreWebView2ControllerOptions();
                options.IsInPrivateModeEnabled = true;
                await view.EnsureCoreWebView2Async(environment, options);
                if (closed.Task.IsCompleted) throw new OperationCanceledException();
                var core = view.CoreWebView2;
                core.Settings.AreDevToolsEnabled = false;
                core.Settings.AreDefaultContextMenusEnabled = false;
                core.Settings.AreHostObjectsAllowed = false;
                core.Settings.IsWebMessageEnabled = false;
                core.NavigationStarting += (_, eventArgs) => eventArgs.Cancel = !IsDashboard(eventArgs.Uri, host.Origin);
                core.FrameNavigationStarting += (_, eventArgs) => eventArgs.Cancel = true;
                core.NewWindowRequested += (_, eventArgs) =>
                {
                    eventArgs.Handled = true;
                    if (eventArgs.IsUserInitiated &&
                        Uri.TryCreate(eventArgs.Uri, UriKind.Absolute, out var external) &&
                        external.Scheme == "https" && external.Host == "dev.maxmind.com" &&
                        external.AbsolutePath == "/geoip/geolite2-free-geolocation-data/" &&
                        string.IsNullOrEmpty(external.UserInfo) && external.IsDefaultPort)
                    {
                        try
                        {
                            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                                external.AbsoluteUri) { UseShellExecute = true });
                        }
                        catch (System.ComponentModel.Win32Exception)
                        {
                            MessageBox.Show(window, "Open https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/ in your browser.",
                                "GeoIP setup", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                    }
                };
                core.PermissionRequested += (_, eventArgs) => eventArgs.State = CoreWebView2PermissionState.Deny;
                var loaded = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                core.NavigationCompleted += (_, eventArgs) => loaded.TrySetResult(eventArgs.IsSuccess);
                var cookie = core.CookieManager.CreateCookie(host.CookieName, host.CookieValue, host.Origin.Host, "/api/capture");
                cookie.IsHttpOnly = true;
                cookie.SameSite = CoreWebView2CookieSameSiteKind.Strict;
                core.CookieManager.AddOrUpdateCookie(cookie);
                await core.AddScriptToExecuteOnDocumentCreatedAsync(
                    "if (window === window.top) sessionStorage.setItem('pns-access-code', 'desktop');");
                core.Navigate(host.Origin.AbsoluteUri);
                view.Focus();
                var navigation = await Task.WhenAny(loaded.Task, closed.Task).WaitAsync(TimeSpan.FromSeconds(25));
                if (closed.Task.IsCompleted) throw new OperationCanceledException();
                if (navigation == loaded.Task && !await loaded.Task)
                    throw new InvalidOperationException("The local dashboard could not load.");
                await WaitForDashboardAsync(core, closed.Task);
                window.Activate();
                view.Focus();
                if (verify)
                {
                    await VerifyAsync(core);
                    window.Close();
                }
                await closed.Task;
            }
            finally
            {
                allowClose = true;
                if (!closed.Task.IsCompleted) window.Close();
            }
        }
        catch (OperationCanceledException) when (!verify) { }
        catch (Exception error)
        {
            exitCode = 1;
            if (verify)
                Console.Error.WriteLine(error);
            else
                MessageBox.Show(error is WebView2RuntimeNotFoundException
                    ? "Install the Microsoft Edge WebView2 Evergreen Runtime and try again."
                    : error.Message, "Personal Network Security", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        application.Shutdown(exitCode);
    }

    private static BitmapImage LoadArtwork(string name) =>
        new(new Uri($"pack://application:,,,/Assets/{name}", UriKind.Absolute));

    private static async Task WaitForDashboardAsync(CoreWebView2 view, Task closed)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            while (!closed.IsCompleted)
            {
                var ready = await view.ExecuteScriptAsync("""
                (() => {
                    const logo = document.querySelector('img.brand-logo');
                    return Boolean(logo?.complete && logo.naturalWidth && document.querySelector('main#workspace'));
                })()
                """).WaitAsync(timeout.Token);
                if (ready == "true") return;
                await Task.Delay(100, timeout.Token);
            }
        }
        catch (OperationCanceledException) when (!closed.IsCompleted)
        {
            throw new TimeoutException("The dashboard startup screen timed out.");
        }
        throw new OperationCanceledException();
    }

    private static bool IsDashboard(string address, Uri origin) =>
        Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Scheme == origin.Scheme &&
        uri.Host == origin.Host && uri.Port == origin.Port && string.IsNullOrEmpty(uri.UserInfo);

    private static async Task VerifyAsync(CoreWebView2 view)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        while (true)
        {
            await Task.Delay(250, timeout.Token);
            var ready = await view.ExecuteScriptAsync("""
                document.body?.innerText.includes('Live stream connected') &&
                document.querySelector('nav[aria-label="Workspace"]') !== null &&
                !document.cookie.includes('pns-desktop-session')
                """).WaitAsync(timeout.Token);
            if (ready == "true")
            {
                var keyboard = await view.ExecuteScriptAsync("""
                    (() => {
                        const skip = document.querySelector('a.skip');
                        skip?.focus();
                        skip?.click();
                        return document.activeElement?.id === 'workspace';
                    })()
                    """);
                if (keyboard != "true") throw new InvalidOperationException("Skip navigation did not focus the workspace.");
                return;
            }
        }
    }
}
