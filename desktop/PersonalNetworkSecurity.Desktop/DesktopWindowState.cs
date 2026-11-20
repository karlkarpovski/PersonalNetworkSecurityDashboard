using System.IO;
using System.Text.Json;
using System.Windows;

internal sealed record DesktopWindowState(double Left, double Top, double Width, double Height, bool Maximized)
{
    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PersonalNetworkSecurity", "window.json");

    public static void Restore(Window window)
    {
        try
        {
            if (!File.Exists(FilePath)) return;
            var state = JsonSerializer.Deserialize<DesktopWindowState>(File.ReadAllText(FilePath));
            if (state is null || !double.IsFinite(state.Left) || !double.IsFinite(state.Top) ||
                !double.IsFinite(state.Width) || !double.IsFinite(state.Height)) return;
            window.Width = Math.Clamp(state.Width, window.MinWidth, Math.Max(window.MinWidth, SystemParameters.WorkArea.Width));
            window.Height = Math.Clamp(state.Height, window.MinHeight, Math.Max(window.MinHeight, SystemParameters.WorkArea.Height));
            window.Left = Math.Clamp(state.Left, SystemParameters.VirtualScreenLeft,
                SystemParameters.VirtualScreenLeft + Math.Max(0, SystemParameters.VirtualScreenWidth - window.Width));
            window.Top = Math.Clamp(state.Top, SystemParameters.VirtualScreenTop,
                SystemParameters.VirtualScreenTop + Math.Max(0, SystemParameters.VirtualScreenHeight - window.Height));
            window.WindowStartupLocation = WindowStartupLocation.Manual;
            if (state.Maximized) window.WindowState = WindowState.Maximized;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException) { }
    }

    public static void Save(Window window)
    {
        try
        {
            var bounds = window.RestoreBounds;
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            var temporary = FilePath + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(new DesktopWindowState(
                bounds.Left, bounds.Top, bounds.Width, bounds.Height, window.WindowState == WindowState.Maximized)));
            File.Move(temporary, FilePath, overwrite: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }
}
