using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

internal static class DashboardChrome
{
    private const int UseImmersiveDarkMode = 20;
    private const int BorderColor = 34;
    private const int CaptionColor = 35;
    private const int TextColor = 36;

    public static void Apply(Window window)
    {
        var handle = new WindowInteropHelper(window).Handle;
        Update(handle, UseImmersiveDarkMode, 1);

        if (SystemParameters.HighContrast) return;

        // Match the dashboard's edge, panel, and foreground colors.
        Update(handle, BorderColor, ColorRef(0x27, 0x3a, 0x54));
        Update(handle, CaptionColor, ColorRef(0x12, 0x1e, 0x30));
        Update(handle, TextColor, ColorRef(0xed, 0xf4, 0xff));
    }

    private static int ColorRef(int red, int green, int blue) => red | (green << 8) | (blue << 16);

    // Windows versions that lack a DWM attribute retain their system default.
    private static void Update(IntPtr handle, int attribute, int value) =>
        DwmSetWindowAttribute(handle, attribute, ref value, sizeof(int));

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
