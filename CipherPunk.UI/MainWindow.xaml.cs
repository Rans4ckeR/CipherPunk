namespace CipherPunk.UI;

internal sealed partial class MainWindow
{
    public MainWindow(MainWindowViewModel mainWindowViewModel)
    {
        InitializeComponent();

        DataContext = mainWindowViewModel;
    }
}