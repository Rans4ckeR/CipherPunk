namespace RS.Schannel.Manager.UI;

internal sealed partial class MainWindow
{
    public MainWindow(MainWindowViewModel mainWindowViewModel)
    {
        InitializeComponent();

        DataContext = mainWindowViewModel;
    }
}