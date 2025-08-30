using System.Windows;

namespace MDE_Monitoring_App
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel _vm;

        public MainWindow()
        {
            InitializeComponent();
            _vm = new MainViewModel();
            DataContext = new MainViewModel();
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            _vm.RefreshData();

            if (LogsDataGrid.Items.Count > 0)
            {
                LogsDataGrid.ScrollIntoView(LogsDataGrid.Items[0]);
            }
        }
    }
}
