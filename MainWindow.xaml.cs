using System.Windows;
using System.Windows.Controls;

namespace MDE_Monitoring_App
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            // Ensure DataContext is set so bindings work
            if (DataContext is null)
                DataContext = new MainViewModel();
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                _ = vm.RefreshDataAsync();
            }
        }

        private void ClearFirewallFilter_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                vm.FirewallFilterText = string.Empty;
            }
        }
    }
}
