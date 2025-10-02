using Microsoft.Win32;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace MDE_Monitoring_App
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            Icon = new BitmapImage(new Uri("pack://application:,,,/Resources/microsoft_defender_icon.png"));
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

        private async Task RefreshDeviceControlPoliciesAsync()
        {
            if (DataContext is MainViewModel vm)
            {
                var status = vm.DeviceControlPolicyStatus;
            }
        }

        private void ClearFirewallFilter_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                vm.FirewallFilterText = string.Empty;
            }
        }

        private async void ExportPdf_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is not MainViewModel vm) return;

            var dlg = new SaveFileDialog
            {
                Title = "Export Security Report",
                Filter = "PDF Files|*.pdf",
                FileName = $"EndpointSecurityReport_{DateTime.Now:yyyyMMdd_HHmm}.pdf"
            };
            if (dlg.ShowDialog(this) != true)
                return;

            Mouse.OverrideCursor = Cursors.Wait;
            try
            {
                var ok = await vm.ExportPdfAsync(dlg.FileName);
                MessageBox.Show(this,
                    ok ? "PDF export complete." : "Export failed.",
                    "Export",
                    MessageBoxButton.OK,
                    ok ? MessageBoxImage.Information : MessageBoxImage.Error);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        private void PolicyRulesGrid_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (sender is not DataGrid grid) return;

            var dep = (DependencyObject)e.OriginalSource;

            // Ignore header clicks
            while (dep != null && dep is not DataGridRow && dep is not DataGridColumnHeader)
                dep = VisualTreeHelper.GetParent(dep);

            if (dep is DataGridColumnHeader) return;
            if (dep is not DataGridRow row) return;

            // Toggle this row's details
            if (row.DetailsVisibility == Visibility.Visible)
            {
                row.DetailsVisibility = Visibility.Collapsed;
                e.Handled = true;
            }
            else
            {
                // (Optional) collapse any other open rows so only one is open
                foreach (var item in grid.Items)
                {
                    if (grid.ItemContainerGenerator.ContainerFromItem(item) is DataGridRow r &&
                        r != row &&
                        r.DetailsVisibility == Visibility.Visible)
                    {
                        r.DetailsVisibility = Visibility.Collapsed;
                    }
                }

                row.DetailsVisibility = Visibility.Visible;
                row.IsSelected = true;
                e.Handled = true;
            }
        }
    }
}
