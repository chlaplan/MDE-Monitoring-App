using Microsoft.Win32;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

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
    }
}
