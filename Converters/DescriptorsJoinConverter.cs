using System;
using System.Collections;
using System.Globalization;
using System.Linq;
using System.Windows.Data;

namespace MDE_Monitoring_App.Converters
{
    public class DescriptorsJoinConverter : IValueConverter
    {
        public string Separator { get; set; } = "; ";

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string s) return s;
            if (value is IEnumerable enumerable)
            {
                var parts = enumerable.Cast<object?>()
                                      .Where(o => o != null)
                                      .Select(o => o.ToString())
                                      .Where(t => !string.IsNullOrWhiteSpace(t));
                return string.Join(Separator, parts);
            }
            return string.Empty;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            Binding.DoNothing;
    }
}