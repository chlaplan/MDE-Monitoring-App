using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows.Data;

namespace MDE_Monitoring_App.Converters
{
    // Single value (int) or IEnumerable<int/long> to descriptive string(s)
    [ValueConversion(typeof(object), typeof(string))]
    public class AccessMaskConverter : IValueConverter
    {
        public static readonly (int Bit, string Name)[] _flags =
        {
            (1,  "Device Read"),
            (2,  "Device Write"),
            (4,  "Device Execute"),
            (8,  "File Read"),
            (16, "File Write"),
            (32, "File Execute"),
            (64, "Print")
        };

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is null) return string.Empty;

            if (value is IEnumerable enumerable && value is not string)
            {
                var parts = new List<string>();
                foreach (var item in enumerable)
                {
                    if (item == null) continue;
                    if (!TryToLong(item, out var mask)) continue;
                    parts.Add(MaskToString(mask));
                }
                return string.Join(" | ", parts.Where(p => !string.IsNullOrEmpty(p)));
            }

            if (TryToLong(value, out var single))
                return MaskToString(single);

            return value.ToString() ?? string.Empty;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            Binding.DoNothing;

        private static bool TryToLong(object o, out long v)
        {
            try
            {
                v = System.Convert.ToInt64(o, CultureInfo.InvariantCulture);
                return true;
            }
            catch
            {
                v = 0;
                return false;
            }
        }

        private static string MaskToString(long mask) =>
            string.Join(", ", _flags.Where(f => (mask & f.Bit) != 0).Select(f => f.Name));
    }
}