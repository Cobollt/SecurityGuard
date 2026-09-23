using System.Globalization;
using System.Windows.Data;

namespace SecurityGuard.UI.Converters;

public sealed class LocalDateTimeConverter
    : IValueConverter
{
    public object Convert(
        object value,
        Type targetType,
        object parameter,
        CultureInfo culture)
    {
        if (value is DateTimeOffset dateTimeOffset)
        {
            return dateTimeOffset
                .ToLocalTime()
                .ToString(
                    "dd.MM.yyyy HH:mm:ss",
                    culture);
        }

        if (value is DateTime dateTime)
        {
            return dateTime
                .ToLocalTime()
                .ToString(
                    "dd.MM.yyyy HH:mm:ss",
                    culture);
        }

        return string.Empty;
    }

    public object ConvertBack(
        object value,
        Type targetType,
        object parameter,
        CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}