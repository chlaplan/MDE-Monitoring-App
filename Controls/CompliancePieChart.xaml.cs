using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace MDE_Monitoring_App.Controls;
public partial class CompliancePieChart : UserControl
{
    public double Percentage
    {
        get => (double)GetValue(PercentageProperty);
        set => SetValue(PercentageProperty, value);
    }
    public static readonly DependencyProperty PercentageProperty =
        DependencyProperty.Register(nameof(Percentage), typeof(double), typeof(CompliancePieChart),
            new PropertyMetadata(0.0, OnPercentChanged));

    public Brush CompliantColor
    {
        get => (Brush)GetValue(CompliantColorProperty);
        set => SetValue(CompliantColorProperty, value);
    }
    public static readonly DependencyProperty CompliantColorProperty =
        DependencyProperty.Register(nameof(CompliantColor), typeof(Brush), typeof(CompliancePieChart),
            new PropertyMetadata(Brushes.Green));

    public Brush NonCompliantColor
    {
        get => (Brush)GetValue(NonCompliantColorProperty);
        set => SetValue(NonCompliantColorProperty, value);
    }
    public static readonly DependencyProperty NonCompliantColorProperty =
        DependencyProperty.Register(nameof(NonCompliantColor), typeof(Brush), typeof(CompliancePieChart),
            new PropertyMetadata(Brushes.Red));

    public CompliancePieChart()
    {
        InitializeComponent();
        Loaded += (_, _) => Redraw();
        SizeChanged += (_, _) => Redraw();
    }

    private static void OnPercentChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is CompliancePieChart chart)
            chart.Redraw();
    }

    private void Redraw()
    {
        if (SlicePath == null) return;
        var pct = Math.Clamp(Percentage, 0, 100);

        // 0% -> show only red background
        if (pct <= 0.0001)
        {
            SlicePath.Data = Geometry.Empty;
            return;
        }
        // 100% -> draw full green circle (override red background)
        if (pct >= 99.999)
        {
            var radius = Math.Max(ActualWidth, ActualHeight) / 2.0;
            if (radius <= 0) radius = 60;
            var center = new Point(radius, radius);
            SlicePath.Data = new EllipseGeometry(center, radius, radius);
            return;
        }

        var angle = pct / 100.0 * 360.0;
        var radius2 = Math.Max(ActualWidth, ActualHeight) / 2.0;
        if (radius2 <= 0) radius2 = 60;

        var center2 = new Point(radius2, radius2);
        var start = new Point(center2.X, 0);
        double rad = (Math.PI / 180.0) * angle;
        var end = new Point(
            center2.X + radius2 * Math.Sin(rad),
            center2.Y - radius2 * Math.Cos(rad));

        bool largeArc = angle > 180;

        var fig = new PathFigure { StartPoint = center2 };
        fig.Segments.Add(new LineSegment(start, true));
        fig.Segments.Add(new ArcSegment(end, new Size(radius2, radius2), 0, largeArc, SweepDirection.Clockwise, true));
        fig.Segments.Add(new LineSegment(center2, true));
        var geo = new PathGeometry();
        geo.Figures.Add(fig);
        SlicePath.Data = geo;
    }
}