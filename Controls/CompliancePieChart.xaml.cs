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
        {
            chart.Redraw();
        }
    }

    private void Redraw()
    {
        if (SlicePath == null) return; // Not loaded yet
        var pct = Math.Clamp(Percentage, 0, 100);
        var angle = pct / 100.0 * 360.0;
        var radius = Math.Max(ActualWidth, ActualHeight) / 2.0;
        if (radius <= 0) radius = 60;

        var center = new Point(radius, radius);
        var start = new Point(center.X, 0);
        double rad = (Math.PI / 180.0) * angle;
        var end = new Point(
            center.X + radius * Math.Sin(rad),
            center.Y - radius * Math.Cos(rad));

        bool largeArc = angle > 180;

        // If 0% compliant, clear slice
        if (pct <= 0.0001)
        {
            SlicePath.Data = Geometry.Empty;
            return;
        }

        var fig = new PathFigure { StartPoint = center };
        fig.Segments.Add(new LineSegment(start, true));
        fig.Segments.Add(new ArcSegment(end, new Size(radius, radius), 0, largeArc, SweepDirection.Clockwise, true));
        fig.Segments.Add(new LineSegment(center, true));
        var geo = new PathGeometry();
        geo.Figures.Add(fig);
        SlicePath.Data = geo;
    }
}