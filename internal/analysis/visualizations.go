package analysis

import (
    "fmt"
    "github.com/wcharczuk/go-chart"
    "heroPacket/internal/models"
    "net/http"
)

type Visualization struct {
    Port int
}

func (v *Visualization) ProtocolPieChart(protocols map[string]int, w http.ResponseWriter) error {
    var slices []chart.Value
    for proto, count := range protocols {
        slices = append(slices, chart.Value{
            Label: proto,
            Value: float64(count),
        })
    }

    pie := chart.PieChart{
        Width:  500,
        Height: 500,
        Values: slices,
    }

    w.Header().Set("Content-Type", "image/svg+xml")
    return pie.Render(chart.SVG, w)
}

func (v *Visualization) SizeDistributionChart(buckets map[string]int, w http.ResponseWriter) error {
    bars := make([]chart.Value, 0, len(buckets))
    for bucket, count := range buckets {
        bars = append(bars, chart.Value{
            Label: bucket,
            Value: float64(count),
        })
    }

    barChart := chart.BarChart{
        Width:  800,
        Height: 400,
        Bars:   bars,
    }

    w.Header().Set("Content-Type", "image/svg+xml")
    return barChart.Render(chart.SVG, w)
}
