// Code generated by templ - DO NOT EDIT.

// templ: version: v0.3.833
package overview

//lint:file-ignore SA4006 This context is only used if a nested component is present.

import "github.com/a-h/templ"
import templruntime "github.com/a-h/templ/runtime"

import (
	"fmt"
	"heroPacket/internal/analysis"
	"time"
)

type ViewData struct {
	Filename      string
	TrafficStats  *analysis.TrafficStats
	TopProtocols  []analysis.ProtocolCount
	Conversations []*analysis.Conversation
	NetworkNodes  []*analysis.NetworkNode
	DNSQueries    []analysis.QueryCount
}

// Helper function for formatting bytes
func formatBytes(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := int64(bytes) / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Helper function for formatting duration
func formatDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	hours := seconds / 3600
	seconds = seconds % 3600
	minutes := seconds / 60
	seconds = seconds % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func Show(data ViewData) templ.Component {
	return templruntime.GeneratedTemplate(func(templ_7745c5c3_Input templruntime.GeneratedComponentInput) (templ_7745c5c3_Err error) {
		templ_7745c5c3_W, ctx := templ_7745c5c3_Input.Writer, templ_7745c5c3_Input.Context
		if templ_7745c5c3_CtxErr := ctx.Err(); templ_7745c5c3_CtxErr != nil {
			return templ_7745c5c3_CtxErr
		}
		templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templruntime.GetBuffer(templ_7745c5c3_W)
		if !templ_7745c5c3_IsBuffer {
			defer func() {
				templ_7745c5c3_BufErr := templruntime.ReleaseBuffer(templ_7745c5c3_Buffer)
				if templ_7745c5c3_Err == nil {
					templ_7745c5c3_Err = templ_7745c5c3_BufErr
				}
			}()
		}
		ctx = templ.InitializeContext(ctx)
		templ_7745c5c3_Var1 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var1 == nil {
			templ_7745c5c3_Var1 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 1, "<head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>PCAP Overview - ")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		var templ_7745c5c3_Var2 string
		templ_7745c5c3_Var2, templ_7745c5c3_Err = templ.JoinStringErrs(data.Filename)
		if templ_7745c5c3_Err != nil {
			return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 52, Col: 39}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var2))
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 2, "</title><link href=\"https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css\" rel=\"stylesheet\"><script src=\"https://unpkg.com/htmx.org@1.9.10\" integrity=\"sha384-D1Kt99CQMDuVetoL1lrYwg5t+9QdHe7NLX/SoJYkXDFfX37iInKRy5xLSi8nO7UC\" crossorigin=\"anonymous\"></script><style>\n\t\t.sidebar-button {\n\t\t\t@apply flex items-center w-full px-4 py-3 text-left text-gray-300 hover:bg-gray-700 hover:text-teal-400 transition-colors rounded-lg;\n\t\t}\n\t\t.sidebar-button.active {\n\t\t\t@apply bg-gray-700 text-teal-400 border-l-4 border-teal-400 pl-3;\n\t\t}\n\t\t.category-header {\n\t\t\t@apply text-xs uppercase tracking-wider text-gray-500 font-semibold px-4 py-2;\n\t\t}\n\t</style></head><body class=\"bg-gradient-to-r from-gray-800 to-gray-900 min-h-screen text-white\"><!-- Top Navigation Bar --><nav class=\"bg-gray-800 border-b border-gray-700 px-4 py-3 shadow-sm\"><div class=\"container mx-auto flex justify-between items-center\"><div class=\"flex items-center\"><h1 class=\"text-2xl font-bold text-teal-400\">HeroPacket</h1></div><div class=\"flex items-center space-x-4\"><a href=\"/\" class=\"bg-gray-700 text-white px-4 py-2 rounded-lg hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors flex items-center\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6\"></path></svg> Home</a></div></div></nav><div class=\"container mx-auto px-4 py-8 flex\"><!-- Left Sidebar --><div class=\"w-64 bg-gray-800 rounded-xl p-4 mr-6 border-2 border-gray-700 h-full\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-700 pb-2\">Analysis</h3><!-- Analytics Category --><div class=\"mb-4\"><div class=\"category-header\">Analytics</div><button class=\"sidebar-button active\" id=\"overview-btn\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z\"></path></svg> Overview</button> <button class=\"sidebar-button\" id=\"resolved-btn\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9\"></path></svg> Resolved Addresses</button> <button class=\"sidebar-button\" id=\"protocol-btn\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2\"></path></svg> Protocol Hierarchy</button> <button class=\"sidebar-button\" id=\"conversations-btn\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z\"></path></svg> Conversations</button> <button class=\"sidebar-button\" id=\"endpoints-btn\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10\"></path></svg> Endpoints</button></div><!-- Security Category --><div class=\"mb-4\"><div class=\"category-header\">Security</div><button class=\"sidebar-button\" id=\"mitre-btn\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z\"></path></svg> MITRE ATT&CK</button></div><!-- Export Options --><div class=\"mt-8\"><div class=\"category-header\">Export</div><button class=\"sidebar-button\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4\"></path></svg> Export Report</button></div></div><!-- Main Content Area --><div class=\"flex-1\"><div class=\"bg-gray-700 rounded-xl p-8 border-2 border-gray-600 mb-8\"><div class=\"flex justify-between items-center mb-6\"><h2 class=\"text-2xl font-bold text-teal-400\">PCAP Overview: ")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		var templ_7745c5c3_Var3 string
		templ_7745c5c3_Var3, templ_7745c5c3_Err = templ.JoinStringErrs(data.Filename)
		if templ_7745c5c3_Err != nil {
			return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 155, Col: 80}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var3))
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 3, "</h2></div><!-- Content sections --><div id=\"content-area\"><!-- Overview Section (default view) --><div id=\"overview-section\"><!-- Traffic Stats --><div class=\"mb-8\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-600 pb-2\">Traffic Statistics</h3><div class=\"grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4\"><div class=\"bg-gray-800 p-4 rounded-lg border border-gray-600\"><div class=\"text-gray-400 text-sm mb-1\">Total Packets</div><div class=\"text-2xl font-bold text-white\">")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		var templ_7745c5c3_Var4 string
		templ_7745c5c3_Var4, templ_7745c5c3_Err = templ.JoinStringErrs(fmt.Sprintf("%d", data.TrafficStats.TotalPackets))
		if templ_7745c5c3_Err != nil {
			return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 168, Col: 103}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var4))
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 4, "</div></div><div class=\"bg-gray-800 p-4 rounded-lg border border-gray-600\"><div class=\"text-gray-400 text-sm mb-1\">Total Bytes</div><div class=\"text-2xl font-bold text-white\">")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		var templ_7745c5c3_Var5 string
		templ_7745c5c3_Var5, templ_7745c5c3_Err = templ.JoinStringErrs(formatBytes(data.TrafficStats.TotalBytes))
		if templ_7745c5c3_Err != nil {
			return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 172, Col: 95}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var5))
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 5, "</div></div><div class=\"bg-gray-800 p-4 rounded-lg border border-gray-600\"><div class=\"text-gray-400 text-sm mb-1\">Duration</div><div class=\"text-2xl font-bold text-white\">")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		var templ_7745c5c3_Var6 string
		templ_7745c5c3_Var6, templ_7745c5c3_Err = templ.JoinStringErrs(formatDuration(data.TrafficStats.EndTime.Sub(data.TrafficStats.StartTime)))
		if templ_7745c5c3_Err != nil {
			return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 176, Col: 128}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var6))
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 6, "</div></div><div class=\"bg-gray-800 p-4 rounded-lg border border-gray-600\"><div class=\"text-gray-400 text-sm mb-1\">Avg Packet Size</div><div class=\"text-2xl font-bold text-white\">")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		var templ_7745c5c3_Var7 string
		templ_7745c5c3_Var7, templ_7745c5c3_Err = templ.JoinStringErrs(formatBytes(data.TrafficStats.TotalBytes / data.TrafficStats.TotalPackets))
		if templ_7745c5c3_Err != nil {
			return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 180, Col: 128}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var7))
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 7, "</div></div></div></div><!-- Top Protocols --><div class=\"mb-8\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-600 pb-2\">Top Protocols</h3><div class=\"bg-gray-800 rounded-lg border border-gray-600 overflow-hidden\"><table class=\"min-w-full divide-y divide-gray-600\"><thead class=\"bg-gray-900\"><tr><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Protocol</th><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Packets</th><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Percentage</th></tr></thead> <tbody class=\"divide-y divide-gray-600\">")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		for _, proto := range data.TopProtocols {
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 8, "<tr class=\"hover:bg-gray-700\"><td class=\"px-6 py-4 whitespace-nowrap text-sm font-medium text-white\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var8 string
			templ_7745c5c3_Var8, templ_7745c5c3_Err = templ.JoinStringErrs(proto.Name)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 200, Col: 95}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var8))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 9, "</td><td class=\"px-6 py-4 whitespace-nowrap text-sm text-gray-300\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var9 string
			templ_7745c5c3_Var9, templ_7745c5c3_Err = templ.JoinStringErrs(fmt.Sprintf("%d", proto.Count))
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 201, Col: 106}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var9))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 10, "</td><td class=\"px-6 py-4 whitespace-nowrap text-sm text-gray-300\"><div class=\"flex items-center\"><div class=\"w-full bg-gray-600 rounded-full h-2.5\"><div class=\"bg-teal-500 h-2.5 rounded-full\" style=\"")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var10 string
			templ_7745c5c3_Var10, templ_7745c5c3_Err = templruntime.SanitizeStyleAttributeValues(fmt.Sprintf("width: %d%%", int(float64(proto.Count)/float64(data.TrafficStats.TotalPackets)*100)))
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 205, Col: 168}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var10))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 11, "\"></div></div><span class=\"ml-2\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var11 string
			templ_7745c5c3_Var11, templ_7745c5c3_Err = templ.JoinStringErrs(fmt.Sprintf("%.1f%%", float64(proto.Count)/float64(data.TrafficStats.TotalPackets)*100))
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 207, Col: 126}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var11))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 12, "</span></div></td></tr>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 13, "</tbody></table></div></div><!-- Top Conversations --><div class=\"mb-8\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-600 pb-2\">Top Conversations</h3><div class=\"bg-gray-800 rounded-lg border border-gray-600 overflow-hidden\"><table class=\"min-w-full divide-y divide-gray-600\"><thead class=\"bg-gray-900\"><tr><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Source</th><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Destination</th><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Protocol</th><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Packets</th><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Bytes</th></tr></thead> <tbody class=\"divide-y divide-gray-600\">")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		for i, _ := range data.Conversations {
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 14, "<tr class=\"hover:bg-gray-700\"><td class=\"px-6 py-4 whitespace-nowrap text-sm font-medium text-white\">Source IP</td><td class=\"px-6 py-4 whitespace-nowrap text-sm text-gray-300\">Destination IP</td><td class=\"px-6 py-4 whitespace-nowrap text-sm text-gray-300\">TCP/IP</td><td class=\"px-6 py-4 whitespace-nowrap text-sm text-gray-300\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var12 string
			templ_7745c5c3_Var12, templ_7745c5c3_Err = templ.JoinStringErrs(fmt.Sprintf("%d", i+1))
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 237, Col: 98}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var12))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 15, "</td><td class=\"px-6 py-4 whitespace-nowrap text-sm text-gray-300\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var13 string
			templ_7745c5c3_Var13, templ_7745c5c3_Err = templ.JoinStringErrs(formatBytes(1024 * (i + 1)))
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 238, Col: 101}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var13))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 16, "</td></tr>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 17, "</tbody></table></div></div><!-- DNS Queries -->")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		if len(data.DNSQueries) > 0 {
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 18, "<div class=\"mb-8\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-600 pb-2\">Top DNS Queries</h3><div class=\"bg-gray-800 rounded-lg border border-gray-600 overflow-hidden\"><table class=\"min-w-full divide-y divide-gray-600\"><thead class=\"bg-gray-900\"><tr><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Domain</th><th scope=\"col\" class=\"px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider\">Count</th></tr></thead> <tbody class=\"divide-y divide-gray-600\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			for _, query := range data.DNSQueries {
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 19, "<tr class=\"hover:bg-gray-700\"><td class=\"px-6 py-4 whitespace-nowrap text-sm font-medium text-white\">")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				var templ_7745c5c3_Var14 string
				templ_7745c5c3_Var14, templ_7745c5c3_Err = templ.JoinStringErrs(query.Domain)
				if templ_7745c5c3_Err != nil {
					return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 261, Col: 98}
				}
				_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var14))
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 20, "</td><td class=\"px-6 py-4 whitespace-nowrap text-sm text-gray-300\">")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				var templ_7745c5c3_Var15 string
				templ_7745c5c3_Var15, templ_7745c5c3_Err = templ.JoinStringErrs(fmt.Sprintf("%d", query.Count))
				if templ_7745c5c3_Err != nil {
					return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/overview/overview.templ`, Line: 262, Col: 107}
				}
				_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var15))
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 21, "</td></tr>")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
			}
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 22, "</tbody></table></div></div>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 23, "</div><!-- Placeholder sections for other views (initially hidden) --><div id=\"resolved-section\" class=\"hidden\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-600 pb-2\">Resolved Addresses</h3><p class=\"text-gray-300\">This section will show resolved IP addresses and their corresponding hostnames.</p><!-- Content will be loaded via HTMX or populated later --></div><div id=\"protocol-section\" class=\"hidden\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-600 pb-2\">Protocol Hierarchy</h3><p class=\"text-gray-300\">This section will display the protocol hierarchy tree.</p><!-- Content will be loaded via HTMX or populated later --></div><div id=\"conversations-section\" class=\"hidden\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-600 pb-2\">Conversations</h3><p class=\"text-gray-300\">This section will show detailed conversation statistics.</p><!-- Content will be loaded via HTMX or populated later --></div><div id=\"endpoints-section\" class=\"hidden\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-600 pb-2\">Endpoints</h3><p class=\"text-gray-300\">This section will display endpoint statistics.</p><!-- Content will be loaded via HTMX or populated later --></div><div id=\"mitre-section\" class=\"hidden\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4 border-b border-gray-600 pb-2\">MITRE ATT&CK Analysis</h3><p class=\"text-gray-300\">This section will show potential MITRE ATT&CK techniques detected in the traffic.</p><!-- Content will be loaded via HTMX or populated later --></div></div></div></div></div><!-- Footer --><footer class=\"mt-auto py-6 text-center text-gray-400 text-sm\">heroPacket 2025</footer><!-- JavaScript for sidebar navigation --><script>\n\t\tdocument.addEventListener('DOMContentLoaded', function() {\n\t\t\t// Get all sidebar buttons and content sections\n\t\t\tconst buttons = {\n\t\t\t\t'overview-btn': 'overview-section',\n\t\t\t\t'resolved-btn': 'resolved-section',\n\t\t\t\t'protocol-btn': 'protocol-section',\n\t\t\t\t'conversations-btn': 'conversations-section',\n\t\t\t\t'endpoints-btn': 'endpoints-section',\n\t\t\t\t'mitre-btn': 'mitre-section'\n\t\t\t};\n\t\t\t\n\t\t\t// Add click event listeners to all buttons\n\t\t\tObject.keys(buttons).forEach(btnId => {\n\t\t\t\tconst btn = document.getElementById(btnId);\n\t\t\t\tif (btn) {\n\t\t\t\t\tbtn.addEventListener('click', function() {\n\t\t\t\t\t\t// Hide all sections\n\t\t\t\t\t\tObject.values(buttons).forEach(sectionId => {\n\t\t\t\t\t\t\tdocument.getElementById(sectionId).classList.add('hidden');\n\t\t\t\t\t\t});\n\t\t\t\t\t\t\n\t\t\t\t\t\t// Show the selected section\n\t\t\t\t\t\tdocument.getElementById(buttons[btnId]).classList.remove('hidden');\n\t\t\t\t\t\t\n\t\t\t\t\t\t// Update active button styling\n\t\t\t\t\t\tdocument.querySelectorAll('.sidebar-button').forEach(button => {\n\t\t\t\t\t\t\tbutton.classList.remove('active');\n\t\t\t\t\t\t});\n\t\t\t\t\t\tbtn.classList.add('active');\n\t\t\t\t\t});\n\t\t\t\t}\n\t\t\t});\n\t\t});\n\t</script></body>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		return nil
	})
}

var _ = templruntime.GeneratedTemplate
