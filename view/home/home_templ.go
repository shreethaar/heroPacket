// Code generated by templ - DO NOT EDIT.

// templ: version: v0.3.833
package home

//lint:file-ignore SA4006 This context is only used if a nested component is present.

import "github.com/a-h/templ"
import templruntime "github.com/a-h/templ/runtime"

import (
	"fmt"
	"time"
)

// Add this type at the top of the file
type UploadedFile struct {
	Name       string
	Size       int64
	UploadTime time.Time
}

// Add response type for upload status
type UploadResponse struct {
	Status  string
	Message string
}

// Landing page template (no CSRF needed)
func Show() templ.Component {
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
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 1, "<head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>HeroPacket</title><link href=\"https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css\" rel=\"stylesheet\"></head><body class=\"bg-gradient-to-r from-gray-800 to-gray-900 min-h-screen text-white flex flex-col items-center justify-center\"><div class=\"bg-gray-700 shadow-xl rounded-xl p-10 w-full max-w-2xl border border-gray-600 text-center\"><h1 class=\"text-5xl font-bold text-teal-400 mb-6\">HeroPacket</h1><p class=\"text-lg text-gray-300 mb-8\">Welcome to HeroPacket, a lightweight packet capture analysis system.</p><a href=\"/home\" class=\"bg-teal-600 text-white px-8 py-3 rounded-lg hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:ring-offset-2 transition-colors\">Get Started</a></div></body>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		return nil
	})
}

// Dashboard template (file upload without CSRF)
func ShowHome(files []UploadedFile, response *UploadResponse) templ.Component {
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
		templ_7745c5c3_Var2 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var2 == nil {
			templ_7745c5c3_Var2 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 2, "<head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>HeroPacket</title><link href=\"https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css\" rel=\"stylesheet\"><script src=\"https://unpkg.com/htmx.org@1.9.10\" integrity=\"sha384-D1Kt99CQMDuVetoL1lrYwg5t+9QdHe7NLX/SoJYkXDFfX37iInKRy5xLSi8nO7UC\" crossorigin=\"anonymous\"></script></head><body class=\"bg-gradient-to-r from-gray-800 to-gray-900 min-h-screen text-white\"><!-- Top Navigation Bar --><nav class=\"bg-gray-800 border-b border-gray-700 px-4 py-3 shadow-sm\"><div class=\"container mx-auto flex justify-between items-center\"><div class=\"flex items-center\"><h1 class=\"text-2xl font-bold text-teal-400\">HeroPacket</h1></div><div class=\"flex items-center space-x-4\"><!-- Documentation Button --><a href=\"/documentation\" class=\"bg-gray-700 text-white px-4 py-2 rounded-lg hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors flex items-center\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z\"></path></svg> Documentation</a></div></div></nav><div class=\"container mx-auto px-4 py-8\"><div class=\"bg-gray-700 rounded-xl p-8 border-2 border-gray-600 mb-8\"><!-- Main content area with welcome message --><div class=\"text-center mb-8\"><h2 class=\"text-3xl font-bold text-teal-400 mb-4\">HeroPacket</h2><p class=\"text-lg text-gray-300 mb-4\">Welcome to HeroPacket .......</p></div><!-- File upload area --><div class=\"mt-8 border-2 border-gray-600 rounded-lg p-6 text-center bg-gray-800/50\"><div class=\"mb-4\"><div id=\"uploadDisplay\" class=\"flex items-center justify-center\"><div class=\"p-4\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-12 w-12 text-teal-400 mx-auto mb-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M9 13h6m-3-3v6m5 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z\"></path></svg><p class=\"text-gray-300 text-sm mb-2\">PCAP Files</p></div></div></div><!-- Form for file upload with HTMX --><form id=\"uploadForm\" hx-post=\"/upload\" hx-encoding=\"multipart/form-data\" hx-target=\"#uploadResponse\" hx-indicator=\"#uploadingIndicator\" hx-trigger=\"change from:#fileInput\" hx-swap=\"innerHTML\"><!-- File input --><input type=\"file\" id=\"fileInput\" name=\"pcap-file\" accept=\".pcap,.pcapng,.cap\" class=\"hidden\"><!-- Button to trigger file input --><label for=\"fileInput\" class=\"bg-teal-600 text-white px-6 py-3 rounded-lg hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-teal-500 mx-auto cursor-pointer inline-flex items-center justify-center shadow-lg border border-teal-700 font-medium transition-all duration-200 transform hover:translate-y-[-2px]\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12\"></path></svg> Upload PCAP</label><!-- Loading indicator --><div id=\"uploadingIndicator\" class=\"htmx-indicator mt-4\"><div class=\"flex justify-center items-center\"><svg class=\"animate-spin h-5 w-5 text-teal-400 mr-2\" xmlns=\"http://www.w3.org/2000/svg\" fill=\"none\" viewBox=\"0 0 24 24\"><circle class=\"opacity-25\" cx=\"12\" cy=\"12\" r=\"10\" stroke=\"currentColor\" stroke-width=\"4\"></circle> <path class=\"opacity-75\" fill=\"currentColor\" d=\"M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z\"></path></svg> <span>Uploading...</span></div></div></form><!-- Response container --><div id=\"uploadResponse\" class=\"mt-4 text-center\" hx-swap-oob=\"true\">")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		if response != nil {
			if response.Status == "error" {
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 3, "<div class=\"text-red-500 bg-red-100/10 p-3 rounded-lg font-bold\">")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				var templ_7745c5c3_Var3 string
				templ_7745c5c3_Var3, templ_7745c5c3_Err = templ.JoinStringErrs(response.Message)
				if templ_7745c5c3_Err != nil {
					return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/home/home.templ`, Line: 138, Col: 34}
				}
				_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var3))
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 4, "</div>")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
			} else if response.Status == "success" {
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 5, "<div class=\"text-green-500 bg-green-100/10 p-3 rounded-lg font-bold\">")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				var templ_7745c5c3_Var4 string
				templ_7745c5c3_Var4, templ_7745c5c3_Err = templ.JoinStringErrs(response.Message)
				if templ_7745c5c3_Err != nil {
					return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/home/home.templ`, Line: 142, Col: 34}
				}
				_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var4))
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 6, "</div>")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
			}
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 7, "</div></div><!-- Previous uploads table --><div id=\"fileListContainer\" hx-get=\"/refresh-files\" hx-trigger=\"load\">")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		if len(files) > 0 {
			templ_7745c5c3_Err = FileListTemplate(files).Render(ctx, templ_7745c5c3_Buffer)
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 8, "</div></div></div><!-- Footer --><footer class=\"mt-auto py-6 text-center text-gray-400 text-sm\">heroPacket 2025</footer><!-- HTMX Script --><script src=\"https://unpkg.com/htmx.org@1.9.10\"></script></body>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		return nil
	})
}

// Helper function
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

var _ = templruntime.GeneratedTemplate
