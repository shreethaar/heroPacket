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
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 1, "<head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>HeroPacket</title><link href=\"https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css\" rel=\"stylesheet\"></head><body class=\"bg-gradient-to-r from-gray-800 to-gray-900 min-h-screen text-white flex flex-col items-center justify-center\"><div class=\"bg-gray-700 shadow-xl rounded-xl p-10 w-full max-w-2xl border border-gray-600 text-center\"><h1 class=\"text-5xl font-bold text-teal-400 mb-6\">Pcap Analyzer</h1><p class=\"text-lg text-gray-300 mb-8\">Welcome to Pcap Analyzer, a lightweight packet capture analysis system.</p><a href=\"/home\" class=\"bg-teal-600 text-white px-8 py-3 rounded-lg hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:ring-offset-2 transition-colors\">Get Started</a></div></body>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		return nil
	})
}

// Dashboard template (with CSRF and file upload)
func ShowHome(csrfToken string, files []UploadedFile) templ.Component {
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
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 2, "<head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>HeroPacket</title><link href=\"https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css\" rel=\"stylesheet\"><script src=\"https://unpkg.com/htmx.org@1.9.10\" integrity=\"sha384-D1Kt99CQMDuVetoL1lrYwg5t+9QdHe7NLX/SoJYkXDFfX37iInKRy5xLSi8nO7UC\" crossorigin=\"anonymous\"></script></head><body class=\"bg-gradient-to-r from-gray-800 to-gray-900 min-h-screen text-white\"><!-- Top Navigation Bar --><nav class=\"bg-gray-800 border-b border-gray-700 px-4 py-3 shadow-sm\"><div class=\"container mx-auto flex justify-between items-center\"><div class=\"flex items-center\"><h1 class=\"text-2xl font-bold text-teal-400\">Pcap Analyzer</h1></div><div class=\"flex items-center space-x-4\"><!-- Documentation Button --><a href=\"/documentation\" class=\"bg-gray-700 text-white px-4 py-2 rounded-lg hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors flex items-center\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z\"></path></svg> Documentation</a></div></div></nav><div class=\"container mx-auto px-4 py-8\"><div class=\"bg-gray-700 rounded-xl p-8 border-2 border-gray-600 mb-8\"><!-- Main content area with welcome message --><div class=\"text-center mb-8\"><h2 class=\"text-3xl font-bold text-teal-400 mb-4\">HeroPacket</h2><p class=\"text-lg text-gray-300 mb-4\">Welcome to HeroPacket .......</p></div><!-- File upload area --><div class=\"mt-8 border-2 border-gray-600 rounded-lg p-6 text-center bg-gray-800/50\"><div class=\"mb-4\"><div id=\"uploadDisplay\" class=\"flex items-center justify-center\"><div class=\"p-4\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-12 w-12 text-teal-400 mx-auto mb-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M9 13h6m-3-3v6m5 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z\"></path></svg><p class=\"text-gray-300 text-sm mb-2\">PCAP Files</p></div></div></div><!-- Form for file upload with HTMX --><form id=\"uploadForm\" action=\"/upload\" method=\"POST\" enctype=\"multipart/form-data\" hx-post=\"/upload\" hx-encoding=\"multipart/form-data\" hx-target=\"#uploadResponse\" hx-indicator=\"#uploadingIndicator\" hx-trigger=\"change from:#fileInput\"><!-- CSRF token input removed --><!-- Button to trigger file input --><label for=\"fileInput\" class=\"bg-teal-600 text-white px-6 py-3 rounded-lg hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-teal-500 mx-auto cursor-pointer inline-flex items-center justify-center shadow-lg border border-teal-700 font-medium transition-all duration-200 transform hover:translate-y-[-2px]\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-5 w-5 mr-2\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12\"></path></svg> Upload PCAP</label> <input type=\"file\" id=\"fileInput\" name=\"pcap-file\" accept=\".pcap,.pcapng,.cap\" class=\"hidden\"><!-- Loading indicator - hidden by default, shown during upload --><div id=\"uploadingIndicator\" class=\"htmx-indicator mt-4 hidden\"><div class=\"flex justify-center items-center\"><svg class=\"animate-spin h-5 w-5 text-teal-400 mr-2\" xmlns=\"http://www.w3.org/2000/svg\" fill=\"none\" viewBox=\"0 0 24 24\"><circle class=\"opacity-25\" cx=\"12\" cy=\"12\" r=\"10\" stroke=\"currentColor\" stroke-width=\"4\"></circle> <path class=\"opacity-75\" fill=\"currentColor\" d=\"M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z\"></path></svg> <span>Uploading...</span></div></div></form><!-- Response container --><div id=\"uploadResponse\" class=\"mt-4 text-center\"></div></div><!-- Previous uploads table -->")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		if len(files) > 0 {
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 3, "<div class=\"mt-8 bg-gray-700 rounded-xl p-6 border-2 border-gray-600\"><h3 class=\"text-xl font-semibold text-teal-400 mb-4\">Previous Uploads</h3><div class=\"overflow-x-auto\"><table class=\"w-full text-left border-collapse\"><thead class=\"bg-gray-800/50\"><tr><th class=\"px-6 py-3 rounded-tl-lg border-b-2 border-gray-600\">Filename</th><th class=\"px-6 py-3 border-b-2 border-gray-600\">Upload Date</th><th class=\"px-6 py-3 border-b-2 border-gray-600\">Size</th><th class=\"px-6 py-3 rounded-tr-lg border-b-2 border-gray-600\">Actions</th></tr></thead> <tbody class=\"divide-y-2 divide-gray-600\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			for _, file := range files {
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 4, "<tr class=\"hover:bg-gray-600/50\"><td class=\"px-6 py-4\">")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				var templ_7745c5c3_Var3 string
				templ_7745c5c3_Var3, templ_7745c5c3_Err = templ.JoinStringErrs(file.Name)
				if templ_7745c5c3_Err != nil {
					return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/home/home.templ`, Line: 151, Col: 53}
				}
				_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var3))
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 5, "</td><td class=\"px-6 py-4\">")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				var templ_7745c5c3_Var4 string
				templ_7745c5c3_Var4, templ_7745c5c3_Err = templ.JoinStringErrs(file.UploadTime.Format("2006-01-02 15:04:05"))
				if templ_7745c5c3_Err != nil {
					return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/home/home.templ`, Line: 152, Col: 89}
				}
				_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var4))
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 6, "</td><td class=\"px-6 py-4\">")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				var templ_7745c5c3_Var5 string
				templ_7745c5c3_Var5, templ_7745c5c3_Err = templ.JoinStringErrs(formatFileSize(file.Size))
				if templ_7745c5c3_Err != nil {
					return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/home/home.templ`, Line: 153, Col: 69}
				}
				_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var5))
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 7, "</td><td class=\"px-6 py-4\"><button data-analyze-button data-filename=\"")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				var templ_7745c5c3_Var6 string
				templ_7745c5c3_Var6, templ_7745c5c3_Err = templ.JoinStringErrs(file.Name)
				if templ_7745c5c3_Err != nil {
					return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/home/home.templ`, Line: 157, Col: 49}
				}
				_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var6))
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 8, "\" class=\"bg-teal-600 text-white px-4 py-2 rounded-lg hover:bg-teal-700 transition-colors shadow-md border border-teal-700 font-medium inline-flex items-center justify-center mr-2\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-4 w-4 mr-1\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2\"></path></svg> Analyze</button> <button data-delete-button data-filename=\"")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				var templ_7745c5c3_Var7 string
				templ_7745c5c3_Var7, templ_7745c5c3_Err = templ.JoinStringErrs(file.Name)
				if templ_7745c5c3_Err != nil {
					return templ.Error{Err: templ_7745c5c3_Err, FileName: `view/home/home.templ`, Line: 167, Col: 49}
				}
				_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var7))
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
				templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 9, "\" class=\"bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors shadow-md border border-red-700 font-medium inline-flex items-center justify-center\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"h-4 w-4 mr-1\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16\"></path></svg> Delete</button></td></tr>")
				if templ_7745c5c3_Err != nil {
					return templ_7745c5c3_Err
				}
			}
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 10, "</tbody></table></div></div>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 11, "</div></div><!-- Footer --><footer class=\"mt-auto py-6 text-center text-gray-400 text-sm\">heroPacket 2025</footer><!-- Confirmation Dialog (hidden by default) --><div id=\"deleteConfirmDialog\" class=\"fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center hidden z-50\"><div class=\"bg-gray-800 rounded-xl p-6 border-2 border-gray-600 max-w-md w-full mx-4\"><h3 class=\"text-xl font-semibold text-red-400 mb-4\">Confirm Deletion</h3><p class=\"text-gray-300 mb-6\">Are you sure you want to delete <span id=\"fileToDelete\" class=\"font-semibold\"></span>? This action cannot be undone.</p><div class=\"flex justify-end space-x-4\"><button id=\"cancelDelete\" class=\"bg-gray-700 text-white px-4 py-2 rounded-lg hover:bg-gray-600 transition-colors\">Cancel</button> <button id=\"confirmDelete\" class=\"bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors\">Delete</button></div></div></div><!-- Scripts --><script>\n    // Enable analyze buttons\n    function setupAnalyzeButtons() {\n      document.querySelectorAll('[data-analyze-button]').forEach(button => {\n        button.addEventListener('click', function() {\n          const fileName = this.getAttribute('data-filename');\n          window.location.href = `/analyze/${fileName}`;\n        });\n      });\n    }\n\n    // Setup delete buttons and confirmation dialog\n    function setupDeleteButtons() {\n      const dialog = document.getElementById('deleteConfirmDialog');\n      const fileToDeleteSpan = document.getElementById('fileToDelete');\n      const cancelBtn = document.getElementById('cancelDelete');\n      const confirmBtn = document.getElementById('confirmDelete');\n      let currentFileName = '';\n\n      // Show confirmation dialog when delete button is clicked\n      document.querySelectorAll('[data-delete-button]').forEach(button => {\n        button.addEventListener('click', function() {\n          currentFileName = this.getAttribute('data-filename');\n          fileToDeleteSpan.textContent = currentFileName;\n          dialog.classList.remove('hidden');\n        });\n      });\n\n      // Hide dialog when cancel is clicked\n      cancelBtn.addEventListener('click', function() {\n        dialog.classList.add('hidden');\n      });\n\n      // Handle delete confirmation\n      confirmBtn.addEventListener('click', function() {\n        // CSRF token removed for now\n        \n        // Send delete request\n        fetch(`/delete/${currentFileName}`, {\n          method: 'DELETE',\n          headers: {\n            'Content-Type': 'application/json'\n            // CSRF header removed\n          }\n        })\n        .then(response => {\n          if (response.ok) {\n            // Show success message\n            const successMessage = document.createElement('div');\n            successMessage.className = 'fixed top-4 right-4 bg-teal-600 text-white px-6 py-3 rounded-lg shadow-lg z-50';\n            successMessage.innerHTML = `<div class=\"flex items-center\"><svg class=\"h-5 w-5 mr-2\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 20 20\" fill=\"currentColor\"><path fill-rule=\"evenodd\" d=\"M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z\" clip-rule=\"evenodd\" /></svg>File deleted successfully</div>`;\n            document.body.appendChild(successMessage);\n            \n            // Remove message after 3 seconds\n            setTimeout(() => {\n              successMessage.remove();\n            }, 3000);\n            \n            // Refresh the page to update the file list\n            setTimeout(() => {\n              window.location.reload();\n            }, 1000);\n          } else {\n            // Show error message\n            const errorMessage = document.createElement('div');\n            errorMessage.className = 'fixed top-4 right-4 bg-red-600 text-white px-6 py-3 rounded-lg shadow-lg z-50';\n            errorMessage.innerHTML = `<div class=\"flex items-center\"><svg class=\"h-5 w-5 mr-2\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 20 20\" fill=\"currentColor\"><path fill-rule=\"evenodd\" d=\"M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z\" clip-rule=\"evenodd\" /></svg>Failed to delete file</div>`;\n            document.body.appendChild(errorMessage);\n            \n            // Remove message after 3 seconds\n            setTimeout(() => {\n              errorMessage.remove();\n            }, 3000);\n          }\n          \n          // Hide dialog\n          dialog.classList.add('hidden');\n        })\n        .catch(error => {\n          console.error('Error:', error);\n          dialog.classList.add('hidden');\n        });\n      });\n    }\n\n    // Run setup when page loads\n    document.addEventListener('DOMContentLoaded', function() {\n      setupAnalyzeButtons();\n      setupDeleteButtons();\n    });\n  </script></body>")
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
