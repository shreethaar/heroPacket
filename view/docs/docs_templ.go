// Code generated by templ - DO NOT EDIT.

// templ: version: v0.3.833
package docs

//lint:file-ignore SA4006 This context is only used if a nested component is present.

import "github.com/a-h/templ"
import templruntime "github.com/a-h/templ/runtime"

import "heroPacket/view/layout"

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
		templ_7745c5c3_Var2 := templruntime.GeneratedTemplate(func(templ_7745c5c3_Input templruntime.GeneratedComponentInput) (templ_7745c5c3_Err error) {
			templ_7745c5c3_W, ctx := templ_7745c5c3_Input.Writer, templ_7745c5c3_Input.Context
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
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 1, "<div class=\"container mx-auto px-4 py-8\"><h1 class=\"text-3xl font-bold text-teal-400 mb-8\">Documentation</h1><div class=\"grid grid-cols-1 md:grid-cols-2 gap-8\"><!-- Quick Start Guide --><div class=\"bg-gray-700 rounded-xl p-6 border border-gray-600\"><h2 class=\"text-xl font-semibold text-teal-400 mb-4\">Quick Start Guide</h2><div class=\"space-y-4\"><p>Get started with HeroPacket by following our comprehensive guides:</p><ul class=\"list-disc list-inside space-y-2 text-gray-300\"><li><a href=\"https://heropacket.readthedocs.io/en/latest/quickstart/\" class=\"text-teal-400 hover:text-teal-300\">Installation Guide</a></li><li><a href=\"https://heropacket.readthedocs.io/en/latest/usage/\" class=\"text-teal-400 hover:text-teal-300\">Basic Usage</a></li><li><a href=\"https://heropacket.readthedocs.io/en/latest/analysis/\" class=\"text-teal-400 hover:text-teal-300\">Traffic Analysis</a></li></ul></div></div><!-- API Reference --><div class=\"bg-gray-700 rounded-xl p-6 border border-gray-600\"><h2 class=\"text-xl font-semibold text-teal-400 mb-4\">API Reference</h2><div class=\"space-y-4\"><p>Explore our API documentation:</p><ul class=\"list-disc list-inside space-y-2 text-gray-300\"><li><a href=\"https://heropacket.readthedocs.io/en/latest/api/overview/\" class=\"text-teal-400 hover:text-teal-300\">API Overview</a></li><li><a href=\"https://heropacket.readthedocs.io/en/latest/api/endpoints/\" class=\"text-teal-400 hover:text-teal-300\">Endpoints</a></li><li><a href=\"https://heropacket.readthedocs.io/en/latest/api/examples/\" class=\"text-teal-400 hover:text-teal-300\">Example Usage</a></li></ul></div></div><!-- Tutorials --><div class=\"bg-gray-700 rounded-xl p-6 border border-gray-600\"><h2 class=\"text-xl font-semibold text-teal-400 mb-4\">Tutorials</h2><div class=\"space-y-4\"><p>Learn through step-by-step tutorials:</p><ul class=\"list-disc list-inside space-y-2 text-gray-300\"><li><a href=\"https://heropacket.readthedocs.io/en/latest/tutorials/basic/\" class=\"text-teal-400 hover:text-teal-300\">Basic PCAP Analysis</a></li><li><a href=\"https://heropacket.readthedocs.io/en/latest/tutorials/advanced/\" class=\"text-teal-400 hover:text-teal-300\">Advanced Features</a></li><li><a href=\"https://heropacket.readthedocs.io/en/latest/tutorials/mitre/\" class=\"text-teal-400 hover:text-teal-300\">MITRE ATT&CK Integration</a></li></ul></div></div><!-- External Resources --><div class=\"bg-gray-700 rounded-xl p-6 border border-gray-600\"><h2 class=\"text-xl font-semibold text-teal-400 mb-4\">External Resources</h2><div class=\"space-y-4\"><p>Additional resources and references:</p><ul class=\"list-disc list-inside space-y-2 text-gray-300\"><li><a href=\"https://github.com/yourusername/heropacket\" class=\"text-teal-400 hover:text-teal-300\">GitHub Repository</a></li><li><a href=\"https://heropacket.readthedocs.io\" class=\"text-teal-400 hover:text-teal-300\">Full Documentation</a></li><li><a href=\"https://heropacket.readthedocs.io/en/latest/contributing/\" class=\"text-teal-400 hover:text-teal-300\">Contributing Guide</a></li></ul></div></div></div></div>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			return nil
		})
		templ_7745c5c3_Err = layout.Base("HeroPacket - Documentation", nav()).Render(templ.WithChildren(ctx, templ_7745c5c3_Var2), templ_7745c5c3_Buffer)
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		return nil
	})
}

func nav() templ.Component {
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
		templ_7745c5c3_Var3 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var3 == nil {
			templ_7745c5c3_Var3 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 2, "<nav class=\"bg-gray-800 p-4\"><div class=\"container mx-auto flex justify-between items-center\"><a href=\"/\" class=\"text-teal-400 hover:text-teal-300 text-xl font-bold\">HeroPacket</a><div class=\"space-x-4\"><a href=\"/home\" class=\"text-gray-300 hover:text-white\">Home</a> <a href=\"/docs\" class=\"text-gray-300 hover:text-white\">Documentation</a></div></div></nav>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		return nil
	})
}

var _ = templruntime.GeneratedTemplate
