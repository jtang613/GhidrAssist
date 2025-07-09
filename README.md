# GhidrAssist
Author: **Jason Tang**

_A plugin that provides LLM helpers to explain code and assist in RE._

## Description:

This is a LLM plugin aimed at enabling the use of local LLM's (Ollama, Open-WebUI, LM-Studio, etc) for assisting with binary exploration and reverse engineering. It supports any OpenAI v1-compatible API. Recommended models are LLaMA-based models such as llama3.1:8b, but others such as DeepSeek and ChatGPT work as well.

Current features include:
* Explain the current function - Works for disassembly and pseudo-C.
* Explain the current instruction - Works for disassembly and pseudo-C.
* General query - Query the LLM directly from the UI.
* MCP client - Leverage MCP tools like [GhidrAssistMCP](https://github.com/jtang613/GhidrAssistMCP) from the interactive LLM chat.
* Agentic RE using the MCP Client and GhidraMCP.
* Propose actions - Provide a list of proposed actions to apply.
* Function calling - Allow agent to call functions to navigate the binary, rename functions and variables.
* Retrieval Augmented Generation - Supports adding contextual documents to refine query effectiveness.
* RLHF dataset generation - To enable model fine tuning.
* Settings to modify API host, key, model name and max tokens.

Future Roadmap:
* Model fine tuning - Leverage the RLHF dataset to fine tune the model.

## Screenshots

![Screenshot](https://github.com/user-attachments/assets/29fcaa14-277c-4eb2-816a-dd1b8ef52259)


https://github.com/user-attachments/assets/bd79474a-c82f-4083-b432-96625fef1387


## Quickstart

* If necessary, copy the binary release ZIP archive to the Ghidra_Install/Extensions/Ghidra directory.
* Launch Ghidra -> File -> Install Extension -> Enable GhidrAssist.
* Load a binary and launch the CodeBrowser.
* CodeBrowser -> File -> Configure -> Miscellaneous -> Enable GhidrAssist.
* CodeBrowser -> Tools -> GhidraAssist Settings.
* Ensure the RLHF and RAG database paths are appropriate for your environment.
* Point the API host to your preferred API provider and set the API key. 
* Open GhidrAssist with the GhidrAssist option in the Windows menu and start exploring.

## LLMs

General LLM setup is a bit outside the scope of this project since there's so many different options and there are plenty of sources that cover the topic much better than I could. It assumes one already has access to an OpenAI-compatible API provider.
Here's a few resources that might get you started:

- https://lmstudio.ai/docs/basics
- https://github.com/ollama/ollama#running-local-builds
- https://help.openai.com/en/articles/4936850-where-do-i-find-my-openai-api-key
- https://docs.anthropic.com/en/docs/initial-setup

For local LLM's, I've found that the Llama3.3:70b, Llama3.1:8b and DeepSeek-r1 produce good results.
From OpenAI, the o4-mini produces good results. Anthropic's Claude Sonnet also produces good results.

## GhidraMCP

To use with GhidraMCP, launch the bridge in SSE mode from a terminal:

`python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/`

Then open Tools -> GhidrAssist and add `http://127.0.0.1:8081` as `GhidraMCP` with `SSE` as the type.

Enable "Use MCP" in the Custom Query tab. Try a simple query like "What does the current function do?"

## Homepage
https://github.com/jtang613/GhidrAssist


## Minimum Version

This plugin requires the following minimum version of Ghidra:

* 11.0

## License

This plugin is released under a MIT license.
