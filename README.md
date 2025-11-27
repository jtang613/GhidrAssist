# GhidrAssist
Author: **Jason Tang**

_An advanced LLM-powered plugin for interactive reverse engineering assistance in Ghidra._

## Description

GhidrAssist integrates Large Language Models (LLMs) into Ghidra to provide intelligent assistance for binary exploration and reverse engineering. It supports any OpenAI v1-compatible API, including local models (Ollama, LM-Studio, Open-WebUI) and cloud providers (OpenAI, Anthropic, Azure).

### Key Features

**Core Functionality:**
* **Code Explanation** - Explain functions and instructions in both disassembly and decompiled pseudo-C
* **Interactive Chat** - Multi-turn conversational queries with persistent chat history
* **Custom Queries** - Direct LLM queries with optional context from current function/location

**Advanced Capabilities:**
* **ReAct Agentic Mode** - Autonomous investigation using structured reasoning (Think-Act-Observe)
  - LLM proposes investigation steps based on your query
  - Systematic tool execution with progress tracking via todo lists
  - Iteration history preservation showing all investigation steps
  - Final synthesis with comprehensive answer and key findings
  - Accurate metrics (iterations, tool calls, duration)
* **MCP Integration** - Model Context Protocol client for tool-based analysis
  - Works with [GhidrAssistMCP](https://github.com/jtang613/GhidrAssistMCP) for Ghidra-specific tools
  - Conversational tool calling with automatic function execution
  - Support for SSE (Server-Sent Events) transport
* **Function Calling** - LLM can autonomously navigate binaries and modify analysis
  - Rename functions and variables
  - Navigate to addresses and cross-references
  - Execute Ghidra commands
* **Actions Tab** - Propose and apply bulk analysis improvements
  - Security vulnerability detection
  - Code quality analysis
  - Automated refactoring suggestions
* **RAG (Retrieval Augmented Generation)** - Enhance queries with contextual documents
  - Add custom documentation, exploit notes, architecture references
  - Lucene-based full-text search
  - Context injection into queries
* **RLHF Dataset Generation** - Collect feedback for model fine-tuning


### Architecture

The plugin uses a modular architecture:
- **Query Modes**: Regular queries, MCP-enhanced queries, or full agentic investigation
- **ReAct Orchestrator**: Manages autonomous investigation loops with todo tracking and findings accumulation
- **Conversational Tool Handler**: Manages multi-turn tool calling sessions
- **MCPToolManager**: Interfaces with external MCP servers for specialized tools
- **AnalysisDB**: SQLite database for chat history and RLHF feedback
- **RAGEngine**: Lucene-powered document search and context retrieval

Future Roadmap:
* Model fine-tuning using collected RLHF dataset
* Additional MCP tool integrations
* Enhanced agentic capabilities, multi-agent collaboration

## Screenshots

![Screenshot](https://github.com/user-attachments/assets/f5476e0d-5e30-4855-90a9-e0dbf39e16c7)


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

## LLM Setup

GhidrAssist works with any OpenAI v1-compatible API. Setup details are provider-specific - here are some helpful resources:

**Local LLM Providers:**
- [LM Studio](https://lmstudio.ai/docs/basics) - Easy local model hosting with GUI
- [Ollama](https://github.com/ollama/ollama#running-local-builds) - Command-line local model management
- Open-WebUI - Web interface for local models

**Cloud Providers:**
- [OpenAI API](https://help.openai.com/en/articles/4936850-where-do-i-find-my-openai-api-key)
- [Anthropic Claude](https://docs.anthropic.com/en/docs/initial-setup)
- Azure OpenAI

### Recommended Models

**For Agentic Mode (requires strong reasoning and tool use):**
- **Cloud**: GPT-5.1, Claude Sonnet 4.5
- **Local**: GPT-OSS, Llama 3.3 70B, DeepSeek-R1 70B, Qwen2.5 72B

**Note**: Agentic mode requires models with strong function calling and multi-step reasoning capabilities. Smaller models may struggle with complex investigations.

## Using GhidrAssistMCP for Tool-Based Analysis

[GhidrAssistMCP](https://github.com/jtang613/GhidrAssistMCP) provides MCP tools that allow the LLM to interact directly with Ghidra's analysis capabilities.

### Setup

1. **Start the MCP Server**

2. **Configure GhidrAssist:**
   - Open Tools → GhidrAssist Settings → MCP Servers tab
   - Add server: `http://127.0.0.1:8081` as `GhidraMCP` with transport type `SSE`

3. **Enable MCP in queries:**
   - In the Custom Query tab, check "Use MCP"
   - Optionally enable "Agentic" for autonomous investigation mode

### Usage Modes

**Regular MCP Queries:**
- Enable "Use MCP" checkbox
- Ask questions like "What does the current function do?"
- LLM can call tools to get decompilation, cross-references, etc.

**Agentic Mode (Recommended):**
- Enable both "Use MCP" and "Agentic" checkboxes
- Ask complex questions like "Find vulnerabilities in this function" or "Analyze the call graph"
- The ReAct agent will:
  1. Propose investigation steps as a todo list
  2. Systematically execute tools to gather information
  3. Track progress and accumulate findings
  4. Synthesize a comprehensive answer with evidence

**Example Queries:**
- "What security vulnerabilities exist in this function?"
- "Trace the data flow from user input to this call"
- "Find all functions that modify global variable X"
- "Analyze the error handling in the current function"

## Homepage
https://github.com/jtang613/GhidrAssist


## Minimum Version

This plugin requires the following minimum version of Ghidra:

* 11.0

## License

This plugin is released under a MIT license.
