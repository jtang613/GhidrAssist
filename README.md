# GhidrAssist
Author: **Jason Tang**

_An advanced LLM-powered plugin for interactive reverse engineering assistance in Ghidra._

## Description

GhidrAssist integrates Large Language Models (LLMs) into Ghidra to provide intelligent assistance for binary exploration and reverse engineering. It supports any OpenAI v1-compatible API, including local models (Ollama, LM-Studio, Open-WebUI) and cloud providers (OpenAI, Anthropic, Azure).

### Key Features

**Core Functionality:**
* **Code Explanation** - Explain functions and instructions in both disassembly and decompiled pseudo-C
  - Security analysis panel showing risk level, activity profile, and API usage
  - Editable summaries with user-edit protection from auto-overwrite
* **Interactive Chat** - Multi-turn conversational queries with persistent chat history
* **Custom Queries** - Direct LLM queries with optional context from current function/location

**Graph-RAG Knowledge System:**
* **Semantic Knowledge Graph** - Hierarchical representation of binary analysis
  - 5-level semantic hierarchy: Statement → Block → Function → Module → Binary
  - Pre-computed LLM summaries enable fast, LLM-free queries
  - SQLite persistence with JGraphT graph algorithms
  - Full-text search (FTS5) on summaries and security annotations
* **Community Detection** - Automatic module discovery via Leiden algorithm
  - Groups related functions into logical modules
  - Hierarchical community structure with summaries
  - Visual graph exploration with configurable depth
* **Security Feature Extraction** - Comprehensive security analysis
  - Network APIs: POSIX sockets, WinSock, DNS, SSL/TLS, WinHTTP, WinINet
  - File I/O APIs: POSIX, Windows, C library functions
  - Crypto APIs: OpenSSL, Windows crypto, platform-specific
  - String patterns: IP addresses, URLs, domains, file paths, registry keys
  - Risk level classification (LOW/MEDIUM/HIGH) and activity profiling
* **Semantic Graph Tab** - Visual knowledge graph interface
  - Graph view with N-hop depth exploration
  - List view of all indexed functions
  - Semantic search across summaries
  - One-click re-indexing and security analysis

**Advanced Capabilities:**
* **Extended Thinking/Reasoning Control** - Adjust LLM reasoning depth for quality vs. speed trade-offs
  - Support for OpenAI o1/o3/o4, Claude with extended thinking, and local reasoning models
  - Configurable effort levels: Low (fast), Medium (balanced), High (thorough)
  - Per-program persistence - different binaries can use different reasoning levels
  - Provider-agnostic implementation (Anthropic, OpenAI, Azure, LiteLLM, LMStudio, Ollama)
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

The plugin uses a modular, service-oriented architecture:

**Core Services:**
- **Query Modes**: Regular queries, MCP-enhanced queries, or full agentic investigation
- **ReAct Orchestrator**: Manages autonomous investigation loops with todo tracking and findings accumulation
- **Conversational Tool Handler**: Manages multi-turn tool calling sessions
- **MCPToolManager**: Interfaces with external MCP servers for specialized tools

**Graph-RAG Backend:**
- **BinaryKnowledgeGraph**: Hybrid SQLite + JGraphT storage for semantic knowledge
- **GraphRAGEngine**: LLM-free query engine using pre-computed summaries
- **SemanticExtractor**: LLM-powered function summarization with batch processing
- **SecurityFeatureExtractor**: Static analysis for network, file I/O, and crypto APIs
- **CommunityDetector**: Leiden algorithm implementation for module discovery

**Data Layer:**
- **AnalysisDB**: SQLite database for chat history, RLHF feedback, and knowledge graphs
- **SchemaMigrationRunner**: Versioned database migrations for transparent upgrades
- **RAGEngine**: Lucene-powered document search for custom context injection

**UI Components:**
- Tab-based interface: Explain, Query, Actions, Semantic Graph, RAG Management, MCP Servers
- Service orchestration via TabController

Future Roadmap:
* Model fine-tuning using collected RLHF dataset
* Additional MCP tool integrations
* Enhanced agentic capabilities, multi-agent collaboration
* Embedding-based similarity search

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
* (Optional) In the Analysis Options tab, set the Reasoning Effort level (None/Low/Medium/High) for models that support extended thinking.
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

**LiteLLM Proxy (Multi-Provider Gateway):**
- [LiteLLM](https://docs.litellm.ai/) - Unified API for 100+ LLM providers
- Supports AWS Bedrock, Google Vertex AI, Azure, and many others
- Select "LiteLLM" as provider type in GhidrAssist settings
- Automatic model family detection for proper message formatting

### Recommended Models

**For Agentic Mode (requires strong reasoning and tool use):**
- **Cloud**: GPT-5.1, Claude Sonnet 4.5
- **Local**: GPT-OSS, Llama 3.3 70B, DeepSeek-R1 70B, Qwen2.5 72B

**Models with Extended Thinking/Reasoning Support:**
- **OpenAI**: o1-preview, o1-mini, o3-mini, o4-mini, gpt-5 (use `reasoning_effort` parameter)
- **Anthropic**: Claude Sonnet 4.5, Claude Opus 4.5, Claude Haiku 4.5, Claude Opus 4.1/4, Claude Sonnet 4 (use `thinking.budget_tokens` parameter)
- **Local**: openai/gpt-oss-20b via Ollama/LMStudio (supports effort levels)

**Reasoning Effort Guidelines:**
- **Low**: Quick analysis, minimal thinking tokens (~5-10s, lower cost)
- **Medium**: Balanced reasoning depth (~15-30s, moderate cost)
- **High**: Deep security analysis (~30-60s, 2x cost, recommended for vulnerability hunting)

**Note**: Agentic mode requires models with strong function calling and multi-step reasoning capabilities. Smaller models may struggle with complex investigations. Extended thinking is optional but can significantly improve analysis quality for complex reverse engineering tasks.

## Using GhidrAssistMCP for Tool-Based Analysis

[GhidrAssistMCP](https://github.com/jtang613/GhidrAssistMCP) provides MCP tools that allow the LLM to interact directly with Ghidra's analysis capabilities.

### Setup

1. **Start the MCP Server**

2. **Configure GhidrAssist:**
   - Open Tools → GhidrAssist Settings → MCP Servers tab
   - Add server: `http://127.0.0.1:8081` as `GhidrAssistMCP` with transport type `SSE`

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

## Using the Semantic Graph (Graph-RAG)

The Semantic Graph tab provides a knowledge graph interface for exploring binary analysis results without requiring LLM calls for every query.

### Getting Started

1. **Index the Binary:**
   - Open the Semantic Graph tab
   - Click "ReIndex Binary" to extract structural relationships
   - Click "Semantic Analysis" to generate LLM summaries (requires API)
   - Progress is shown in the status bar

2. **Explore the Graph:**
   - **List View**: Browse all indexed functions with summaries and security flags
   - **Graph View**: Visualize call relationships with configurable N-hop depth
   - **Search View**: Full-text search across summaries and security annotations

3. **Security Analysis:**
   - Click "Security Analysis" to scan for security-relevant features
   - Results include: network APIs, file I/O, crypto usage, string patterns
   - Risk levels (LOW/MEDIUM/HIGH) are assigned based on detected features

### Explain Tab Integration

When viewing a function in the Explain tab:
- If the function is indexed, the pre-computed summary is shown instantly
- Security panel displays: risk level, activity profile, APIs used
- Click "Edit" to modify summaries (protected from auto-overwrite)
- Use "Refresh" to re-generate the summary with the LLM

### Benefits

- **Fast Queries**: Pre-computed summaries eliminate LLM latency for repeat queries
- **Offline Analysis**: Browse indexed data without API connectivity
- **Security Focus**: Automatic detection of security-relevant code patterns
- **Module Discovery**: Community detection groups related functions automatically

## Homepage
https://github.com/jtang613/GhidrAssist


## Minimum Version

This plugin requires the following minimum version of Ghidra:

* 11.0

## License

This plugin is released under a MIT license.
