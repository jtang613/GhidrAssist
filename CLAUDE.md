# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

**Build the extension:**
```bash
GHIDRA_INSTALL_DIR=/home/jtang613/tools/ghidra_11.3.2_PUBLIC/ /opt/gradle/bin/gradle buildExtension
```
Set `GHIDRA_INSTALL_DIR` environment variable to avoid specifying it each time.

**Clean build:**
```bash
GHIDRA_INSTALL_DIR=/home/jtang613/tools/ghidra_11.3.2_PUBLIC/ /opt/gradle/bin/gradle clean
```

## Architecture Overview

GhidrAssist is a Ghidra plugin that integrates LLM capabilities for reverse engineering assistance. The architecture is built around several key components:

### Core Plugin Structure
- **GhidrAssistPlugin**: Main plugin entry point that extends ProgramPlugin. Manages program location changes and provides access to current program context.
- **GhidrAssistProvider**: Component provider that manages the UI and plugin actions. Creates the main UI and handles refresh actions.
- **GhidrAssistUI**: Main UI component with tabbed interface for different functionalities.

### API Provider System
The plugin supports multiple LLM providers through a pluggable architecture:
- **APIProvider**: Abstract base class for all LLM providers
- **APIProviderConfig**: Configuration management for API providers
- Concrete implementations: OpenAIProvider, AnthropicProvider, OllamaProvider, LMStudioProvider, OpenWebUiProvider
- Each provider handles streaming responses, function calling, and embeddings

### Core Processing Engine
- **QueryProcessor**: Handles macro expansion in queries (#line, #func, #addr, #range macros) and RAG context integration
- **LlmApi**: Main API interface that manages streaming responses, filters thinking blocks, and handles both regular and function-calling modes
- **ActionParser/ActionExecutor**: Parse and execute LLM-generated actions for automated binary analysis

### RAG (Retrieval Augmented Generation)
- **RAGEngine**: Hybrid search using both Apache Lucene (BM25) and vector embeddings
- Uses embedding cache with Guava for performance
- Supports document ingestion, chunking, and similarity search
- Integrates contextual information into LLM queries

### Data Management
- **AnalysisDB**: SQLite database for storing analysis context and program-specific data
- **RLHFDatabase**: Manages reinforcement learning from human feedback dataset generation

### UI Architecture
Tab-based interface with specialized components:
- **QueryTab**: General LLM queries with macro support
- **ExplainTab**: Code explanation for functions/instructions
- **ActionsTab**: Proposed actions and automated analysis
- **RAGManagementTab**: Document management for contextual search
- **AnalysisOptionsTab**: Configuration and settings

## Key Development Patterns

### LLM Integration
- All LLM interactions go through the APIProvider abstraction
- Responses are streamed for better UX
- Function calling support for agentic behavior
- Thinking blocks are filtered from responses in real-time

### Ghidra Integration
- Plugin follows Ghidra's ComponentProvider pattern
- Location changes are tracked to provide current context
- Program, function, and address context automatically available
- Decompiler vs disassembler view detection

### Error Handling
- Comprehensive error handling with user-friendly messages
- Timeout support for API calls
- Graceful degradation when services unavailable

## Dependencies

Key external libraries:
- Jackson for JSON processing
- RxJava for reactive programming
- Flexmark for Markdown rendering
- SQLite JDBC for database operations
- Apache Lucene for full-text search
- OkHttp for HTTP client operations

## Configuration

Settings stored in Ghidra preferences:
- API provider configurations (multiple providers supported)
- RAG database and Lucene index paths
- API timeouts and model settings
- RLHF dataset generation options