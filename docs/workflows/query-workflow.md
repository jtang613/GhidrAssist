# Workflow: Interactive Queries and the ReAct Agent

This guide walks through using the Query tab for interactive analysis and autonomous investigation.

## Overview

The Query tab supports:

- Multi-turn chat
- Context macros
- MCP tool calling
- ReAct agentic investigations

## Basic Query Workflow

### Ask a Question

1. Open the Query tab
2. Type your question
3. Click **Submit**

![Basic Query](../screenshots/query-basic-question.png)
<!-- SCREENSHOT: Query tab showing a simple question and streaming response -->

### Use Context Macros

Macros insert context from Ghidra:

| Macro | Description |
|-------|-------------|
| `#func` | Current function code (decompiler or disassembly) |
| `#addr` | Data at current address |
| `#line` | Current line (decompiler or disassembly) |
| `#range(start, end)` | Data in address range |

Example:
```
What does #func do with user input?
```

![Context Macro](../screenshots/query-context-macro.png)
<!-- SCREENSHOT: Query showing #func macro and context-based response -->

### Manage Conversations

- **New**: Start a new conversation
- **Delete**: Remove selected chats
- Chats persist across sessions

## MCP Tool Integration

When **Use MCP Tools** is enabled, the LLM can call tools to gather data.

![MCP Tool Call](../screenshots/query-mcp-tools.png)
<!-- SCREENSHOT: Query conversation showing tool calls and results -->

Common tool usage:
- Decompile or disassemble
- Query cross-references
- Navigate to addresses
- Query the semantic graph

## ReAct Agent Workflow

### When to Use ReAct

Use agentic mode for:

- Complex investigations
- Vulnerability searches
- Call-graph exploration
- Data flow tracing

### Enabling ReAct

1. Enable **Use MCP Tools**
2. Enable **Agentic Mode (ReAct)**
3. Ask your question

### The Investigation Process

1. **Planning**: Create a todo list of investigation steps
2. **Investigation**: Call tools and gather evidence
3. **Reflection**: Update the plan if needed
4. **Synthesis**: Provide a final, evidence-based answer

![ReAct Planning](../screenshots/query-react-planning.png)
<!-- SCREENSHOT: ReAct planning checklist visible in Query tab -->

![ReAct Synthesis](../screenshots/query-react-synthesis.png)
<!-- SCREENSHOT: ReAct final response with findings and summary -->

### Stopping Early

Click **Stop** to cancel the investigation. GhidrAssist will save partial findings in the chat history.

## Extended Thinking

Configure reasoning depth in [Settings](../tabs/settings-tab.md):

| Level | Best For |
|-------|----------|
| None | Quick responses |
| Low | Light reasoning |
| Medium | Moderate complexity |
| High | Deep analysis |

Higher levels improve quality but increase latency and cost.

## Tips for Effective Queries

- Be specific about what you want analyzed
- Use macros to include relevant code
- Enable MCP for complex questions
- Use ReAct for multi-step investigations

## Related Documentation

- [Query Tab Reference](../tabs/query-tab.md)
- [Explain Workflow](explain-workflow.md)
- [Semantic Graph Workflow](semantic-graph-workflow.md)
- [Settings Tab](../tabs/settings-tab.md)
