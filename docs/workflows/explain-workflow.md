# Workflow: Building Context with the Explain Tab

This guide shows how to use the Explain tab to document your understanding of a binary in Ghidra.

## Overview

The Explain tab generates LLM-powered explanations of functions and stores them for later use. It is best for building persistent context across a project.

## When to Use the Explain Tab

Use Explain when you want to:

- Understand a function at a high level
- Document findings for later reference
- Capture security-relevant information
- Build a knowledge base as you analyze

For ad-hoc questions, use the [Query tab](../tabs/query-tab.md).

## Step-by-Step Workflow

### Step 1: Select a Function

Navigate to a function in Ghidra:

1. Click a function in the Functions window
2. Or press **G** to jump to an address

The Explain tab shows the current function automatically.

### Step 2: Generate an Explanation

Click **Explain Function** to generate a summary.

The explanation includes:
- Purpose and behavior
- Parameters and return values
- Notable operations

### Step 3: Review Security Analysis

Expand the security panel to view:

| Field | Description |
|-------|-------------|
| **Risk Level** | Low / Medium / High risk assessment |
| **Activity Profile** | Behavioral category |
| **Security Flags** | Detected patterns |
| **Network APIs** | Network calls detected |
| **File I/O APIs** | File operations detected |

### Step 4: Edit and Save

If needed:

1. Click **Edit**
2. Modify the markdown
3. Click **Save** to store updates

Edits are persisted and protected from auto-overwrite.

### Step 5: Clear Analysis (Optional)

Use **Clear** to remove stored analysis for the current function.

## Enhancing Explanations

### Using RAG

If you have documents indexed in the [RAG tab](../tabs/rag-tab.md):

1. Enable **Use RAG** in Query tab before analysis
2. Run Explain Function
3. The LLM uses relevant document context

### Using MCP

If MCP servers are configured:

1. Enable **Use MCP Tools** in Query tab
2. Run Explain Function
3. The LLM can call tools for extra context

## Explain Line

The **Explain Line** button is currently disabled and marked as "Coming Soon" in GhidrAssist.

## Building a Documentation Set

To systematically document a binary:

1. Start with entry points and exports
2. Follow call chains through key functions
3. Prioritize security-relevant functions
4. Update explanations as your understanding improves

Explanations are stored by binary hash and function address.

## Related Documentation

- [Explain Tab Reference](../tabs/explain-tab.md)
- [Query Workflow](query-workflow.md)
- [RAG Tab](../tabs/rag-tab.md)
