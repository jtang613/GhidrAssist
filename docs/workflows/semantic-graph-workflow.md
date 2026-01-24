# Workflow: Building a Semantic Graph

This guide shows how to build and use GhidrAssist's semantic graph for structured analysis.

## Overview

The semantic graph captures:

- Function summaries and call relationships
- Security flags and activity profiles
- Taint and network flow paths
- Function communities

It can be used directly in the Semantic Graph tab or via MCP queries.

## Step-by-Step Workflow

### Step 1: Open the Semantic Graph Tab

Navigate to the Semantic Graph tab in GhidrAssist.

![Semantic Graph Empty](../screenshots/semantic-graph-empty.png)
<!-- SCREENSHOT: Semantic Graph tab before indexing, empty or baseline state -->

### Step 2: ReIndex the Binary

Click **ReIndex Binary** to build the initial graph.

This extracts:
- Functions and addresses
- Call relationships
- Imports/exports

![ReIndex](../screenshots/semantic-graph-reindex.png)
<!-- SCREENSHOT: ReIndex progress or completed status -->

### Step 3: Run Semantic Analysis

Click **Semantic Analysis** to generate LLM summaries and security metadata.

![Semantic Analysis](../screenshots/semantic-graph-semantic.png)
<!-- SCREENSHOT: List View populated with summaries and flags -->

### Step 4: Run Security Analysis

From the Manual Analysis panel, click **Security Analysis** to find source-to-sink paths.

![Security Analysis](../screenshots/semantic-graph-security.png)
<!-- SCREENSHOT: Security analysis results or highlighted functions -->

### Step 5: Run Network Flow Analysis

Click **Network Flow Analysis** to track data flow through network send/recv APIs.

### Step 6: Run Community Detection

Click **Community Detection** to group related functions using Label Propagation.

![Communities](../screenshots/semantic-graph-communities.png)
<!-- SCREENSHOT: Functions showing community labels -->

## Exploring the Graph

### List View

- Browse all functions and summaries
- Review security flags
- Navigate directly to code

### Visual Graph

- Explore relationships visually
- Adjust depth and focus on critical nodes

![Visual Graph](../screenshots/semantic-graph-visual-explore.png)
<!-- SCREENSHOT: Visual graph with nodes, edges, selected function -->

### Search

Search summaries and function names:

![Search Results](../screenshots/semantic-graph-search-results.png)
<!-- SCREENSHOT: Search tab showing results with snippets -->

## Using the Graph in Queries

With MCP enabled in Query tab, the LLM can:
- Search summaries
- Find related functions
- Trace call chains
- Identify risky code paths

## Sharing via SymGraph

If you want to contribute:

1. Open the SymGraph tab
2. Select **Graph**
3. Click **Push to SymGraph**

See [SymGraph Workflow](symgraph-workflow.md).

## Related Documentation

- [Semantic Graph Tab Reference](../tabs/semantic-graph-tab.md)
- [Query Workflow](query-workflow.md)
- [SymGraph Workflow](symgraph-workflow.md)
