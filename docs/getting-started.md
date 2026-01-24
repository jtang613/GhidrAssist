# Getting Started with GhidrAssist

This guide helps you install GhidrAssist, configure an LLM provider, and run your first analysis in Ghidra.

## Prerequisites

Before installing GhidrAssist, ensure you have:

- **Ghidra**: Version 11.0 or higher
- **Internet connection**: For cloud providers or downloading local models
- **Python (optional)**: For some local tooling, depending on your MCP server setup

## Installation

GhidrAssist is installed as a Ghidra extension.

### Step 1: Install the Extension

**Option A: Extension Manager (Recommended)**

1. Download the GhidrAssist release ZIP
2. Open Ghidra
3. Go to **File → Install Extensions**
4. Click the **+** button and select the ZIP
5. Enable the extension and restart Ghidra

**Option B: Manual Install**

1. Copy the release ZIP into:
   - `Ghidra_Install/Extensions/Ghidra/`
2. Restart Ghidra
3. Enable the extension in **File → Install Extensions**

### Step 2: Enable the Plugin

1. Open or create a project
2. Launch **CodeBrowser**
3. Go to **File → Configure → Miscellaneous**
4. Check **Enable GhidrAssist**

### Step 3: Open GhidrAssist

1. In CodeBrowser, open **Window → GhidrAssist**
2. The GhidrAssist panel appears with the tab interface

![GhidrAssist Window](screenshots/ghidrassist-window.png)
<!-- SCREENSHOT: Ghidra CodeBrowser with GhidrAssist window open and docked -->

## Initial Configuration

You need to configure at least one LLM provider.

### Accessing Settings

1. In the GhidrAssist panel, click the **Settings** tab
2. The LLM Providers section appears at the top

![Settings Tab](screenshots/settings-tab-overview.png)
<!-- SCREENSHOT: Settings tab showing empty LLM providers table with Add button visible -->

## Setting Up an LLM Provider

GhidrAssist supports multiple providers. Choose the one that fits your needs:

### Option 1: Ollama (Local, Free, Private)

Ollama runs models locally on your machine.

**Step 1: Install Ollama**

```bash
# Linux/macOS
curl -fsSL https://ollama.ai/install.sh | sh

# Windows: Download from https://ollama.ai/download
```

**Step 2: Pull a Model**

```bash
# General purpose model
ollama pull llama3.1:8b

# Reasoning model (recommended for complex analysis)
ollama pull gpt-oss:20b

# Start the server
ollama serve
```

**Step 3: Configure in GhidrAssist**

1. In Settings, click **Add** in LLM Providers
2. Fill in:
   - **Name**: `Ollama Local`
   - **Type**: `Ollama`
   - **Model**: `gpt-oss:20b`
   - **URL**: `http://localhost:11434`
   - **API Key**: Leave empty
   - **Max Tokens**: `16384`
3. Click **Save**
4. Click **Test**

![Add Ollama Provider](screenshots/add-provider-ollama.png)
<!-- SCREENSHOT: Add Provider dialog filled out for Ollama with localhost URL -->

### Option 2: OpenAI Platform API

Use OpenAI models with a paid API key.

**Step 1: Get an API Key**

1. Go to [platform.openai.com](https://platform.openai.com/)
2. Create an API key from the dashboard

**Step 2: Configure in GhidrAssist**

1. Click **Add** in LLM Providers
2. Fill in:
   - **Name**: `OpenAI`
   - **Type**: `OpenAI Platform API`
   - **Model**: `gpt-5.2-codex`
   - **URL**: Leave empty (default)
   - **API Key**: Paste your API key
   - **Max Tokens**: `20000`
3. Click **Save**
4. Click **Test**

### Option 3: Anthropic Platform API

Use Claude models with a paid API key.

**Step 1: Get an API Key**

1. Go to [console.anthropic.com](https://console.anthropic.com/)
2. Create an API key

**Step 2: Configure in GhidrAssist**

1. Click **Add** in LLM Providers
2. Fill in:
   - **Name**: `Anthropic Claude`
   - **Type**: `Anthropic Platform API`
   - **Model**: `claude-sonnet-4-5`
   - **URL**: Leave empty (default)
   - **API Key**: Paste your API key
   - **Max Tokens**: `20000`
3. Click **Save**
4. Click **Test**

### Option 4: OAuth Providers (Claude Pro/Max or ChatGPT Pro/Plus)

If you have a Claude Pro/Max or ChatGPT Pro/Plus subscription, use OAuth instead of an API key.

**Claude Pro/Max:**

1. Click **Add** in LLM Providers
2. Select **Type**: `Anthropic OAuth`
3. Enter **Name** and **Model** (e.g., `claude-sonnet-4-5`)
4. Click **Authenticate**
5. A browser window opens for login
6. After authorization, credentials are saved automatically
7. Click **Save**

**ChatGPT Pro/Plus:**

1. Click **Add** in LLM Providers
2. Select **Type**: `OpenAI OAuth`
3. Enter **Name** and **Model** (e.g., `gpt-5.2-codex`)
4. Click **Authenticate**
5. A browser window opens for login
6. After authorization, credentials are saved automatically
7. Click **Save**

![OAuth Authentication](screenshots/oauth-authenticate.png)
<!-- SCREENSHOT: Add Provider dialog showing OAuth type selected with Authenticate button -->

### Setting the Active Provider

1. Use the **Active Provider** dropdown at the bottom of the LLM Providers section
2. Select the provider you want to use

## Your First Analysis

### Step 1: Load a Binary

1. Open a binary in Ghidra
2. Wait for auto-analysis to complete

### Step 2: Navigate to a Function

1. In the Functions window, click a function
2. Or press **G** and enter an address

### Step 3: Explain the Function

1. Open the GhidrAssist panel
2. Click the **Explain** tab
3. Click **Explain Function**
4. Wait for the explanation to stream in

![First Explanation](screenshots/first-explanation.png)
<!-- SCREENSHOT: Explain tab showing a function explanation with the response text visible -->

### Step 4: Ask a Question

1. Switch to the **Query** tab
2. Type a question, for example:
   - "What does this function do?"
   - "Are there any security concerns here?"
   - "What functions does this call?"
3. Click **Submit**
4. Watch the response stream in

## Next Steps

Explore these guides:

- [Explain Workflow](workflows/explain-workflow.md)
- [Query Workflow](workflows/query-workflow.md)
- [Semantic Graph Workflow](workflows/semantic-graph-workflow.md)
- [Settings Reference](tabs/settings-tab.md)

## Troubleshooting

### "Connection failed" when testing provider

- **Ollama**: Ensure `ollama serve` is running
- **Cloud providers**: Verify your API key is correct
- **Network issues**: Check firewall and proxy settings

### No response from LLM

- Check **Window → Console** in Ghidra for errors
- Verify the model name is correct
- Ensure you have sufficient API credits

### Plugin not appearing

- Restart Ghidra after installation
- Confirm the extension is enabled
- Ensure it is enabled in **File → Configure → Miscellaneous**

### Slow responses

- Local models: Use a smaller model or a GPU
- Cloud models: Reasoning models are slower by design
- Large functions: Analyze smaller functions first
