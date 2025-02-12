# GhidrAssist
Author: **Jason Tang**

_A plugin that provides LLM helpers to explain code and assist in RE._

## Support Continued Improvements

[!["Buy Me A Beer"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/jtang613)
[!["Patreon"](https://c14.patreon.com/thumbnail_Patreon_Wordmark_fb38c295a1.png)](https://patreon.com/jtang613)

## Description:

This is a LLM plugin aimed at enabling the use of local LLM's (ollama, text-generation-webui, lm-studio, etc) for assisting with binary exploration and reverse engineering. It supports any OpenAI v1-compatible API. Recommended models are LLaMA-based models such as llama3.1:8b, but others such as DeepSeek and ChatGPT work as well.

Current features include:
* Explain the current function - Works for disassembly and pseudo-C.
* Explain the current instruction - Works for disassembly and pseudo-C.
* General query - Query the LLM directly from the UI.
* Propose actions - Provide a list of proposed actions to apply.
* Function calling - Allow agent to call functions to navigate the binary, rename functions and variables.
* RAG augmentation - Supports adding contextual documents to refine query effectiveness.
* RLHF dataset generation - To enable model fine tuning.
* Settings to modify API host, key, model name and max tokens.

Future Roadmap:
* Agentic assistant - Use Autogen or similar framework for self-guided binary RE.
* Model fine tuning - Leverage the RLHF dataset to fine tune the model.

## Screenshot
![Screenshot](/res/screenshot1.png)
![Screenshots](/res/screenshots_anim.gif)

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
- ~https://docs.anthropic.com/en/docs/initial-setup~

For local LLM's, I've found that the Llama3.3:70b, Llama3.1:8b and DeepSeek-r1 produce good results.
From OpenAI, the gpt-4o-mini produces good results. ~I've not yet tested Claude, but I expect it would work fine as well.~

## Homepage
https://github.com/jtang613/GhidrAssist


## Minimum Version

This plugin requires the following minimum version of Ghidra:

* 11.0

## License

This plugin is released under a MIT license.
