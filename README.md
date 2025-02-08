# GhidrAssist
Author: **Jason Tang**

_A plugin that provides LLM helpers to explain code and assist in RE._

## Support Continued Improvements

[!["Buy Me A Beer"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/jtang613)

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

## Quickstart

* If necessary, copy the binary release ZIP archive to the Ghidra_Install/Extensions/Ghidra directory.
* Launch Ghidra -> File -> Install Extension -> Enable GhidrAssist.
* Load a binary and launch the CodeBrowser.
* CodeBrowser -> File -> Configure -> Miscellaneous -> Enable GhidrAssist.
* Open Tool Settings -> GhidraAssist.
* Ensure the RLHF and RAG database paths are appropriate for your environment.
* Point the API host to your preferred API provider and set the API key. 
* Open GhidrAssist with the GhidrAssist option in the Windows menu and start exploring.

## Screenshot
![Screenshot](/res/screenshot1.png)
![Screenshots](/res/screenshots_anim.gif)

## Homepage
https://github.com/jtang613/GhidrAssist


## Minimum Version

This plugin requires the following minimum version of Ghidra:

* 11.0

## License

This plugin is released under a MIT license.
