# IDA Copilot

An AI assistant plugin for **IDA Pro 9.x**. It embeds a chat window into the IDA
workspace and lets you talk to a model over any **OpenAI-compatible** endpoint.
The assistant is powered by a **Pydantic AI** agent that can call IDA APIs
directly (pseudocode, disassembly, renaming, typing, structs, comments, …), with
full **streaming**, **thinking** and **tool-calling** visualization.

> This plugin is designed for IDA 9.x (targets IDAPython / Python 3.12).

---

## 1. Design requirements

### 1.1 Opening the window

- **Hotkey `Ctrl+Shift+C`** opens the plugin window from anywhere in IDA.
- The window can also be opened from the **menu bar** (`Edit > Plugins > IDA Copilot`).
- If the window is already open, activating it again simply **brings it to the front**.

### 1.2 Window layout

The window is a **dockable widget** that by default docks to the **right half**
of the workspace (`WOPN_DP_RIGHT`). It has three areas, top to bottom:

```
+--------------------------------------------------------+
|  [⚙ Setting]      [＋ New Chat]                        |
+--------------------------------------------------------+
|                                                        |
|                    Chat messages                       |
|       (user / model / system / tool / thinking)        |
|                                                        |
+--------------------------------------------------------+
|  [ input box ................................ ] [Send] |
+--------------------------------------------------------+
```

1. **Top bar**
   - `Setting` — opens the configuration dialog (endpoint, model, keys, limits…).
   - `New Chat` — starts a fresh conversation (clears history and resets context).
2. **Middle — message list**
   - Renders **user**, **assistant/model**, and **system** messages distinctly.
   - Supports **markdown** rendering for model responses (code blocks, lists, etc.).
   - **Thinking blocks** and **tool-calling blocks** are rendered as collapsible
     cards, **collapsed by default**, with the ability to expand and re-collapse.
3. **Bottom — input area**
   - Multi-line input box.
   - The button to the right is **Send** while idle, and switches to **Stop**
     while a response is streaming; Stop cancels the in-flight generation.

### 1.3 Configuration (`Setting`)

All settings are persisted across IDA sessions (JSON in the user config dir).

| Field                    | Description                                              |
| ------------------------ | -------------------------------------------------------- |
| **Endpoint (Base URL)**  | OpenAI-compatible API base URL, e.g. `https://api.openai.com/v1` |
| **API Key**              | Secret key for the endpoint (stored locally, masked in UI) |
| **Model Name**           | Model identifier, e.g. `gpt-4o`, `deepseek-chat`, `qwen-plus` |
| **Max Context Length**   | Soft cap on input token usage; older messages are dropped/truncated when exceeded |
| **Max Output Length**    | `max_tokens` for the model’s completion |
| **Thinking**             | Enable/disable reasoning output (where the model supports it) |
| **System Prompt**        | Optional custom system prompt override |

The API key and any other secret are stored **only** on the local machine and
never logged.

### 1.4 The agent (Pydantic AI)

The chat is driven by a **Pydantic AI agent**:

- Built with an `OpenAIChatModel` (chat-completions wire format) configured with
  the user-supplied `base_url`, `api_key` and `model`.
- Supports **streaming** (`agent.run_stream`) so tokens appear incrementally.
- Supports **tool calling**: the agent is given a rich set of **IDA tools** (see below).
- Supports **thinking** content where the endpoint/model exposes it.

### 1.5 IDA tools exposed to the agent

The agent can call any of the following tools. Tools are async, run in a
dedicated worker thread, and every call returns JSON so the model can reason
about results.

**Reading / inspection**

- `get_ea_by_name` — resolve a symbol name to an address.
- `get_name_at_ea` — get the name at an address.
- `get_current_ea` — the current cursor location in IDA.
- `get_disassembly` — disassemble a range / around an address.
- `get_function_disassembly` — disassemble an entire function.
- `get_pseudocode` — Hex-Rays decompile a function (or address) to C.
- `get_function_list` — list functions (optionally filtered by a substring).
- `get_function_info` — details about a function (start/end, prototype, comment).
- `get_segments` — list memory segments (name, start, end, permissions).
- `get_strings` — list strings in the binary (optionally filtered).
- `get_xrefs_to` — list code/data references **to** an address or name.
- `get_xrefs_from` — list references **from** an address or name.
- `get_data_info` — bytes/type/string at an address.
- `get_type_info` — describe a named type (struct/union/enum/typedef) as text.
- `get_comments` — comments at an address.
- `list_local_types` — list all named types in the local type library.

**Editing / writing**

- `set_name` — rename the symbol at an address.
- `set_comment` — set a regular or repeatable comment at an address.
- `set_function_comment` — set a function’s comment.
- `set_function_prototype` — apply a C prototype to a function.
- `set_type_at_ea` — apply a C type declaration to an address.
- `set_variable_name` — rename a Hex-Rays local variable in a function.
- `set_variable_type` — change the type of a Hex-Rays local variable.
- `create_struct` — create a struct from a C-like member list.
- `add_struct_member` / `rename_struct_member` / `del_struct_member` — edit a UDT.
- `create_enum` — create a named enum from `{name: value}` entries.
- `apply_struct_type` — apply a struct type to a buffer/field reference at an address.

All editing tools run under IDA’s **undo** and **auto-analysis** tracking and
refresh the UI afterward.

### 1.6 Streaming, thinking, tool-calling display

- Responses stream into the message list token by token.
- When the model emits **thinking/reasoning**, it is shown inside a collapsed
  `Thinking` block that can be expanded.
- When the model **calls a tool**, a collapsed `Tool call` block shows the tool
  name, arguments, and the tool’s result; it is collapsed by default and can be
  expanded.
- When the model finishes, the full structured turn is committed to the message
  history so the next request has proper context.

### 1.7 Concurrency / thread-safety

- The Pydantic AI agent runs in a **background worker thread** (its own
  `asyncio` event loop).
- All results are marshalled back to the Qt/IDA UI thread through thread-safe
  **Qt signals**.
- `Stop` cancels the current run via a `CancellationToken` (and cancels the
  underlying event-loop task). The UI never blocks.

### 1.8 Error handling

- Missing/invalid configuration shows a friendly dialog prompting the user to
  open Settings.
- Network/provider errors (timeout, 4xx/5xx, malformed key) are rendered as an
  error bubble in the chat instead of crashing.
- Missing Hex-Rays (no decompiler) degrades gracefully: pseudocode tools return
  a clear message.

---

## 2. Project layout

```
ida_copilot/
├── README.md            ← this file
├── ida-plugin.json      ← IDA 9.x directory-plugin manifest
├── requirements.txt     ← Python dependencies (install into IDA's interpreter)
├── main.py              ← plugin entry point (plugin_t, hotkey, menu)
└── ida_copilot/         ← package
    ├── __init__.py
    ├── config.py        ← settings model + JSON persistence
    ├── tools.py         ← IDA tools exposed to the agent
    ├── agent.py         ← Pydantic AI agent factory + streaming worker
    └── ui.py            ← Qt chat window + settings dialog + thread-safe bridge
```

## 3. Installation

1. **Choose the directory**

   Either copy/symlink this whole folder into IDA’s `plugins` directory
   (directory plugins are auto-discovered via `ida-plugin.json`), or use a
   user-plugin directory:

   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_copilot`
   - Linux/macOS: `~/.idapro/plugins/ida_copilot`

2. **Install the Python dependencies into the interpreter IDA uses** (see
   `idapyswitch`). For a typical Python 3.12 install:

   ```bash
   python -m pip install -r requirements.txt
   ```

3. **Restart IDA.** The plugin registers the `IDA Copilot` action.

## 4. Usage

- Press **`Ctrl+Shift+C`** (or `Edit > Plugins > IDA Copilot`) to open the window.
- Click **Setting**, fill in your endpoint/model/key, and Save.
- Type a request such as:

  > What does `sub_401000` do? Rename its local variables to something meaningful
  > and add comments at each call site.

- The agent will stream its answer and, where useful, call IDA tools you can
  expand to inspect.

## 5. Development notes

- `config.py` uses `dataclasses` + JSON persistence; secrets are not logged.
- `tools.py` imports IDA modules lazily so the package can be imported outside
  IDA for testing (tools raise a clear error instead of touching a database).
- `agent.py` runs a Pydantic AI agent on a dedicated worker thread (its own
  `asyncio` loop) and consumes the granular stream via `agent.run_stream_events`
  (`PartStartEvent`, `PartDeltaEvent`, `FunctionToolCallEvent`,
  `FunctionToolResultEvent`, …) to drive the live UI through Qt signals.
- The chat history is kept in memory per conversation; `New Chat` resets it.
