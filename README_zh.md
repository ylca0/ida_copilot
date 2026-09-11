<div align="center">

# 🤖 IDA Copilot

**适用于 IDA Pro 9.x 的 AI 助手** —— 在 IDA 中直接与 LLM 对话，让它帮你分析、反编译、重命名、改类型、加注释。

基于 **Pydantic AI** · **OpenAI 兼容接口** · **Qt 聊天界面**

**[English](README.md)** · **[中文](README_zh.md)**

</div>

---

## ✨ 特性

- 🪟 **可停靠聊天窗口** —— 按 `Ctrl+Shift+C` 或 `Edit > Plugins > IDA Copilot` 打开，默认停靠在工作区右侧。
- 🧠 **Pydantic AI Agent** —— 真正的 Agent 循环，支持流式输出、工具调用与思考过程。
- 🔧 **30+ 个 IDA 工具** —— Agent 可读取并修改数据库：伪代码、反汇编、交叉引用、字符串、内存段、重命名、改类型、结构体/枚举、注释等等。
- ⚡ **流式输出** —— 逐 token 实时生成，并以 Markdown 渲染（表格、代码块、列表…）。
- 💭 **思考 & 工具调用卡片** —— 可折叠，默认收起，随时展开。
- 🛠️ **`run_idapython`** —— 模型可对当前数据库执行 IDAPython 脚本（沙箱化：仅允许 IDA 模块 + Python 标准库）。
- 🔌 **任意 OpenAI 兼容接口** —— OpenAI、DeepSeek、通义千问/DashScope、Ollama、vLLM 等。
- ⏱️ **可配置超时** —— 请求超时与工具执行超时。
- 🧵 **不阻塞** —— Agent 在后台工作线程运行，IDA 界面不会卡顿。

## 🖼️ 截图

![IDA Copilot](image.png)

## 📋 环境要求

- **IDA Pro 9.x**（GUI，64 位）
- IDA 内置的 **Python 3.12**（或通过 `idapyswitch` 选择的 Python 3.10+ 解释器）
- Python 依赖：见 [requirements.txt](requirements.txt)

## 🚀 快速开始

```bash
# 1) 将 Python 依赖安装到 IDA 使用的解释器
python -m pip install -r requirements.txt

# 2) 将此文件夹复制/软链到 IDA 插件目录
#    Windows:   %APPDATA%\Hex-Rays\IDA Pro\plugins\ida_copilot
#    macOS/Linux: ~/.idapro/plugins/ida_copilot
#    （也可直接放入 IDA 安装目录下的 <ida>/plugins/ 目录）

# 3) 重启 IDA
```

## 🎮 使用方法

1. 打开聊天窗口：按 **`Ctrl+Shift+C`**（或 `Edit > Plugins > IDA Copilot`）。
2. 点击 **⚙ Setting**，填写 **Endpoint**、**API Key** 和 **Model**，然后 **保存**。
3. 开始提问，例如：

   > `sub_401000` 是干什么的？把它的局部变量改成有意义的名字，并在每个调用处加上注释。

Agent 会流式返回答案，并在必要时调用 IDA 工具，你可以展开查看。

## ⚙️ 配置说明

设置会持久化到本地 JSON 文件：

| 字段 | 说明 |
|------|------|
| **Endpoint** | OpenAI 兼容接口地址，如 `https://api.openai.com/v1` |
| **API Key** | 密钥（仅本地保存，不会发送到其他任何地方） |
| **Model** | 模型名称，如 `gpt-4o`、`deepseek-chat`、`qwen-plus` |
| **Max Context** | 输入 token 软上限 |
| **Max Output** | 生成的最大 `max_tokens` |
| **Request Timeout** | 模型请求超时（秒） |
| **Tool Timeout** | 工具执行超时（秒） |
| **Thinking** | 是否启用思考/推理输出（模型支持时） |
| **System Prompt** | 可选的自定义系统提示词 |

配置文件位置：

- Windows：`%APPDATA%\Hex-Rays\IDA Pro\ida_copilot.json`
- macOS / Linux：`~/.idapro/ida_copilot.json`

环境变量可作为默认值：`OPENAI_BASE_URL`、`OPENAI_API_KEY`、`OPENAI_MODEL`。

## 🧰 Agent 工具

Agent 可调用以下工具：

**读取 / 检查**

`get_ea_by_name` · `get_name_at_ea` · `get_current_ea` · `get_function_list` ·
`get_segments` · `get_strings` · `get_xrefs_to` · `get_xrefs_from` ·
`get_function_info` · `get_disassembly` · `get_function_disassembly` ·
`get_pseudocode` · `get_data_info` · `get_type_info` · `get_comments` ·
`list_local_types`

**写入 / 编辑**

`set_name` · `set_comment` · `set_function_comment` · `set_function_prototype` ·
`set_type_at_ea` · `set_variable_name` · `set_variable_type` · `create_struct` ·
`create_enum` · `add_struct_member` · `rename_struct_member` ·
`del_struct_member` · `apply_struct_type`

**执行**

`run_idapython` —— 对数据库执行 IDAPython 代码（沙箱化）。

## 🛡️ 安全性

- `run_idapython` 只允许 **IDA 模块 + Python 标准库**；宿主模块（`os`、`sys`、`subprocess`、`socket`、`pathlib`、`ctypes`、`requests` 等）会被拦截，模型无法逃逸到宿主系统。
- 请求超时与工具超时防止长时间运行的调用卡住。

## ❓ 常见问题

<details>
<summary>支持哪些模型？</summary>

任何 **OpenAI 兼容** 的聊天模型：OpenAI、DeepSeek、通义千问/DashScope、
Ollama（本地）、vLLM、Groq、Mistral 等。把 Endpoint 指向其 `/v1` 接口地址即可。

</details>

<details>
<summary>必须要有 Hex-Rays 反编译器吗？</summary>

不需要。没有反编译器时，伪代码工具会返回明确提示，其他工具照常可用。

</details>

<details>
<summary>我的 API Key 存储安全吗？</summary>

它以明文形式保存在本地 JSON 配置文件中（除你配置的 Endpoint 外不会发送到任何地方）。请像对待本地敏感文件一样对待它。

</details>

## 📁 项目结构

```
ida_copilot/
├── ida-plugin.json      ← IDA 9.x 目录插件清单
├── requirements.txt     ← Python 依赖
├── main.py              ← 插件入口（快捷键、菜单、停靠）
└── ida_copilot/
    ├── config.py        ← 设置模型 + JSON 持久化
    ├── tools.py         ← 暴露给 Agent 的 IDA 工具
    ├── agent.py         ← Pydantic AI Agent + 流式工作线程
    └── ui.py            ← Qt 聊天窗口 + 设置对话框
```

## 🤝 贡献

欢迎提交 Issue、Feature Request 和 Pull Request。

## 📄 许可证

本项目基于 [Apache License 2.0](LICENSE) 分发。

---

**[English](README.md)**
