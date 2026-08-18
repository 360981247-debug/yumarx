# VeADK GitHub PR Code Review Agent

这是“做好被集成：Code Review 场景实战”文档中 **Beginner** 路径的实现：

## 双策略 PR 评审工作流

`review-specs/general.md` 与 `review-specs/security.md` 是固定的评审依据；GitHub Actions 仅从
默认分支读取它们。配置 `PR_SERVER_URL` 和 `PR_SERVER_API_KEY` 两个 Repository Secret 后，PR 工作流会
提交任务、轮询两项结果，并以幂等标记更新两条 PR 评论。

- `pr_reader` 工具从 GitHub REST API 读取公共 PR 的元数据、文件 diff 与行级评论；
- VeADK Agent 必须先调用工具，再用中文 Markdown 给出基于证据的代码评审；
- 使用 AgentKit 的流式应用入口，可直接部署到 AgentKit Runtime。

## 前置条件

- Python 3.12 和 `uv`
- 一个可调用的火山方舟模型 Endpoint ID 和 API Key
- 要评审的公共 GitHub 仓库。匿名 GitHub API 的限额较低；如需更高限额或私有仓库，请在运行环境注入 `GITHUB_TOKEN`，不要把它写入代码或 Git。

## 安装与本地运行

先填写项目根目录的 `.env`（该文件已被 Git 忽略）：

```dotenv
VOLCENGINE_ACCESS_KEY=你的火山引擎AK
VOLCENGINE_SECRET_KEY=你的火山引擎SK
MODEL_AGENT_NAME=你的方舟Endpoint ID
MODEL_AGENT_API_KEY=你的方舟API Key
```

`simple_agent.py` 启动时会自动加载此文件。

```bash
cd /Users/bytedance/Documents/ChatGPT/codexagent/veadk-starter
uv sync --frozen

# 可选：仅在需要更高 GitHub API 限额或访问已授权私有仓库时设置
read -s 'GITHUB_TOKEN?请输入 GitHub Token（可选）：'
export GITHUB_TOKEN

.venv/bin/python simple_agent.py
```

服务会监听 `http://127.0.0.1:8000`。在另一个终端中调用：

```bash
curl --location 'http://127.0.0.1:8000/invoke' \
  --header 'Content-Type: application/json' \
  --header 'user_id: local-test' \
  --header 'session_id: first-session' \
  --data '{"prompt":"请评审 https://github.com/octocat/Hello-World 的 PR #1，重点关注正确性和测试。"}'
```

按 `Control + C` 停止服务。

## 工具接口

`pr_reader(repository, pr_number, include_comments=True, max_files=50, max_patch_chars=80000)`：

- `repository` 支持 `owner/repo` 或 `https://github.com/owner/repo`；
- 返回 PR 信息、变更文件（含可用的 unified diff）和已有行级评论；`context_limits` 会明确提示文件、diff 或评论是否因上下文上限被截断；
- 文件数和 diff 长度均有上限，避免超出模型上下文；二进制文件或 GitHub 未提供 patch 的文件会显式标记；
- 仅接受 GitHub 仓库，错误会以结构化结果返回给 Agent，而不会暴露认证信息。

## 测试

```bash
cd /Users/bytedance/Documents/ChatGPT/codexagent/veadk-starter
.venv/bin/python -m unittest discover -s tests -v
```

测试使用 `httpx.MockTransport`，不会访问 GitHub，也不需要任何密钥。

## 部署到 AgentKit Runtime

先登录并按你的账户资源补全 `agentkit.yaml` 中的 Runtime、TOS 和镜像仓库名称。不要把模型 API Key 或 GitHub Token 写进这个文件；在 Runtime 的安全环境变量配置中注入它们。

```bash
cd /Users/bytedance/Documents/ChatGPT/codexagent/veadk-starter
.venv/bin/agentkit login
.venv/bin/agentkit config --show
.venv/bin/agentkit launch --config-file agentkit.yaml
```

部署完成后可用 `agentkit invoke` 或 Runtime 的调用地址验证。具体云资源名称与权限由你的火山引擎账户决定，因此本项目不会自动创建或修改云资源。
