# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging

from dotenv import load_dotenv
from google.adk.agents import RunConfig
from google.adk.agents.run_config import StreamingMode
from google.adk.tools import FunctionTool
from google.genai.types import Content, Part
from veadk import Agent, Runner

from agentkit.apps import AgentkitSimpleApp
from pr_reader import pr_reader

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Load local credentials before VeADK initializes the model client.
load_dotenv()

app = AgentkitSimpleApp()

app_name = "code_review_agent"

agent_name = "code_review_agent"
description = "读取 GitHub Pull Request 并生成可执行代码评审意见的 Agent。"
system_prompt = """你是一名严谨的高级代码评审工程师。

当用户要求评审、分析或解释 GitHub Pull Request 时，必须先调用 `pr_reader` 获取
真实的 PR 元数据、diff 与已有评论；不要根据 PR 标题或用户描述臆测变更内容。仅在用户
没有提供仓库和 PR 编号时，简洁地向其索取 `owner/repo` 与 PR 编号。

评审时只报告有证据、可操作的问题。优先级从高到低为：安全、数据完整性/正确性、可靠性、
兼容性、性能、可维护性、测试缺口。对于每项问题，请说明：
- 严重级别（阻塞 / 建议）
- 文件及对应 diff 行（无法确定精确行时明确说明）
- 风险或潜在影响
- 可行的修复建议

以中文 Markdown 输出，按以下结构组织：`## 评审摘要`、`## 发现的问题`、
`## 建议补充的测试`、`## 结论`。没有问题时明确写“未发现阻塞问题”，同时说明评审
受 diff 截断、二进制文件或缺少上下文的限制。不要声称已经执行过代码、测试或访问过
仓库中未由工具返回的文件。
"""


tools = [FunctionTool(pr_reader)]


agent = Agent(
    name=agent_name,
    description=description,
    instruction=system_prompt,
    tools=tools,
)
agent.model._additional_args["stream_options"] = {"include_usage": True}
runner = Runner(agent=agent, app_name=app_name)


@app.entrypoint
async def run(payload: dict, headers: dict):
    prompt = payload["prompt"]
    user_id = headers["user_id"]
    session_id = headers["session_id"]

    logger.info(
        f"Running agent with prompt: {prompt}, user_id: {user_id}, session_id: {session_id}"
    )

    session_service = runner.short_term_memory.session_service  # type: ignore

    # prevent session recreation
    session = await session_service.get_session(
        app_name=app_name, user_id=user_id, session_id=session_id
    )
    if not session:
        await session_service.create_session(
            app_name=app_name, user_id=user_id, session_id=session_id
        )

    new_message = Content(role="user", parts=[Part(text=prompt)])
    try:
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=new_message,
            run_config=RunConfig(streaming_mode=StreamingMode.SSE),
        ):
            # Format as SSE data
            sse_event = event.model_dump_json(exclude_none=True, by_alias=True)
            logger.debug("Generated event in agent run streaming: %s", sse_event)
            yield sse_event
    except Exception as e:
        logger.exception("Error in event_generator: %s", e)
        # You might want to yield an error event here
        error_data = json.dumps({"error": str(e)})
        yield error_data


@app.ping
def ping() -> str:
    return "pong!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
