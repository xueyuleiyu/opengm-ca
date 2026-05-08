#!/usr/bin/env python3
"""
轻量级代理：Claude Code (Anthropic API) -> Kimi Code (OpenAI API)
支持协议转换 + User-Agent 伪装 + 流式响应转换
"""

import os
import json
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
import httpx

app = FastAPI(title="Claude Code -> Kimi Code Proxy")

KIMI_BASE_URL = "https://api.kimi.com/coding/v1"
KIMI_API_KEY = os.environ.get("MOONSHOT_API_KEY", "")
USER_AGENT = "claude-code/0.1.0"


def anthropic_to_openai_messages(anthropic_messages):
    """Anthropic messages 格式与 OpenAI 基本一致，直接透传"""
    openai_messages = []
    for msg in anthropic_messages:
        if isinstance(msg.get("content"), str):
            openai_messages.append({"role": msg["role"], "content": msg["content"]})
        elif isinstance(msg.get("content"), list):
            texts = []
            for block in msg["content"]:
                if block.get("type") == "text":
                    texts.append(block.get("text", ""))
                elif block.get("type") == "image":
                    texts.append("[image]")
            openai_messages.append({"role": msg["role"], "content": "\n".join(texts)})
    return openai_messages


def openai_to_anthropic_response(openai_data):
    """将 OpenAI chat.completion 响应转为 Anthropic message 响应"""
    choice = openai_data["choices"][0]
    content_text = choice["message"].get("content", "")
    reasoning = choice["message"].get("reasoning_content", "")

    content_blocks = []
    if reasoning:
        content_blocks.append({
            "type": "thinking",
            "thinking": reasoning,
            "signature": ""
        })
    if content_text:
        content_blocks.append({
            "type": "text",
            "text": content_text
        })

    return {
        "id": openai_data.get("id", "msg_"),
        "type": "message",
        "role": "assistant",
        "model": openai_data.get("model", "kimi-for-coding"),
        "content": content_blocks,
        "stop_reason": "end_turn" if choice.get("finish_reason") == "stop" else choice.get("finish_reason"),
        "usage": {
            "input_tokens": openai_data.get("usage", {}).get("prompt_tokens", 0),
            "output_tokens": openai_data.get("usage", {}).get("completion_tokens", 0)
        }
    }


async def convert_sse_stream(response):
    """将 OpenAI SSE 流实时转换为 Anthropic SSE 流"""
    msg_id = None
    sent_thinking_start = False
    sent_text_start = False
    thinking_done = False
    index = 0
    input_tokens = 0

    async for line in response.aiter_lines():
        if not line.startswith("data:"):
            continue
        data_str = line[5:].strip()
        if data_str == "[DONE]":
            # 发送结束事件
            if sent_text_start or sent_thinking_start:
                yield f"event: content_block_stop\ndata: {json.dumps({'type':'content_block_stop','index':index})}\n\n"
            yield f"event: message_delta\ndata: {json.dumps({'type':'message_delta','delta':{'stop_reason':'end_turn'},'usage':{'output_tokens':0}})}\n\n"
            yield f"event: message_stop\ndata: {json.dumps({'type':'message_stop'})}\n\n"
            break

        try:
            chunk = json.loads(data_str)
        except json.JSONDecodeError:
            continue

        if msg_id is None:
            msg_id = chunk.get("id", "msg_")
            # 发送 message_start
            yield f"event: message_start\ndata: {json.dumps({'type':'message_start','message':{'id':msg_id,'type':'message','role':'assistant','content':[],'model':'kimi-for-coding','stop_reason':None,'usage':{'input_tokens':input_tokens,'output_tokens':1}}})}\n\n"

        delta = chunk.get("choices", [{}])[0].get("delta", {})
        reasoning = delta.get("reasoning_content", "")
        content = delta.get("content", "")
        finish_reason = chunk.get("choices", [{}])[0].get("finish_reason")

        # reasoning content 处理
        if reasoning and not thinking_done:
            if not sent_thinking_start:
                sent_thinking_start = True
                yield f"event: content_block_start\ndata: {json.dumps({'type':'content_block_start','index':index,'content_block':{'type':'thinking','thinking':''}})}\n\n"
            yield f"event: content_block_delta\ndata: {json.dumps({'type':'content_block_delta','index':index,'delta':{'type':'thinking_delta','thinking':reasoning}})}\n\n"

        # content 处理
        if content:
            if sent_thinking_start and not thinking_done:
                thinking_done = True
                yield f"event: content_block_stop\ndata: {json.dumps({'type':'content_block_stop','index':index})}\n\n"
                index += 1

            if not sent_text_start:
                sent_text_start = True
                yield f"event: content_block_start\ndata: {json.dumps({'type':'content_block_start','index':index,'content_block':{'type':'text','text':''}})}\n\n"
            yield f"event: content_block_delta\ndata: {json.dumps({'type':'content_block_delta','index':index,'delta':{'type':'text_delta','text':content}})}\n\n"

        if finish_reason:
            if (sent_text_start or sent_thinking_start) and not (thinking_done or not sent_thinking_start):
                # 需要关闭当前 block
                if sent_thinking_start and not thinking_done:
                    thinking_done = True
                    yield f"event: content_block_stop\ndata: {json.dumps({'type':'content_block_stop','index':index})}\n\n"
                    index += 1
                elif sent_text_start:
                    yield f"event: content_block_stop\ndata: {json.dumps({'type':'content_block_stop','index':index})}\n\n"


@app.post("/v1/messages")
async def anthropic_messages(request: Request):
    """Anthropic /v1/messages 端点 -> Kimi /v1/chat/completions"""
    body = await request.json()

    openai_body = {
        "model": "kimi-for-coding",
        "messages": anthropic_to_openai_messages(body.get("messages", [])),
        "max_tokens": body.get("max_tokens", 4096),
        "stream": body.get("stream", False),
    }

    if "temperature" in body:
        openai_body["temperature"] = body["temperature"]
    if "top_p" in body:
        openai_body["top_p"] = body["top_p"]
    if "stop_sequences" in body:
        openai_body["stop"] = body["stop_sequences"]

    headers = {
        "Authorization": f"Bearer {KIMI_API_KEY}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }

    async with httpx.AsyncClient(timeout=300.0) as client:
        resp = await client.post(
            f"{KIMI_BASE_URL}/chat/completions",
            headers=headers,
            json=openai_body
        )

    if openai_body["stream"]:
        return StreamingResponse(
            convert_sse_stream(resp),
            status_code=resp.status_code,
            media_type="text/event-stream"
        )

    openai_data = resp.json()

    if resp.status_code != 200:
        return Response(
            content=json.dumps(openai_data),
            status_code=resp.status_code,
            media_type="application/json"
        )

    anthropic_resp = openai_to_anthropic_response(openai_data)
    return Response(
        content=json.dumps(anthropic_resp),
        status_code=200,
        media_type="application/json"
    )


@app.get("/v1/models")
async def list_models():
    return {
        "data": [
            {"id": "claude-sonnet-4-6", "object": "model", "created": 1677610602, "owned_by": "anthropic"},
            {"id": "claude-opus-4-6", "object": "model", "created": 1677610602, "owned_by": "anthropic"}
        ],
        "object": "list"
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=4000)
