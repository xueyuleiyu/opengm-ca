#!/bin/bash
# LiteLLM Proxy 启动脚本（Claude Code -> Kimi）
# 用法: ./litellm_start.sh [start|stop|status|restart]

CONFIG="/root/opengm-ca/litellm_config.yaml"
LOG="/root/opengm-ca/litellm.log"
PIDFILE="/tmp/litellm_proxy.pid"
PORT=4000

case "$1" in
  start)
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
      echo "LiteLLM Proxy 已在运行 (PID: $(cat $PIDFILE))"
      exit 0
    fi
    echo "启动 LiteLLM Proxy ..."
    nohup litellm --config "$CONFIG" --port $PORT --host 0.0.0.0 > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 2
    if curl -s http://localhost:$PORT/v1/models > /dev/null; then
      echo "✅ LiteLLM Proxy 启动成功 (端口 $PORT)"
    else
      echo "⚠️ 启动中，请稍后检查日志: tail -f $LOG"
    fi
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then
      kill $(cat "$PIDFILE") 2>/dev/null && echo "✅ LiteLLM Proxy 已停止"
      rm -f "$PIDFILE"
    else
      pkill -f "litellm --config $CONFIG" && echo "✅ LiteLLM Proxy 已停止" || echo "未运行"
    fi
    ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
      echo "✅ LiteLLM Proxy 运行中 (PID: $(cat $PIDFILE))"
      echo "可用模型:"
      curl -s http://localhost:$PORT/v1/models -H "Authorization: Bearer any-key" | python3 -m json.tool 2>/dev/null | grep '"id"'
    else
      echo "❌ LiteLLM Proxy 未运行"
    fi
    ;;
  restart)
    $0 stop
    sleep 1
    $0 start
    ;;
  *)
    echo "用法: $0 {start|stop|status|restart}"
    exit 1
    ;;
esac
