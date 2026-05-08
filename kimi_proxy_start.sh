#!/bin/bash
# Kimi Code 代理启动脚本（Claude Code -> Kimi Code）
# 用法: ./kimi_proxy_start.sh [start|stop|status|restart]

LOG="/root/opengm-ca/kimi_proxy.log"
PIDFILE="/tmp/kimi_proxy.pid"
PORT=4000

case "$1" in
  start)
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
      echo "Kimi Proxy 已在运行 (PID: $(cat $PIDFILE))"
      exit 0
    fi
    echo "启动 Kimi Proxy ..."
    nohup python3 /root/opengm-ca/kimi_proxy.py > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 2
    if curl -s http://localhost:$PORT/health > /dev/null; then
      echo "✅ Kimi Proxy 启动成功 (端口 $PORT)"
    else
      echo "⚠️ 启动中，请稍后检查日志: tail -f $LOG"
    fi
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then
      kill $(cat "$PIDFILE") 2>/dev/null && echo "✅ Kimi Proxy 已停止"
      rm -f "$PIDFILE"
    else
      pkill -f "kimi_proxy.py" && echo "✅ Kimi Proxy 已停止" || echo "未运行"
    fi
    ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
      echo "✅ Kimi Proxy 运行中 (PID: $(cat $PIDFILE))"
      curl -s http://localhost:$PORT/v1/models -H "Authorization: Bearer any-key" | python3 -m json.tool 2>/dev/null | grep '"id"'
    else
      echo "❌ Kimi Proxy 未运行"
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
