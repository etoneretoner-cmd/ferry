#!/bin/bash
# (Re)démarre la passerelle agents si elle ne répond pas.
cd ~/workspace/gateway || exit 1
if curl -s --max-time 5 http://127.0.0.1:8000/v1/status | grep -q '"ok": true'; then
  echo "gateway already up"
  exit 0
fi
pkill -f "gateway.py" 2>/dev/null
sleep 1
nohup ./venv/bin/python gateway.py > gateway.log 2>&1 &
sleep 3
curl -s --max-time 5 http://127.0.0.1:8000/v1/status | grep -q '"ok": true' \
  && echo "gateway restarted" || { echo "gateway FAILED to start"; tail -5 gateway.log; exit 1; }
