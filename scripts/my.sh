set -e
set -x

echo $1
echo $2

CMD="python"

tmux new session "${CMD} $1; sh" \; \
  split-window  "${CMD} $2; sh" \;
  
#   splitw -v -p 30  "${CMD} $3; sh" \; \
#   selectp -t 0 \;

# scripts/my.sh scripts/broker.py scripts/worker.py scripts/client.py