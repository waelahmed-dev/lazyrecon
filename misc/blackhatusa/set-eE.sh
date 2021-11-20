#!/bin/bash
set -eE # same as: `set -o errexit -o errtrace`
set -m  # process management

# error handler
trap errorfunc ERR
# teardown handler
trap exitfunc EXIT

errorfunc(){
    PID=$$
    echo "error PID = $PID"
    echo "error $(basename $0): ${FUNCNAME} ${LINENO} ${BASH_LINENO[@]}"
    ps -f
    jobs -l | awk '{print $2}' | xargs kill -9
    kill -- -${PID} &>/dev/null || true
}

exitfunc(){
    PID=$$
    echo "exit PID=$PID"
    echo "exit $(basename $0): ${FUNCNAME} ${LINENO} ${BASH_LINENO[@]}"
    ps -f
    jobs -l | awk '{print $2}' | xargs kill -9
    kill -- -${PID} &>/dev/null || true
    echo "DONE"
}

brokenfunc(){
  sleep 555 &
  echo "https://hackerone.com" | nuclei -silents -t $HOMEDIR/nuclei-templates/technologies/
}

recon(){
  CPID=$$
  echo "func PID = $CPID"
  brokenfunc &
  tmpdemopid=$!
  wait $tmpdemopid
  echo "func PID=$tmpdemopid"
}

main() {
  MAINPID=$$
  echo "[main] PID = $MAINPID"
  recon
  echo "[main] exit point PID=$MAINPID"
}

main
