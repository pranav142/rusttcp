#! /usr/bin/bash

export RUST_BACKTRACE=1

tcp_pid=""
cleanup() {
    if [ -n tcp_pid ]; then
        echo "Cleaning Up"
        sudo kill $tcp_pid
    fi
    exit 1
}

trap cleanup INT TERM EXIT 

./target/debug/rustcp &
if [ $? -ne 0 ]; then
    echo "Failed to run"
    exit 1
fi
tcp_pid=$!
echo "$tcp_pid"

ip link set dev tun0 up &
if [ $? -ne 0 ]; then
    echo "Failed to setup tun interface"
    exit 1
fi

ip address add 10.0.0.1 peer 10.0.0.2 dev tun0 &
if [ $? -ne 0 ]; then 
    echo "Failed to add ip address"
    exit 1
else
    echo "kernels address to tun0 is 10.0.0.1 programs address to tun0 is 10.0.0.2"
fi

wait "$tcp_pid"
