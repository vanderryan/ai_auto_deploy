#!/bin/bash
/root/anaconda/bin/streamlit run sniff_parse.py &
pid=`ps -ef | awk '/streamlit/{ print $2 }'`

echo "Running.........."
echo PID is $pid

echo "*************Press ENTER to stop*************"
echo "*************Press ENTER to stop*************"
echo "*************Press ENTER to stop*************"
read -p "*************Press ENTER to stop*************" stop

kill -9 $pid
> tcp_header.csv
> ip_header.csv
> ethernet_header.csv
