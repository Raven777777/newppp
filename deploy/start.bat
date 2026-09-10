@echo off
cd /d "%~dp0"
.\newppp.exe -c --auth alice:secret123 --server https://newppp2.love4z.cn --url wss://newppp.love4z.cn/api/ppp --bind 127.0.0.1:1080 --http-bind 127.0.0.1:8081
pause