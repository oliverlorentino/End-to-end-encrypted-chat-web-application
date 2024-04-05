@echo off
cd nginx-1.25.4
start /b nginx
cd ..
python proxy.py
echo running succefully