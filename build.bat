@echo off
chcp 65001
echo Cleaning old build files...
rmdir /s /q build dist
del /f /q "WPS进程清理工具.spec"

echo Building...
pyinstaller --noconfirm ^
    --clean ^
    wps_killer.spec

echo Build completed!
pause