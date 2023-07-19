@ECHO OFF
:repeat
cd C:\Qbot_Project\Back_end
call fast-env\scripts\activate
start uvicorn main:app --host 192.168.60.200 --reload
goto repeat"