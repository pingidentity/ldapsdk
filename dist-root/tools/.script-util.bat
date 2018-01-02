@echo off

rem Copyright 2015-2018 Ping Identity Corporation
rem All Rights Reserved.
rem
rem -----
rem
rem Copyright (C) 2015-2018 Ping Identity Corporation
rem This program is free software; you can redistribute it and/or modify
rem it under the terms of the GNU General Public License (GPLv2 only)
rem or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
rem as published by the Free Software Foundation.
rem
rem This program is distributed in the hope that it will be useful,
rem but WITHOUT ANY WARRANTY; without even the implied warranty of
rem MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
rem GNU General Public License for more details.
rem
rem You should have received a copy of the GNU General Public License

rem Figure out which Java command to invoke.
if "%UNBOUNDID_JAVA_HOME%" == "" goto checkJavaHome
set JAVA_CMD=%UNBOUNDID_JAVA_HOME%\bin\java.exe
goto checkTerminalSize

:checkJavaHome
if "%JAVA_HOME%" == "" goto usePath
set JAVA_CMD=%JAVA_HOME%\bin\java.exe
goto checkTerminalSize

:usePath
set JAVA_CMD=java.exe


rem Try to figure out how wide the teriminal window is.
:checkTerminalSize
FOR /F "tokens=2" %%A IN (' %SystemRoot%\System32\mode con ^| %SystemRoot%\System32\find.exe "Columns" ') DO SET COLUMNS=%%A

