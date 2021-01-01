@echo off

rem Copyright 2015-2021 Ping Identity Corporation
rem All Rights Reserved.
rem
rem -----
rem
rem Copyright 2015-2021 Ping Identity Corporation
rem
rem Licensed under the Apache License, Version 2.0 (the "License");
rem you may not use this file except in compliance with the License.
rem You may obtain a copy of the License at
rem
rem    http://www.apache.org/licenses/LICENSE-2.0
rem
rem Unless required by applicable law or agreed to in writing, software
rem distributed under the License is distributed on an "AS IS" BASIS,
rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
rem See the License for the specific language governing permissions and
rem limitations under the License.
rem
rem -----
rem
rem Copyright (C) 2015-2021 Ping Identity Corporation
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

