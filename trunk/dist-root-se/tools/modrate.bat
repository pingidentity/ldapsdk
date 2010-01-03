@echo off

rem Copyright 2008-2010 UnboundID Corp.
rem All Rights Reserved.
rem
rem -----
rem
rem Copyright (C) 2008-2010 UnboundID Corp.
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


rem Get the directory containing this batch file.
set BATDIR=%~dp0

rem Figure out which Java command to invoke.
if "%UNBOUNDID_JAVA_HOME%" == "" goto checkJavaHome
set JAVA_CMD=%UNBOUNDID_JAVA_HOME%\bin\java.exe
goto runTool

:checkJavaHome
if "%JAVA_HOME%" == "" goto usePath
set JAVA_CMD=%JAVA_HOME%\bin\java.exe
goto runTool

:usePath
set JAVA_CMD=java.exe

:runTool
"%JAVA_CMD%" %JAVA_ARGS% -cp "%BATDIR%\..\unboundid-ldapsdk-se.jar" com.unboundid.ldap.sdk.examples.ModRate %*

