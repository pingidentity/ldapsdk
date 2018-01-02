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


rem Get the directory containing this batch file.
set BATDIR=%~dp0

rem Invoke a number of common script utility functions.
call "%BATDIR%\.script-util.bat"

rem Invoke the tool with the provided command-line arguments.
"%JAVA_CMD%" %JAVA_ARGS% -cp "%BATDIR%\..\unboundid-ldapsdk.jar" com.unboundid.ldap.sdk.unboundidds.DeliverPasswordResetToken %*

