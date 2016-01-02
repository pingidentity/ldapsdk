@echo off

rem Copyright 2007-2016 UnboundID Corp.
rem All Rights Reserved.


setlocal
set SCRIPT_DIR=%~dP0

set ANT_HOME=%SCRIPT_DIR%\ext\ant
"%ANT_HOME%\bin\ant" %*

