@echo off

rem Copyright 2013-2017 UnboundID Corp.
rem All Rights Reserved.


rem Get the directory containing this batch file.
set BATDIR=%~dp0

rem Invoke a number of common script utility functions.
call "%BATDIR%\.script-util.bat"

rem Invoke the tool with the provided command-line arguments.
"%JAVA_CMD%" %JAVA_ARGS% -cp "%BATDIR%\..\unboundid-ldapsdk-ce.jar;%CLASSPATH%" com.unboundid.ldap.sdk.examples.IdentifyReferencesToMissingEntries %*

