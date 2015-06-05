@echo off

rem Copyright 2008-2015 UnboundID Corp.
rem All Rights Reserved.


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
"%JAVA_CMD%" %JAVA_ARGS% -cp "%BATDIR%\..\unboundid-ldapsdk-ce.jar;%CLASSPATH%" com.unboundid.ldap.sdk.persist.GenerateSchemaFromSource %*

