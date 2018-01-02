#!/bin/sh

# Copyright 2015-2018 Ping Identity Corporation
# All Rights Reserved.
#
# -----
#
# Copyright (C) 2015-2018 Ping Identity Corporation
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License (GPLv2 only)
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License


# Figure out which Java command to invoke.
if test -z "${UNBOUNDID_JAVA_HOME}"
then
  if test -z "${JAVA_HOME}"
  then
    JAVA_CMD="java"
  else
    JAVA_CMD="${JAVA_HOME}/bin/java"
  fi
else
  JAVA_CMD="${UNBOUNDID_JAVA_HOME}/bin/java"
fi


# Try to figure out how big the terminal window is.  The tput command-line
# utility can be used to accomplish this if it's available.
if test -f "/usr/bin/tput"
then
  if [ -n "${TERM:+x}" ]
  then
    TPUT="/usr/bin/tput"
  else
    TPUT="/usr/bin/tput -T xterm"
  fi

  COLUMNS=`${TPUT} cols`
  if test "${COLUMNS}" != ""
  then
    export COLUMNS
  fi

  LINES=`${TPUT} lines`
  if test "${LINES}" != ""
  then
    export LINES
  fi
fi

