#!/bin/sh

# Copyright 2007-2019 Ping Identity Corporation
# All Rights Reserved.
#
# -----
#
# Copyright (C) 2007-2019 Ping Identity Corporation
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


# Determine the path to this script.
ORIG_DIR=`pwd`
cd `dirname $0`

SCRIPT_DIR=`pwd`
cd "${ORIG_DIR}"


# Set ANT_HOME to the path of the ant installation.
ANT_HOME="${SCRIPT_DIR}/ext/ant"
export ANT_HOME

# SONAR will run out of heap space if this isn't set.
for arg in "${@}"
do
  if test "${arg}" = "sonar"
  then
    if test -z "${ANT_OPTS}"
    then
      ANT_OPTS="-Xms512m -Xmx1024m"
      export ANT_OPTS
    fi
  fi
done

# Invoke ant with the default build script.
"${ANT_HOME}/bin/ant" --noconfig ${*}

