#!/bin/sh

# Copyright 2007-2015 UnboundID Corp.
# All Rights Reserved.


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

