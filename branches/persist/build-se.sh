#!/bin/sh

# Copyright 2007-2010 UnboundID Corp.
# All Rights Reserved.
#
# -----
#
# Copyright (C) 2008-2010 UnboundID Corp.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License (GPLv2 only)
# or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
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


# Invoke ant with the default build script.
"${ANT_HOME}/bin/ant" --noconfig -f "${SCRIPT_DIR}/build-se.xml" ${*}

