#!/bin/sh

# Copyright 2007-2021 Ping Identity Corporation
# All Rights Reserved.
#
# -----
#
# Copyright 2007-2021 Ping Identity Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# -----
#
# Copyright (C) 2007-2021 Ping Identity Corporation
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

