/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.util;



/**
 * This enum defines a set of output formats that may be used in conjunction
 * with the {@link ColumnFormatter} when formatting data.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum OutputFormat
{
  /**
   * Indicates that the output should be formatted in columns.
   */
  COLUMNS,



  /**
   * Indicates that the output should be formatted as tab-delimited text.
   */
  TAB_DELIMITED_TEXT,



  /**
   * Indicates that the output should be formatted as comma-separated values.
   */
  CSV;
}
