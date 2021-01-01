/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



  /**
   * Retrieves the output format value with the specified name.
   *
   * @param  name  The name of the output format value to retrieve.  It must not
   *               be {@code null}.
   *
   * @return  The requested output format value, or {@code null} if no such
   *          format is defined.
   */
  @Nullable()
  public static OutputFormat forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "columns":
        return COLUMNS;
      case "tabdelimitedtext":
      case "tab-delimited-text":
      case "tab_delimited_text":
        return TAB_DELIMITED_TEXT;
      case "csv":
        return CSV;
      default:
        return null;
    }
  }
}
