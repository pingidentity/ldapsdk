/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the output stream values that may be used in conjunction
 * with the {@link CollectSupportDataOutputIntermediateResponse}.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 *
 * @see  CollectSupportDataExtendedRequest
 * @see  CollectSupportDataOutputIntermediateResponse
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum CollectSupportDataOutputStream
{
  /**
   * The output stream that will be used to indicate standard output.
   */
  STANDARD_OUTPUT("stdout", 0),



  /**
   * The output stream that will be used to indicate standard error.
   */
  STANDARD_ERROR("stderr", 1);



  // The integer value for this output stream value.
  private final int intValue;

  // The name for this output stream value.
  @NotNull private final String name;



  /**
   * Creates a new collect support data output stream value with the provided
   * information.
   *
   * @param  name      The name for this collect support data output stream
   *                   value.
   * @param  intValue  The integer value for this collect support data output
   *                   stream value.
   */
  CollectSupportDataOutputStream(@NotNull final String name, final int intValue)
  {
    this.name = name;
    this.intValue = intValue;
  }



  /**
   * Retrieves the name for this collect support data output stream value.
   *
   * @return  The name for this collect support data output stream value.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the integer value for this collect support data output stream
   * value.
   *
   * @return  The integer value for this collect support data output stream
   *          value.
   */
  public int getIntValue()
  {
    return intValue;
  }



  /**
   * Retrieves the collect support data output stream value with the given name.
   *
   * @param  name  The name for the output stream value to retrieve.  It must
   *               not be {@code null}.
   *
   * @return  The collect support data output stream value with the given name,
   *          or {@code null} if no output stream value is defined with the
   *          given name.
   */
  @Nullable()
  public static CollectSupportDataOutputStream forName(
                     @NotNull final String name)
  {
    final String lowerName = StaticUtils.toLowerCase(name).replace('-', '_');
    switch (lowerName)
    {
      case "stdout":
      case "std-out":
      case "standardout":
      case "standard_out":
      case "standardoutput":
      case "standard_output":
        return STANDARD_OUTPUT;

      case "stderr":
      case "std-err":
      case "standarderr":
      case "standard_err":
      case "standarderror":
      case "standard_error":
        return STANDARD_ERROR;

      default:
        return null;
    }
  }



  /**
   * Retrieves the collect support data output stream value with the given
   * integer value.
   *
   * @param  intValue  The integer value for the output stream value to
   *                   retrieve.  It must not be {@code null}.
   *
   * @return  The collect support data output stream value with the given
   *          integer value, or {@code null} if no output stream value is
   *          defined with the given integer value.
   */
  @Nullable()
  public static CollectSupportDataOutputStream forIntValue(final int intValue)
  {
    for (final CollectSupportDataOutputStream os : values())
    {
      if (os.intValue == intValue)
      {
        return os;
      }
    }

    return null;
  }



  /**
   * Retrieves a string representation of this collect support data output
   * stream value.
   *
   * @return  A string representation of this collect support data output stream
   *          value.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
