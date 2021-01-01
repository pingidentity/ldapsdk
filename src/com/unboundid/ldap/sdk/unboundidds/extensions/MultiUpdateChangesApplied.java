/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



/**
 * This enum defines the set of possible values for the element of a
 * multi-update result which indicates whether any updates were applied to
 * server data.
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
 * @see MultiUpdateExtendedResult
 */
public enum MultiUpdateChangesApplied
{
  /**
   * Indicates that none of the changes contained in the multi-update request
   * were applied to the server.
   */
  NONE(0),



  /**
   * Indicates that all of the changes contained in the multi-update request
   * were applied to the server.
   */
  ALL(1),



  /**
   * Indicates that one or more changes from the multi-update request were
   * applied, but at least one failure was also encountered.
   */
  PARTIAL(2);



  // The integer value associated with this changes applied value.
  private final int intValue;



  /**
   * Creates a new multi-update changes applied value with the provided integer
   * representation.
   *
   * @param  intValue  The integer value associated with this changes applied
   *                   value.
   */
  MultiUpdateChangesApplied(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value associated with this changes applied value.
   *
   * @return  The integer value associated with this changes applied value.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the multi-update changes applied value with the specified integer
   * value.
   *
   * @param  intValue  The integer value for the changes applied value to
   *                   retrieve.
   *
   * @return  The multi-update changes applied value with the specified integer
   *          value, or {@code null} if there is no changes applied value with
   *          the specified integer value.
   */
  @Nullable()
  public static MultiUpdateChangesApplied valueOf(final int intValue)
  {
    for (final MultiUpdateChangesApplied v : values())
    {
      if (intValue == v.intValue)
      {
        return v;
      }
    }

    return null;
  }



  /**
   * Retrieves the multi-update changes applied value with the specified name.
   *
   * @param  name  The name of the multi-update changes applied value to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested multi-update changes applied value, or {@code null}
   *          if no such value is defined.
   */
  @Nullable()
  public static MultiUpdateChangesApplied forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "none":
        return NONE;
      case "all":
        return ALL;
      case "partial":
        return PARTIAL;
      default:
        return null;
    }
  }
}
