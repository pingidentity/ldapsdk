/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
 * This enum defines a set of change type values that may be used in conjunction
 * with the set notification destination extended request.
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
 */
public enum SetNotificationDestinationChangeType
{
  /**
   * Indicates that the complete set of destination details should be replaced.
   */
  REPLACE(0),



  /**
   * Indicates that the provided destination details should be added to the
   * existing set.
   */
  ADD(1),



  /**
   * Indicates tht the specified destination details should be removed from the
   * notification destination.
   */
  DELETE(2);



  // The integer value for this change type.
  private final int intValue;



  /**
   * Creates a new set notification destination change type with the provided
   * information.
   *
   * @param  intValue  The integer value for this change type.
   */
  SetNotificationDestinationChangeType(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this set notification destination change
   * type.
   *
   * @return  The integer value for this set notification destination change
   *          type.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the set notification destination change type with the specified
   * integer value.
   *
   * @param  intValue  The integer value for the change type to retrieve.
   *
   * @return  The requested change type, or {@code null} if there is no change
   *          type with the specified integer value.
   */
  @Nullable()
  public static SetNotificationDestinationChangeType valueOf(final int intValue)
  {
    for (final SetNotificationDestinationChangeType t : values())
    {
      if (t.intValue == intValue)
      {
        return t;
      }
    }

    return null;
  }



  /**
   * Retrieves the set notification destination change type with the specified
   * name.
   *
   * @param  name  The name of the set notification destination change type to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested set notification destination change type, or
   *          {@code null} if no such type is defined.
   */
  @Nullable()
  public static SetNotificationDestinationChangeType forName(
                     @NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "replace":
        return REPLACE;
      case "add":
        return ADD;
      case "delete":
        return DELETE;
      default:
        return null;
    }
  }
}
