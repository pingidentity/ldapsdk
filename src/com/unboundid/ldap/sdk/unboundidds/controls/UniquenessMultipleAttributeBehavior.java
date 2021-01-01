/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of multiple attribute behavior values that may be
 * used in conjunction with the {@link UniquenessRequestControl}.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum UniquenessMultipleAttributeBehavior
{
  /**
   * Indicates that the server should treat each configured attribute
   * separately.  For each attribute, the server will attempt to identify
   * conflicts with other entries that have the same value for the same
   * attribute, but it will not flag cases in which the same value is used in
   * different attribute types.  This behavior is equivalent to including
   * multiple controls in the request, where each control only references a
   * single attribute type.
   */
  UNIQUE_WITHIN_EACH_ATTRIBUTE(0),



  /**
   * Indicates that the server should flag any case in which any entry has a
   * conflicting value in any of the configured attribute types, including cases
   * in which the same value appears in multiple attributes within the same
   * entry.
   */
  UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_IN_SAME_ENTRY(1),



  /**
   * Indicates that the server should flag any case in which any entry has a
   * conflicting value in any of the configured attribute types, with the
   * exception that conflicts will be permitted across different attributes in
   * the same entry.
   */
  UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_IN_SAME_ENTRY(2),



  /**
   * Indicates that the server should flag any case in which another entry has
   * the same combination of values for all of the configured attribute types.
   * This will only apply to entries that have at least one value for each of
   * the target attributes.  If any of the target attributes has multiple
   * values, then the server will flag each unique combination of those values.
   */
  UNIQUE_IN_COMBINATION(3);



  // The integer value for this uniqueness multiple attribute behavior.
  private final int intValue;



  /**
   * Creates a new uniqueness multiple attribute behavior with the provided
   * integer value.
   *
   * @param  intValue  The integer value for this uniqueness multiple attribute
   *                   behavior.
   */
  UniquenessMultipleAttributeBehavior(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this uniqueness multiple attribute
   * behavior.
   *
   * @return  The integer value for this uniqueness multiple attribute behavior.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the uniqueness multiple attribute behavior with the specified
   * integer value.
   *
   * @param  intValue  The integer value for the uniqueness multiple attribute
   *                   behavior to retrieve.
   *
   * @return  The uniqueness multiple attribute behavior for the provided
   *          integer value, or {@code null} if there is no multiple attribute
   *          behavior with the given integer value.
   */
  @Nullable()
  public static UniquenessMultipleAttributeBehavior valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return UNIQUE_WITHIN_EACH_ATTRIBUTE;
      case 1:
        return UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_IN_SAME_ENTRY;
      case 2:
        return UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_IN_SAME_ENTRY;
      case 3:
        return UNIQUE_IN_COMBINATION;
      default:
        return null;
    }
  }



  /**
   * Retrieves the uniqueness multiple attribute behavior with the specified
   * name.
   *
   * @param  name  The name of the uniqueness multiple attribute behavior to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested uniqueness multiple attribute behavior, or
   *          {@code null} if no such behavior is defined.
   */
  @Nullable()
  public static UniquenessMultipleAttributeBehavior forName(
                     @NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "uniquewithineachattribute":
      case "unique-within-each-attribute":
      case "unique_within_each_attribute":
        return UNIQUE_WITHIN_EACH_ATTRIBUTE;
      case "uniqueacrossallattributesincludinginsameentry":
      case "unique-across-all-attributes-including-in-same-entry":
      case "unique_across_all_attributes_including_in_same_entry":
        return UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_IN_SAME_ENTRY;
      case "uniqueacrossallattributesexceptinsameentry":
      case "unique-across-all-attributes-except-in-same-entry":
      case "unique_across_all_attributes_except_in_same_entry":
        return UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_IN_SAME_ENTRY;
      case "uniqueincombination":
      case "unique-in-combination":
      case "unique_in_combination":
        return UNIQUE_IN_COMBINATION;
      default:
        return null;
    }
  }
}
