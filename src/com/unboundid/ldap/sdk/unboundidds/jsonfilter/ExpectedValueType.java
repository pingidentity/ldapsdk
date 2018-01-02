/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.jsonfilter;



import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * An enum that defines the possible values that may be used for the
 * {@code expectedType} element of a {@link ContainsFieldJSONObjectFilter}.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum ExpectedValueType
{
  /**
   * Indicates that the target field may have a value of {@code true} or
   * {@code false}.
   */
  BOOLEAN("boolean"),



  /**
   * Indicates that the target field may have a value that is an array
   * containing zero elements.
   */
  EMPTY_ARRAY("empty-array"),



  /**
   * Indicates that the target field may have a value that is an array
   * containing at least one element.  No restriction will be placed on the type
   * of elements that may be held in the array.
   */
  NON_EMPTY_ARRAY("non-empty-array"),



  /**
   * Indicates that the target field may have a value of {@code null}.
   * {@code null}.
   */
  NULL("null"),



  /**
   * Indicates that the target field may have a value that is a number.
   */
  NUMBER("number"),



  /**
   * Indicates that the target field may have a value that is a JSON object.
   */
  OBJECT("object"),



  /**
   * Indicates that the target field may have a value that is a string.
   */
  STRING("string");



  // The name that should be used for the type.
  private final String name;



  /**
   * Creates a new expected value type with the specified name.
   *
   * @param  name  The name for the type.
   */
  ExpectedValueType(final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the expected value type with the specified name.
   *
   * @param  name  The name of the expected value type to retrieve.
   *
   * @return  The expected value type with the specified name, ro {@code null}
   *          if there is no type with the given name.
   */
  public static ExpectedValueType forName(final String name)
  {
    final String lowerName = StaticUtils.toLowerCase(name);
    for (final ExpectedValueType t : values())
    {
      if (t.name.equals(lowerName))
      {
        return t;
      }
    }

    return null;
  }



  /**
   * Retrieves a string representation of this expected value type.
   *
   * @return  A string representation of this expected value type.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
