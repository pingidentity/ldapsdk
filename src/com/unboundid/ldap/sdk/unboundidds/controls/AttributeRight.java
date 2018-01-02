/*
 * Copyright 2008-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.EnumSet;

import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.StaticUtils.*;



/**
 * This enum contains the set of possible attribute-level rights that may be
 * described for an attribute in an entry retrieved with the get effective
 * rights control.
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
public enum AttributeRight
{
  /**
   * The attribute right that indicates that the user has sufficient permission
   * to perform search operations that target the associated attribute.
   */
  SEARCH("search"),



  /**
   * The attribute right that indicates that the user has sufficient permission
   * to read the values of the specified attribute.
   */
  READ("read"),



  /**
   * The attribute right that indicates that the user has sufficient permission
   * to make comparisons against the value of the specified attribute.
   */
  COMPARE("compare"),



  /**
   * The attribute right that indicates that the user has sufficient permission
   * to alter the values of the specified attribute.
   */
  WRITE("write"),



  /**
   * The attribute right that indicates that the user has sufficient permission
   * to add his or her own DN to the set of values for the specified attribute.
   */
  SELFWRITE_ADD("selfwrite_add"),



  /**
   * The attribute right that indicates that the user has sufficient permission
   * to remove his or her own DN from the set of values for the specified
   * attribute.
   */
  SELFWRITE_DELETE("selfwrite_delete"),



  /**
   * The attribute right that indicates that the user has sufficient permission
   * to perform operations involving proxied authorization with the attribute.
   */
  PROXY("proxy");



  // The name of this attribute right.
  private final String name;



  /**
   * Creates a new attribute right with the specified name.
   *
   * @param  name  The name for this attribute right.
   */
  AttributeRight(final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name of this attribute right.
   *
   * @return  The name of this attribute right.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the attribute right for the specified name.
   *
   * @param  name  The name for which to retrieve the corresponding attribute
   *               right.
   *
   * @return  The requested attribute right, or {@code null} if there is no such
   *          right.
   */
  public static AttributeRight forName(final String name)
  {
    final String lowerName = toLowerCase(name);

    for (final AttributeRight r : EnumSet.allOf(AttributeRight.class))
    {
      if (r.name.equals(lowerName))
      {
        return r;
      }
    }

    return null;
  }



  /**
   * Retrieves a string representation of this attribute right.
   *
   * @return  A string representation of this attribute right.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
