/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.schema;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of attribute type usages that are defined in the
 * LDAP protocol.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum AttributeUsage
{
  /**
   * The "userApplications" attribute usage.
   */
  USER_APPLICATIONS("userApplications", false),



  /**
   * The "directoryOperation" attribute usage.
   */
  DIRECTORY_OPERATION("directoryOperation", true),



  /**
   * The "distributedOperation" attribute usage.
   */
  DISTRIBUTED_OPERATION("distributedOperation", true),



  /**
   * The "dSAOperation" attribute usage.
   */
  DSA_OPERATION("dSAOperation", true);



  // Indicates whether this is an operational attribute usage.
  private final boolean isOperational;

  // The name for this object class type.
  private final String name;



  /**
   * Creates a new attribute usage with the specified name.
   *
   * @param  name           The name for this attribute usage.
   * @param  isOperational  Indicates whether this is an operational attribute
   *                        usage.
   */
  AttributeUsage(final String name, final boolean isOperational)
  {
    this.name          = name;
    this.isOperational = isOperational;
  }



  /**
   * Retrieves the name of this attribute usage.
   *
   * @return  The name of this attribute usage.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Indicates whether this is an operational attribute usage.
   *
   * @return  {@code true} if this is an operational attribute usage.
   */
  public boolean isOperational()
  {
    return isOperational;
  }



  /**
   * Retrieves the attribute usage value with the specified name.
   *
   * @param  name  The name of the attribute usage to retrieve.
   *
   * @return  The attribute usage with the specified name, or {@code null} if
   *          there is no usage with the given name.
   */
  public static AttributeUsage forName(final String name)
  {
    for (final AttributeUsage u : values())
    {
      if (u.name.equalsIgnoreCase(name))
      {
        return u;
      }
    }

    return null;
  }



  /**
   * Retrieves a string representation of this attribute usage.
   *
   * @return  A string representation of this attribute usage.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
