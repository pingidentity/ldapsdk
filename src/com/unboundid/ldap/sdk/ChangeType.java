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
package com.unboundid.ldap.sdk;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.StaticUtils.*;



/**
 * This enum defines a set of change types that are associated with operations
 * that may be processed in an LDAP directory server.  The defined change types
 * are "add", "delete", "modify", and "modify DN".
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum ChangeType
{
  /**
   * Indicates that the change type is for an add operation.
   */
  ADD("add"),



  /**
   * Indicates that the change type is for a delete operation.
   */
  DELETE("delete"),



  /**
   * Indicates that the change type is for a modify operation.
   */
  MODIFY("modify"),



  /**
   * Indicates that the change type is for a modify DN operation.
   */
  MODIFY_DN("moddn");



  // The human-readable name for this change type.
  private final String name;



  /**
   * Creates a new change type with the specified name.
   *
   * @param  name  The human-readable name for this change type.
   */
  ChangeType(final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the human-readable name for this change type.
   *
   * @return  The human-readable name for this change type.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the change type with the specified name.
   *
   * @param  name  The name of the change type to retrieve.
   *
   * @return  The requested change type, or {@code null} if no such change type
   *          is defined.
   */
  public static ChangeType forName(final String name)
  {
    final String lowerName = toLowerCase(name);
    if (lowerName.equals("add"))
    {
      return ADD;
    }
    else if (lowerName.equals("delete"))
    {
      return DELETE;
    }
    else if (lowerName.equals("modify"))
    {
      return MODIFY;
    }
    else if (lowerName.equals("moddn") || lowerName.equals("modrdn"))
    {
      return MODIFY_DN;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves a string representation for this change type.
   *
   * @return  A string representation for this change type.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
