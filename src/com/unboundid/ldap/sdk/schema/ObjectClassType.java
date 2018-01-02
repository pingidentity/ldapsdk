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
 * This enum defines the set of object class types that are defined in the LDAP
 * protocol.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum ObjectClassType
{
  /**
   * The object class type for abstract object classes.  An abstract object
   * class may only serve as the superclass for another object class, and may
   * not appear in an entry unless at least one of its non-abstract subclasses
   * is also included.
   */
  ABSTRACT("ABSTRACT"),



  /**
   * The object class type for structural object classes.  An entry must have
   * exactly one structural object class.
   */
  STRUCTURAL("STRUCTURAL"),



  /**
   * The object class type for auxiliary object classes.  An entry may have any
   * number of auxiliary classes (although that may potentially be restricted by
   * DIT content rule definitions in the server).
   */
  AUXILIARY("AUXILIARY");



  // The name for this object class type.
  private final String name;



  /**
   * Creates a new object class type with the specified name.
   *
   * @param  name  The name for this object class type.
   */
  ObjectClassType(final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name of this object class type.
   *
   * @return  The name of this object class type.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the object class type value with the specified name.
   *
   * @param  name  The name of the object class type to retrieve.
   *
   * @return  The object class type with the specified name, or {@code null} if
   *          there is no type with the given name.
   */
  public static ObjectClassType forName(final String name)
  {
    for (final ObjectClassType t : values())
    {
      if (t.name.equalsIgnoreCase(name))
      {
        return t;
      }
    }

    return null;
  }



  /**
   * Retrieves a string representation of this object class type.
   *
   * @return  A string representation of this object class type.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
