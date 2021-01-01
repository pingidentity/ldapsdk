/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
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
  @NotNull private final String name;



  /**
   * Creates a new object class type with the specified name.
   *
   * @param  name  The name for this object class type.
   */
  ObjectClassType(@NotNull final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name of this object class type.
   *
   * @return  The name of this object class type.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the object class type value with the specified name.
   *
   * @param  name  The name of the object class type to retrieve.  It must not
   *               be {@code null}.
   *
   * @return  The object class type with the specified name, or {@code null} if
   *          there is no type with the given name.
   */
  @Nullable()
  public static ObjectClassType forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "abstract":
        return ABSTRACT;
      case "structural":
        return STRUCTURAL;
      case "auxiliary":
        return AUXILIARY;
      default:
        return null;
    }
  }



  /**
   * Retrieves a string representation of this object class type.
   *
   * @return  A string representation of this object class type.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
