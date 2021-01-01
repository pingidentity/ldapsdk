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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.HashMap;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a data type for modification type values.  Clients should
 * generally use one of the {@code ADD}, {@code DELETE}, {@code REPLACE}, or
 * {@code INCREMENT} values, although it is possible to create a new
 * modification type with a specified integer value if necessary using the
 * {@link #valueOf(int)} method.  The following modification types are defined:
 * <UL>
 *   <LI>{@code ADD} -- Indicates that the provided value(s) should be added to
 *       the specified attribute in the target entry.  If the attribute does not
 *       already exist, it will be created.  If it does exist, then the new
 *       values will be merged added to the existing values.  At least one value
 *       must be provided with the {@code ADD} modification type, and none of
 *       those values will be allowed to exist in the entry.</LI>
 *   <LI>{@code DELETE} -- Indicates that the specified attribute or attribute
 *       values should be removed from the entry.  If no values are provided,
 *       then the entire attribute will be removed.  If one or more values are
 *       given, then only those values will be removed.  If any values are
 *       provided, then all of those values must exist in the target entry.</LI>
 *   <LI>{@code REPLACE} -- Indicates that the set of values for the specified
 *       attribute should be replaced with the provided value(s).  If no values
 *       are given, then the specified attribute will be removed from the entry
 *       if it exists, or no change will be made.  If one or more values are
 *       provided, then those values will replace the existing values if the
 *       attribute already exists, or a new attribute will be added with those
 *       values if there was previously no such attribute in the entry.</LI>
 *   <LI>{@code INCREMENT} -- Indicates that the value of the specified
 *       attribute should be incremented.  The target entry must have exactly
 *       one value for the specified attribute and it must be an integer.  The
 *       modification must include exactly one value, and it must be an integer
 *       which specifies the amount by which the existing value is to be
 *       incremented (or decremented, if the provided value is negative).</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ModificationType
       implements Serializable
{
  /**
   * The integer value for the "add" modification type.
   */
  public static final int ADD_INT_VALUE = 0;



  /**
   * A predefined add modification type, which indicates that the associated
   * value(s) should be added to the specified attribute in the target entry.
   * If the attribute does not already exist, it will be created.  If it does
   * exist, then the new values will be merged added to the existing values.  At
   * least one value must be provided with the {@code ADD} modification type,
   * and none of those values will be allowed to exist in the entry.
   */
  @NotNull public static final ModificationType ADD =
       new ModificationType("ADD", ADD_INT_VALUE);



  /**
   * The integer value for the "delete" modification type.
   */
  public static final int DELETE_INT_VALUE = 1;



  /**
   * A predefined delete modification type, which indicates that the specified
   * attribute or attribute values should be removed from the entry.  If no
   * values are provided, then the entire attribute will be removed.  If one or
   * more values are given, then only those values will be removed.  If any
   * values are provided, then all of those values must exist in the target
   * entry.
   */
  @NotNull public static final ModificationType DELETE =
       new ModificationType("DELETE", DELETE_INT_VALUE);



  /**
   * The integer value for the "replace" modification type.
   */
  public static final int REPLACE_INT_VALUE = 2;



  /**
   * A predefined replace modification type, which indicates that the set of
   * values for the specified attribute should be replaced with the provided
   * value(s).  If no values are given, then the specified attribute will be
   * removed from the entry if it exists, or no change will be made.  If one or
   * more values are provided, then those values will replace the existing
   * values if the attribute already exists, or a new attribute will be added
   * with those values if there was previously no such attribute in the entry.
   */
  @NotNull public static final ModificationType REPLACE =
       new ModificationType("REPLACE", REPLACE_INT_VALUE);



  /**
   * The integer value for the "increment" modification type.
   */
  public static final int INCREMENT_INT_VALUE = 3;



  /**
   * A predefined increment modification type, which indicates that the value of
   * the specified attribute should be incremented.  The target entry must have
   * exactly one value for the specified attribute and it must be an integer.
   * The modification must include exactly one value, and it must be an integer
   * which specifies the amount by which the existing value is to be incremented
   * (or decremented, if the provided value is negative).
   */
  @NotNull public static final ModificationType INCREMENT =
       new ModificationType("INCREMENT", INCREMENT_INT_VALUE);



  /**
   * The set of result code objects created with undefined int result code
   * values.
   */
  @NotNull private static final HashMap<Integer,ModificationType>
       UNDEFINED_MOD_TYPES = new HashMap<>(StaticUtils.computeMapCapacity(10));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7863114394728980308L;



  // The integer value for this modification type.
  private final int intValue;

  // The name to use for this modification type.
  @NotNull private final String name;



  /**
   * Creates a new modification type with the specified integer value.
   *
   * @param  intValue  The integer value to use for this modification type.
   */
  private ModificationType(final int intValue)
  {
    this.intValue = intValue;

    name = String.valueOf(intValue);
  }



  /**
   * Creates a new modification type with the specified name and integer value.
   *
   * @param  name      The name to use for this modification type.
   * @param  intValue  The integer value to use for this modification type.
   */
  private ModificationType(@NotNull final String name, final int intValue)
  {
    this.name     = name;
    this.intValue = intValue;
  }



  /**
   * Retrieves the name for this modification type.
   *
   * @return  The name for this modification type.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the integer value for this modification type.
   *
   * @return  The integer value for this modification type.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the modification type with the specified integer value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   modification type.
   *
   * @return  The modification type with the specified integer value, or a new
   *          modification type if the provided value does not match any of the
   *          predefined modification types.
   */
  @NotNull()
  public static ModificationType valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return ADD;
      case 1:
        return DELETE;
      case 2:
        return REPLACE;
      case 3:
        return INCREMENT;
      default:
        synchronized (UNDEFINED_MOD_TYPES)
        {
          ModificationType t = UNDEFINED_MOD_TYPES.get(intValue);
          if (t == null)
          {
            t = new ModificationType(intValue);
            UNDEFINED_MOD_TYPES.put(intValue, t);
          }

          return t;
        }
    }
  }



  /**
   * Retrieves the predefined modification type with the specified integer
   * value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   modification type.
   *
   * @return  The modification type with the specified integer value, or
   *          {@code null} if the provided integer value does not represent a
   *          defined modification type.
   */
  @Nullable()
  public static ModificationType definedValueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return ADD;
      case 1:
        return DELETE;
      case 2:
        return REPLACE;
      case 3:
        return INCREMENT;
      default:
        return null;
    }
  }



  /**
   * Retrieves an array of all modification types defined in the LDAP SDK.
   *
   * @return  An array of all modification types defined in the LDAP SDK.
   */
  @NotNull()
  public static ModificationType[] values()
  {
    return new ModificationType[]
    {
      ADD,
      DELETE,
      REPLACE,
      INCREMENT
    };
  }



  /**
   * The hash code for this modification type.
   *
   * @return  The hash code for this modification type.
   */
  @Override()
  public int hashCode()
  {
    return intValue;
  }



  /**
   * Indicates whether the provided object is equal to this modification type.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is a modification type that is
   *          equal to this modification type, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }
    else if (o == this)
    {
      return true;
    }
    else if (o instanceof ModificationType)
    {
      return (intValue == ((ModificationType) o).intValue);
    }
    else
    {
      return false;
    }
  }



  /**
   * Retrieves a string representation of this modification type.
   *
   * @return  A string representation of this modification type.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
