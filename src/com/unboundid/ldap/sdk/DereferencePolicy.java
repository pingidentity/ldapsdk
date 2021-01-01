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
 * This class defines a data type for dereference policy values.  Clients should
 * generally use one of the {@code NEVER}, {@code SEARCHING}, {@code FINDING},
 * or {@code ALWAYS} values, although it is possible to create a new dereference
 * policy with a specified integer value if necessary using the
 * {@link #valueOf(int)} method.  The following dereference policy values are
 * defined:
 * <UL>
 *   <LI>{@code NEVER} -- Indicates that the server should not dereference any
 *       aliases that it encounters.</LI>
 *   <LI>{@code SEARCHING} -- Indicates that the server should dereference any
 *       aliases that it may encounter while examining candidate entries, but it
 *       should not dereference the base entry if it happens to be an alias
 *       entry.</LI>
 *   <LI>{@code FINDING} -- Indicates that the server should dereference the
 *       base entry if it happens to be an alias entry, but it should not
 *       dereference any alias entries that may be encountered while examining
 *       candidate entries.</LI>
 *   <LI>{@code ALWAYS} -- Indicates that the server should dereference the base
 *       entry if it happens to be an alias entry, and should also dereference
 *       any entries that may be encountered while examining candidates.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DereferencePolicy
       implements Serializable
{
  /**
   * A predefined dereference policy value which indicates that the server
   * should not dereference any aliases that it encounters.
   */
  @NotNull public static final DereferencePolicy NEVER =
       new DereferencePolicy("NEVER", 0);



  /**
   * A predefined dereference policy value which indicates that the server
   * should dereference any aliases that it may encounter while examining
   * candidate entries, but it should not dereference the base entry if it
   * happens to be an alias entry.
   */
  @NotNull public static final DereferencePolicy SEARCHING =
       new DereferencePolicy("SEARCHING", 1);



  /**
   * A predefined dereference policy value which indicates that the server
   * should dereference the base entry if it happens to be an alias entry, but
   * it should not dereference any alias entries that may be encountered while
   * examining candidate entries.
   */
  @NotNull public static final DereferencePolicy FINDING =
       new DereferencePolicy("FINDING", 2);



  /**
   * A predefined dereference policy value which indicates that the server
   * should dereference the base entry if it happens to be an alias entry, and
   * should also dereference any entries that may be encountered while examining
   * candidates.
   */
  @NotNull public static final DereferencePolicy ALWAYS =
       new DereferencePolicy("ALWAYS", 3);



  /**
   * The set of dereference policy objects created with undefined int values.
   */
  @NotNull private static final HashMap<Integer,DereferencePolicy>
       UNDEFINED_POLICIES = new HashMap<>(StaticUtils.computeMapCapacity(10));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3722883359911755096L;



  // The integer value for this dereference policy.
  private final int intValue;

  // The name to use for this dereference policy.
  @NotNull private final String name;



  /**
   * Creates a new dereference policy with the specified integer value.
   *
   * @param  intValue  The integer value to use for this dereference policy.
   */
  private DereferencePolicy(final int intValue)
  {
    this.intValue = intValue;

    name = String.valueOf(intValue);
  }



  /**
   * Creates a new dereference policy with the specified name and integer value.
   *
   * @param  name      The name to use for this dereference policy.
   * @param  intValue  The integer value to use for this dereference policy.
   */
  private DereferencePolicy(@NotNull final String name, final int intValue)
  {
    this.name     = name;
    this.intValue = intValue;
  }



  /**
   * Retrieves the name for this dereference policy.
   *
   * @return  The name for this dereference policy.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the integer value for this dereference policy.
   *
   * @return  The integer value for this dereference policy.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the dereference policy with the specified integer value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   dereference policy.
   *
   * @return  The dereference policy with the specified integer value, or a new
   *          dereference policy if the provided value does not match any of the
   *          predefined policies.
   */
  @NotNull()
  public static DereferencePolicy valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return NEVER;
      case 1:
        return SEARCHING;
      case 2:
        return FINDING;
      case 3:
        return ALWAYS;
      default:
        synchronized (UNDEFINED_POLICIES)
        {
          DereferencePolicy p = UNDEFINED_POLICIES.get(intValue);
          if (p == null)
          {
            p = new DereferencePolicy(intValue);
            UNDEFINED_POLICIES.put(intValue, p);
          }

          return p;
        }
    }
  }



  /**
   * Retrieves the predefined dereference policy with the specified integer
   * value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   dereference policy.
   *
   * @return  The dereference policy with the specified integer value, or
   *          {@code null} if the provided value does not match any of the
   *          predefined policies.
   */
  @Nullable()
  public static DereferencePolicy definedValueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return NEVER;
      case 1:
        return SEARCHING;
      case 2:
        return FINDING;
      case 3:
        return ALWAYS;
      default:
        return null;
    }
  }



  /**
   * Retrieves an array of all dereference policies defined in the LDAP SDK.
   *
   * @return  An array of all dereference policies defined in the LDAP SDK.
   */
  @NotNull()
  public static DereferencePolicy[] values()
  {
    return new DereferencePolicy[]
    {
      NEVER,
      SEARCHING,
      FINDING,
      ALWAYS
    };
  }



  /**
   * The hash code for this dereference policy.
   *
   * @return  The hash code for this dereference policy.
   */
  @Override()
  public int hashCode()
  {
    return intValue;
  }



  /**
   * Indicates whether the provided object is equal to this dereference policy.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is a dereference policy that
   *          is equal to this dereference policy, or {@code false} if not.
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
    else if (o instanceof DereferencePolicy)
    {
      return (intValue == ((DereferencePolicy) o).intValue);
    }
    else
    {
      return false;
    }
  }



  /**
   * Retrieves a string representation of this dereference policy.
   *
   * @return  A string representation of this dereference policy.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
