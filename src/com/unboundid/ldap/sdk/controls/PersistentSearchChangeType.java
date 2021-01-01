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
package com.unboundid.ldap.sdk.controls;



import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;

import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines a set of change types that can be associated with
 * persistent search operations.  Change types may be used in the
 * {@link PersistentSearchRequestControl}, as well as in
 * {@link EntryChangeNotificationControl}s returned in search result entries
 * as part of a persistent search.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum PersistentSearchChangeType
{
  /**
   * Indicates that the change type is for an add operation.
   */
  ADD("add", 1),



  /**
   * Indicates that the change type is for a delete operation.
   */
  DELETE("delete", 2),



  /**
   * Indicates that the change type is for a modify operation.
   */
  MODIFY("modify", 4),



  /**
   * Indicates that the change type is for a modify DN operation.
   */
  MODIFY_DN("moddn", 8);



  // The numeric value associated with this change type.
  private final int value;

  // The human-readable name for this change type.
  @NotNull private final String name;



  /**
   * Creates a new persistent search change type with the provided information.
   *
   * @param  name   The human-readable name for this change type.
   * @param  value  The numeric value associated with this change type.
   */
  PersistentSearchChangeType(@NotNull final String name, final int value)
  {
    this.name  = name;
    this.value = value;
  }



  /**
   * Retrieves the human-readable name for this change type.
   *
   * @return  The human-readable name for this change type.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the integer value for this change type.
   *
   * @return  The integer value for this change type.
   */
  public int intValue()
  {
    return value;
  }



  /**
   * Retrieves the persistent search change type with the specified int value.
   *
   * @param  intValue  the numeric value associated with the change type.
   *
   * @return  The associated change type, or {@code null} if there is no
   *          persistent search change type with the specified set of values.
   */
  @Nullable()
  public static PersistentSearchChangeType valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 1:
        return ADD;

      case 2:
        return DELETE;

      case 4:
        return MODIFY;

      case 8:
        return MODIFY_DN;

      default:
        return null;
    }
  }



  /**
   * Retrieves the persistent search change type with the specified name.
   *
   * @param  name  The name of the change type for which to retrieve the name.
   *               It must not be {@code null}.
   *
   * @return  The requested persistent search change type, or {@code null} if
   *          there is no change type with the given name.
   */
  @Nullable()
  public static PersistentSearchChangeType forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "add":
        return ADD;
      case "delete":
      case "del":
        return DELETE;
      case "modify":
      case "mod":
        return MODIFY;
      case "modifydn":
      case "modify-dn":
      case "modify_dn":
      case "moddn":
      case "mod-dn":
      case "mod_dn":
      case "modifyrdn":
      case "modify-rdn":
      case "modify_rdn":
      case "modrdn":
      case "mod-rdn":
      case "mod_rdn":
        return MODIFY_DN;
      default:
        return null;
    }
  }



  /**
   * Retrieves a set containing all defined change types.
   *
   * @return  A set containing all defined change types.
   */
  @NotNull()
  public static Set<PersistentSearchChangeType> allChangeTypes()
  {
    return EnumSet.allOf(PersistentSearchChangeType.class);
  }



  /**
   * Encodes the provided set of change types into an integer value suitable for
   * use as the change types for the persistent search request control.
   *
   * @param  changeTypes  The set of change types to be encoded.
   *
   * @return  An integer value containing the encoded representation of the
   *          change types.
   */
  public static int encodeChangeTypes(
              @NotNull final PersistentSearchChangeType... changeTypes)
  {
    int changeTypesValue = 0;

    for (final PersistentSearchChangeType changeType : changeTypes)
    {
      changeTypesValue |= changeType.intValue();
    }

    return changeTypesValue;
  }



  /**
   * Encodes the provided set of change types into an integer value suitable for
   * use as the change types for the persistent search request control.
   *
   * @param  changeTypes  The set of change types to be encoded.
   *
   * @return  An integer value containing the encoded representation of the
   *          change types.
   */
  public static int encodeChangeTypes(
              @NotNull final Collection<PersistentSearchChangeType> changeTypes)
  {
    int changeTypesValue = 0;

    for (final PersistentSearchChangeType changeType : changeTypes)
    {
      changeTypesValue |= changeType.intValue();
    }

    return changeTypesValue;
  }



  /**
   * Decodes the provided set of change types from the provided value.
   *
   * @param  changeTypes  The int value representing the encoded set of change
   *                      types.
   *
   * @return  A list of the change types encoded in the provided value.
   */
  @NotNull()
  public static Set<PersistentSearchChangeType> decodeChangeTypes(
                                                      final int changeTypes)
  {
    final EnumSet<PersistentSearchChangeType> ctSet =
         EnumSet.noneOf(PersistentSearchChangeType.class);

    if ((changeTypes & ADD.intValue()) == ADD.intValue())
    {
      ctSet.add(ADD);
    }

    if ((changeTypes & DELETE.intValue()) == DELETE.intValue())
    {
      ctSet.add(DELETE);
    }

    if ((changeTypes & MODIFY.intValue()) == MODIFY.intValue())
    {
      ctSet.add(MODIFY);
    }

    if ((changeTypes & MODIFY_DN.intValue()) == MODIFY_DN.intValue())
    {
      ctSet.add(MODIFY_DN);
    }

    return ctSet;
  }



  /**
   * Retrieves a string representation for this persistent search change type.
   *
   * @return  A string representation for this persistent search change type.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
