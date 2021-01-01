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
  @NotNull private final String name;



  /**
   * Creates a new attribute usage with the specified name.
   *
   * @param  name           The name for this attribute usage.
   * @param  isOperational  Indicates whether this is an operational attribute
   *                        usage.
   */
  AttributeUsage(@NotNull final String name, final boolean isOperational)
  {
    this.name          = name;
    this.isOperational = isOperational;
  }



  /**
   * Retrieves the name of this attribute usage.
   *
   * @return  The name of this attribute usage.
   */
  @NotNull()
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
   * @param  name  The name of the attribute usage to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The attribute usage with the specified name, or {@code null} if
   *          there is no usage with the given name.
   */
  @Nullable()
  public static AttributeUsage forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "userapplications":
      case "user-applications":
      case "user_applications":
        return USER_APPLICATIONS;
      case "directoryoperation":
      case "directory-operation":
      case "directory_operation":
        return DIRECTORY_OPERATION;
      case "distributedoperation":
      case "distributed-operation":
      case "distributed_operation":
        return DISTRIBUTED_OPERATION;
      case "dsaoperation":
      case "dsa-operation":
      case "dsa_operation":
        return DSA_OPERATION;
      default:
        return null;
    }
  }



  /**
   * Retrieves a string representation of this attribute usage.
   *
   * @return  A string representation of this attribute usage.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
