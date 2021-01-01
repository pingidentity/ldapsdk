/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.persist;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;



/**
 * This enumeration defines a set of options that indicate how the value of a
 * field or getter method may be used in the process of constructing a search
 * filter.  The resulting filter will be constructed as a logical AND of
 * equality components created from the structural object class and any
 * auxiliary classes, as well as equality components created from the values of
 * fields with the {@link LDAPField} annotation type and/or the return values of
 * methods with the {@link LDAPGetter} annotation type.
 * <BR><BR>
 * If a class has any fields or getter methods with a filter usage of
 * {@code REQUIRED}, then all fields and/or getter methods marked as
 * {@code REQUIRED} must have a non-{@code null} value and will be included in
 * the filter, and any other fields or getter methods marked as
 * {@code ALWAYS_ALLOWED} or {@code CONDITIONALLY_ALLOWED} with non-{@code null}
 * values will be included in the filter as well.
 * <BR><BR>
 * If a class does not have any fields or getter methods that are marked
 * {@code REQUIRED}, then at least one field or getter method marked
 * {@code ALWAYS_ALLOWED} must have a non-{@code null} value in order to
 * generate a search filter from that object, and the resulting filter will
 * contain components for all non-{@code null} fields and/or getter methods
 * marked {@code ALWAYS_ALLOWED} or {@code CONDITIONALLY_ALLOWED}.  If an object
 * does not have any non-{@code null} fields or getter methods marked
 * {@code REQUIRED} or {@code ALWAYS_ALLOWED}, then it will not be possible to
 * generate a search filter from that object.
 */
public enum FilterUsage
{
  /**
   * Indicates that the associated field or getter method must have a value in
   * an object in order to be able to generate a search filter from that object.
   * If an attempt is made to generate a search filter from an object that does
   * not have a value for the associated field or getter method, then an
   * exception will be thrown.
   */
  REQUIRED,



  /**
   * Indicates that the associated field or getter method may always be included
   * in a search filter if it has a value, regardless of whether any other
   * fields or getter methods in the object may have values.  If the associated
   * field or getter method does not have a value, then it will be excluded from
   * the generated search filter.  It is generally recommended that the
   * corresponding attribute be indexed for equality in the directory server, or
   * that the server otherwise be configured to perform fast equality searches
   * for filters containing this attribute.
   */
  ALWAYS_ALLOWED,



  /**
   * Indicates that the associated field or getter method may be included in a
   * generated search filter if it has a non-{@code null} value, and if at least
   * one field or getter method marked {@code REQUIRED} or
   * {@code ALWAYS_ALLOWED} has a non-{@code null} value.  This usage indicates
   * that the associated field or getter method may be used to help refine a
   * search filter, but is not sufficient to be included in a search filter by
   * itself.
   */
  CONDITIONALLY_ALLOWED,



  /**
   * Indicates that the associated field or getter method will never be included
   * in a search filter generated from an object, regardless of whether it has a
   * value in that object.
   */
  EXCLUDED;



  /**
   * Retrieves the filter usage with the specified name.
   *
   * @param  name  The name of the filter usage to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The requested filter usage, or {@code null} if no such usage is
   *          defined.
   */
  @Nullable()
  public static FilterUsage forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "required":
        return REQUIRED;
      case "alwaysallowed":
      case "always-allowed":
      case "always_allowed":
        return ALWAYS_ALLOWED;
      case "conditionallyallowed":
      case "conditionally-allowed":
      case "conditionally_allowed":
        return CONDITIONALLY_ALLOWED;
      case "excluded":
        return EXCLUDED;
      default:
        return null;
    }
  }
}
