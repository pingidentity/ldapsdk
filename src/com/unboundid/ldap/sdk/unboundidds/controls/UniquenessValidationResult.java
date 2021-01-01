/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;



/**
 * This enum defines a set of values that provide information about the result
 * of validation processing that the server performed in response to a
 * {@link UniquenessRequestControl}.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
public enum UniquenessValidationResult
{
  /**
   * Indicates that the server verified that the requested update did not
   * conflict with any existing entries at the time the validation processing
   * was performed.
   */
  VALIDATION_PASSED("validation-passed"),



  /**
   * Indicates that the server found at least one other entry in the server that
   * conflicted with the attempted write operation.
   */
  VALIDATION_FAILED("validation-failed"),



  /**
   * Indicates that the server did not attempt any uniqueness validation
   * processing at the associated point in operation processing.  Potential
   * reasons that no validation may have been attempted include that the
   * {@link UniquenessRequestControl} indicated that no validation was required
   * at that point in the processing, because the uniqueness constraint did
   * not apply to the associated operation (for example, the control indicated
   * that uniqueness should be maintained for an attribute that was not included
   * in the update), or that the operation failed for some reason that was not
   * related to uniqueness processing.
   */
  VALIDATION_NOT_ATTEMPTED("validation-not-attempted");



  // The name for this validation result.
  @NotNull private final String name;



  /**
   * Creates a new uniqueness validation result with the provided name.
   *
   * @param  name  The name for this uniqueness validation result.
   */
  UniquenessValidationResult(@NotNull final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name for this uniqueness validation result.
   *
   * @return  The name for this uniqueness validation result.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the uniqueness validation result with the given name.
   *
   * @param  name  The name for the uniqueness validation result to retrieve.
   *               It must not be {@code null}.
   *
   * @return  The uniqueness validation result with the given name, or
   *          {@code null} if there is no result with the given name.
   */
  @Nullable()
  public static UniquenessValidationResult forName(@NotNull final String name)
  {
    final String n = StaticUtils.toLowerCase(name).replace('_', '-');
    for (final UniquenessValidationResult r : values())
    {
      if (r.getName().equals(n))
      {
        return r;
      }
    }

    return null;
  }



  /**
   * Retrieves a string representation for this uniqueness validation result.
   *
   * @return  A string representation for this uniqueness validation result.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
