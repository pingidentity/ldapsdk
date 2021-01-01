/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import com.unboundid.util.StaticUtils;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the security level values that may be used in conjunction
 * with the collect-support-data tool (and the corresponding administrative
 * task and extended operation).
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum CollectSupportDataSecurityLevel
{
  // NOTICE:  If new items are added in the future, then enum values should be
  // sorted



  /**
   * The security level that indicates that no data should be obscured or
   * redacted.
   */
  NONE("none"),



  /**
   * The security level that indicates that secret information (like the values
   * of sensitive configuration properties) should be obscured, and that logs
   * containing user data (like the data recovery log) will be excluded from the
   * support data archive.
   */
  OBSCURE_SECRETS("obscure-secrets"),



  /**
   * The security level that includes everything in the {@link #OBSCURE_SECRETS}
   * level, but takes even more drastic measures to avoid capturing any
   * personally identifiable information, including excluding access logs from
   * the archive and obscuring values in entry DNs and search filters.
   */
  MAXIMUM("maximum");



  // The name used to identify this security level.
  @NotNull private final String name;



  /**
   * Creates a new collect support data security level with the provided name.
   *
   * @param  name  The name used to identify this security level.
   */
  CollectSupportDataSecurityLevel(@NotNull final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name used to identify this security level.
   *
   * @return  The name used to identify this security level.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the collect support data security level with the given name.
   *
   * @param  name  The name for the collect support data security level to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The collect support data security level with the given name, or
   *          {@code null} if there is no security level with the provided name.
   */
  @Nullable()
  public static CollectSupportDataSecurityLevel forName(
              @NotNull final String name)
  {
    final String normalizedName =
         StaticUtils.toLowerCase(name).replace('_', '-');
    for (final CollectSupportDataSecurityLevel l : values())
    {
      if (normalizedName.equals(l.name))
      {
        return l;
      }
    }

    return null;
  }



  /**
   * Retrieves a string representation of this collect support data security
   * level.
   *
   * @return  A string representation of this collect support data security
   *          level.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
