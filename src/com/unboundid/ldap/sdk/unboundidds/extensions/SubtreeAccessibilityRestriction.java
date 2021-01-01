/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.Serializable;
import java.util.Date;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a data structure with information about a subtree with
 * restricted access, as may be included in a
 * {@link GetSubtreeAccessibilityExtendedResult}.
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
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SubtreeAccessibilityRestriction
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1893365464740536092L;



  // The time the subtree accessibility restriction was created.
  @NotNull private final Date effectiveTime;

  // The DN of a user allowed to bypass any associated restrictions.
  @Nullable private final String bypassUserDN;

  // The base DN of the affected subtree.
  @NotNull private final String subtreeBaseDN;

  // The accessibility state of the affected subtree.
  @NotNull private final SubtreeAccessibilityState accessibilityState;



  /**
   * Creates a new subtree accessibility restriction object with the provided
   * information.
   *
   * @param  subtreeBaseDN       The base DN of the affected subtree.
   * @param  accessibilityState  The accessibility state of the affected
   *                             subtree.
   * @param  bypassUserDN        The DN of a user allowed to bypass any
   *                             associated restrictions, if defined.
   * @param  effectiveTime       The time this restriction was put into place.
   */
  public SubtreeAccessibilityRestriction(@NotNull final String subtreeBaseDN,
              @NotNull final SubtreeAccessibilityState accessibilityState,
              @Nullable final String bypassUserDN,
              @NotNull final Date effectiveTime)
  {
    this.subtreeBaseDN      = subtreeBaseDN;
    this.accessibilityState = accessibilityState;
    this.bypassUserDN       = bypassUserDN;
    this.effectiveTime      = effectiveTime;
  }



  /**
   * Retrieves the base DN for the affected subtree.
   *
   * @return  The base DN for the affected subtree.
   */
  @NotNull()
  public String getSubtreeBaseDN()
  {
    return subtreeBaseDN;
  }



  /**
   * Retrieves the accessibility state for the affected subtree.
   *
   * @return  The accessibility state for the affected subtree.
   */
  @NotNull()
  public SubtreeAccessibilityState getAccessibilityState()
  {
    return accessibilityState;
  }



  /**
   * Retrieves the DN of a user that will be allowed to bypass any restrictions
   * on the affected subtree.
   *
   * @return  The DN of a user that will be allowed to bypass any restrictions
   *          on the affected subtree, or {@code null} if no bypass user is
   *          defined.
   */
  @Nullable()
  public String getBypassUserDN()
  {
    return bypassUserDN;
  }



  /**
   * Retrieves the time the accessibility restriction was put into place.
   *
   * @return  The time the accessibility restriction was put into place.
   */
  @NotNull()
  public Date getEffectiveTime()
  {
    return effectiveTime;
  }



  /**
   * Retrieves a string representation of this accessibility restriction.
   *
   * @return  A string representation of this accessibility restriction.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this accessibility restriction to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SubtreeAccessibilityRestriction(base='");
    buffer.append(subtreeBaseDN.replace("\\\"", "\\22"));
    buffer.append("', state='");
    buffer.append(accessibilityState.getStateName());
    buffer.append('\'');

    if (bypassUserDN != null)
    {
      buffer.append(", bypassUser='");
      buffer.append(bypassUserDN.replace("\\\"", "\\22"));
      buffer.append('\'');
    }

    buffer.append(", effectiveTime='");
    buffer.append(StaticUtils.encodeGeneralizedTime(effectiveTime));
    buffer.append("')");
  }
}
