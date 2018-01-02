/*
 * Copyright 2012-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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
  private final Date effectiveTime;

  // The DN of a user allowed to bypass any associated restrictions.
  private final String bypassUserDN;

  // The base DN of the affected subtree.
  private final String subtreeBaseDN;

  // The accessibility state of the affected subtree.
  private final SubtreeAccessibilityState accessibilityState;



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
  public SubtreeAccessibilityRestriction(final String subtreeBaseDN,
              final SubtreeAccessibilityState accessibilityState,
              final String bypassUserDN, final Date effectiveTime)
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
  public String getSubtreeBaseDN()
  {
    return subtreeBaseDN;
  }



  /**
   * Retrieves the accessibility state for the affected subtree.
   *
   * @return  The accessibility state for the affected subtree.
   */
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
  public String getBypassUserDN()
  {
    return bypassUserDN;
  }



  /**
   * Retrieves the time the accessibility restriction was put into place.
   *
   * @return  The time the accessibility restriction was put into place.
   */
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
  public void toString(final StringBuilder buffer)
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
