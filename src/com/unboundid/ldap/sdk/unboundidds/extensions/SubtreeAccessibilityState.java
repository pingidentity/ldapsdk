/*
 * Copyright 2012-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2025 Ping Identity Corporation
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
 * Copyright (C) 2012-2025 Ping Identity Corporation
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



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;



/**
 * This enum defines the set of allowed accessibility states that may be used
 * with the {@link SetSubtreeAccessibilityExtendedRequest}.
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
public enum SubtreeAccessibilityState
{
  /**
   * Indicates that the subtree should return to normal accessibility so that
   * all appropriately-authorized users will be able to perform all kinds of
   * operations in the target subtree.
   */
  ACCESSIBLE(0, "accessible"),



  /**
   * Indicates that the subtree should be made read-only so that search and
   * compare operations targeting those entries will be allowed, but add,
   * delete, modify, and modify DN operations will only be allowed for one
   * specified user (as indicated in the set subtree accessibility request).
   * Bind operations will be allowed, but any changes intended to update
   * password policy or other account state (e.g., to record failed
   * authentication attempts or update last login time) will not be applied.
   */
  READ_ONLY_BIND_ALLOWED(1, "read-only-bind-allowed"),



  /**
   * Indicates that the subtree should be made read-only so that search and
   * compare operations targeting those entries will be allowed, but add,
   * delete, modify, and modify DN operations will only be allowed for one
   * specified user (as indicated in the set subtree accessibility request).
   * Bind operations will not be allowed for any user in the specified subtree.
   */
  READ_ONLY_BIND_DENIED(2, "read-only-bind-denied"),



  /**
   * Indicates that the subtree should be made hidden so that it is not
   * accessible to most clients for any kinds of operations.  The subtree will
   * be available to one specified user (as indicated in the set subtree
   * accessibility request) for add, compare, delete, modify, modify DN, and
   * search operations.  Bind operations will not be allowed for any user in a
   * hidden subtree.
   */
  HIDDEN(3, "hidden"),



  /**
   * Indicates that the subtree is intended to be deleted.  It will behave in
   * the same way as the {@link #HIDDEN} state, with the exception that the
   * server will not allow any further changes to the subtree accessibility
   * state.  That accessibility state will persist until the entry at the base
   * of the subtree has been removed.
   */
  TO_BE_DELETED(4, "to-be-deleted");



  // The integer value for this subtree accessibility state.
  private final int intValue;

  // The name for this subtree accessibility state.
  @NotNull private final String stateName;



  /**
   * Creates a new subtree accessibility state with the provided integer value.
   *
   * @param  intValue   The integer value for this subtree accessibility state.
   * @param  stateName  The name for this subtree accessibility state.
   */
  SubtreeAccessibilityState(final int intValue, @NotNull final String stateName)
  {
    this.intValue  = intValue;
    this.stateName = stateName;
  }



  /**
   * Retrieves the integer value for this subtree accessibility state.
   *
   * @return  The integer value for this subtree accessibility state.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the name for this subtree accessibility state.
   *
   * @return  The name for this subtree accessibility state.
   */
  @NotNull()
  public String getStateName()
  {
    return stateName;
  }



  /**
   * Indicates whether this state object represents the ACCESSIBLE state.
   *
   * @return  {@code true} if this state object represents the ACCESSIBLE state,
   *          or {@code false} if not.
   */
  public boolean isAccessible()
  {
    return (this == ACCESSIBLE);
  }



  /**
   * Indicates whether this state object represents the HIDDEN state.  For the
   * purpose of this method, TO_BE_DELETED will also be considered to be HIDDEN,
   * since the server will treat the two states as equivalent with the exception
   * that the accessibility state of TO_BE_DELETED subtrees cannot be changed.
   *
   * @return  {@code true} if this state object represents the HIDDEN or
   *          TO_BE_DELETED state, or {@code false} if not.
   */
  public boolean isHidden()
  {
    return ((this == HIDDEN) ||
            (this == TO_BE_DELETED));
  }



  /**
   * Indicates whether this state object represents one of the read-only states.
   *
   * @return  {@code true} if this state object represents one of the read-only
   *          states, or {@code false} if not.
   */
  public boolean isReadOnly()
  {
    return ((this == READ_ONLY_BIND_ALLOWED) ||
            (this == READ_ONLY_BIND_DENIED));
  }



  /**
   * Indicates whether this state object represents one of the read-only states.
   *
   * @return  {@code true} if this state object represents one of the read-only
   *          states, or {@code false} if not.
   */
  public boolean isToBeDeleted()
  {
    return (this == TO_BE_DELETED);
  }



  /**
   * Indicates whether this subtree accessibility state is considered more
   * restrictive than the provided state.  States will be considered in the
   * following descending order of restrictiveness:
   * <OL>
   *   <LI>{@code TO_BE_DELETED}</LI>
   *   <LI>{@code HIDDEN}</LI>
   *   <LI>{@code READ_ONLY_BIND_DENIED}</LI>
   *   <LI>{@code READ_ONLY_BIND_ALLOWED}</LI>
   *   <LI>{@code ACCESSIBLE}</LI>
   * </OL>
   *
   * @param  state  The accessibility state to compare against this one.  It
   *                must not be {@code null}.
   *
   * @return  {@code true} if this state is more restrictive than the provided
   *          state, or {@code false} if this state is the same as or less
   *          restrictive than the provided state.
   */
  public boolean isMoreRestrictiveThan(
              @NotNull final SubtreeAccessibilityState state)
  {
    switch (this)
    {
      case TO_BE_DELETED:
        return (state != SubtreeAccessibilityState.TO_BE_DELETED);

      case HIDDEN:
        return ((state != SubtreeAccessibilityState.TO_BE_DELETED) &&
             (state != SubtreeAccessibilityState.HIDDEN));

      case READ_ONLY_BIND_DENIED:
        return ((state != SubtreeAccessibilityState.TO_BE_DELETED) &&
             (state != SubtreeAccessibilityState.HIDDEN) &&
             (state != SubtreeAccessibilityState.READ_ONLY_BIND_DENIED));

      case READ_ONLY_BIND_ALLOWED:
        return ((state != SubtreeAccessibilityState.TO_BE_DELETED) &&
             (state != SubtreeAccessibilityState.HIDDEN) &&
             (state != SubtreeAccessibilityState.READ_ONLY_BIND_DENIED) &&
             (state != SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED));

      case ACCESSIBLE:
      default:
        return false;
    }
  }



  /**
   * Retrieves the subtree accessibility state with the specified integer value.
   *
   * @param  intValue  The integer value for the state to retrieve.
   *
   * @return  The subtree accessibility state with the specified integer value,
   *          or {@code null} if there is no accessibility state with the
   *          specified integer value.
   */
  @Nullable()
  public static SubtreeAccessibilityState valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return ACCESSIBLE;
      case 1:
        return READ_ONLY_BIND_ALLOWED;
      case 2:
        return READ_ONLY_BIND_DENIED;
      case 3:
        return HIDDEN;
      case 4:
        return TO_BE_DELETED;
      default:
        return null;
    }
  }



  /**
   * Retrieves the subtree accessibility state with the provided name.
   *
   * @param  name  The name for the subtree accessibility state to retrieve.  It
   *               must not be {@code null}.
   *
   * @return  The subtree accessibility state with the specified name, or
   *          {@code null} if no state has the provided name.
   */
  @Nullable()
  public static SubtreeAccessibilityState forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "accessible":
        return ACCESSIBLE;
      case "readonlybindallowed":
      case "read-only-bind-allowed":
      case "read_only_bind_allowed":
        return READ_ONLY_BIND_ALLOWED;
      case "readonlybinddenied":
      case "read-only-bind-denied":
      case "read_only_bind_denied":
        return READ_ONLY_BIND_DENIED;
      case "hidden":
        return HIDDEN;
      case "tobedeleted":
      case "to-be-deleted":
      case "to_be_deleted":
        return TO_BE_DELETED;
      default:
        return null;
    }
  }



  /**
   * Retrieves a string representation of this subtree accessibility state.
   *
   * @return  A string representation of this subtree accessibility state.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return stateName;
  }
}
