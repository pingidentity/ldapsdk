/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.SubtreeAccessibilityState;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines a number of properties that can be used when attempting to
 * move a subtree from one Ping Identity Directory Server instance to another
 * Ping Identity Directory Server instance using restricted subtree
 * accessibility.
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
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class MoveSubtreeProperties
{
  // Indicates whether to suppress referential integrity processing on the
  // source server.
  private boolean suppressReferentialIntegrityUpdates;

  // Indicates whether to use the to-be-deleted subtree accessibility state
  // (rather than the hidden state) when beginning to remove entries from the
  // source server.
  private boolean useToBeDeletedAccessibilityState;

  // The base DN for the subtree to move.
  @NotNull private DN baseDN;

  // The maximum number of entries allowed in the subtree to move.
  private int maximumAllowedSubtreeSize;

  // An optional listener that may be invoked during the course of moving
  // entries from the source server to the target server.
  @Nullable private MoveSubtreeListener listener;

  // An optional operation purpose request control to include in all requests
  // sent to the source and target servers.
  @Nullable private OperationPurposeRequestControl
       operationPurposeRequestControl;



  /**
   * Creates a new set of properties that can be used when moving the specified
   * subtree from one server to another.
   *
   * @param  baseDN  The base DN for the subtree to be moved.  It must not be
   *                 {@code null}, and it must represent a valid DN with one or
   *                 more RDN components.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   */
  public MoveSubtreeProperties(@NotNull final String baseDN)
         throws LDAPException
  {
    this(new DN(baseDN));
  }



  /**
   * Creates a new set of properties that can be used when moving the specified
   * subtree from one server to another.
   *
   * @param  baseDN  The base DN for the subtree to be moved.  It must not be
   *                 {@code null}, and it must have one or more RDN components.
   */
  public MoveSubtreeProperties(@NotNull final DN baseDN)
  {
    setBaseDN(baseDN);

    suppressReferentialIntegrityUpdates = false;
    useToBeDeletedAccessibilityState = false;
    maximumAllowedSubtreeSize = 0;
    listener = null;
    operationPurposeRequestControl = null;
  }



  /**
   * Creates a new set of properties that is a copy of the provided properties
   * object.
   *
   * @param  properties  The properties object to use to create the new
   *                     properties.
   */
  public MoveSubtreeProperties(@NotNull final MoveSubtreeProperties properties)
  {
    baseDN = properties.baseDN;
    suppressReferentialIntegrityUpdates =
         properties.suppressReferentialIntegrityUpdates;
    useToBeDeletedAccessibilityState =
         properties.useToBeDeletedAccessibilityState;
    maximumAllowedSubtreeSize = properties.maximumAllowedSubtreeSize;
    listener = properties.listener;
    operationPurposeRequestControl = properties.operationPurposeRequestControl;
  }



  /**
   * Retrieves the base DN of the subtree to move.
   *
   * @return  The base DN of the subtree to move.
   */
  @NotNull()
  public DN getBaseDN()
  {
    return baseDN;
  }



  /**
   * Specifies the base DN of the subtree to move.
   *
   * @param  baseDN  The base DN for the subtree to be moved.  It must not be
   *                 {@code null}, and it must represent a valid DN with one or
   *                 more RDN components.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   */
  public void setBaseDN(@NotNull final String baseDN)
         throws LDAPException
  {
    setBaseDN(new DN(baseDN));
  }



  /**
   * Specifies the base DN of the subtree to move.
   *
   * @param  baseDN  The base DN for the subtree to be moved.  It must not be
   *                 {@code null}, and it must have one or more RDN components.
   */
  public void setBaseDN(@NotNull final DN baseDN)
  {
    Validator.ensureNotNullWithMessage(baseDN,
         "MoveSubtreeProperties.baseDN must not be null.");
    Validator.ensureTrue((baseDN.getRDNs().length > 0),
         "MoveSubtreeProperties.baseDN must include one or more RDN " +
              "components.");

    this.baseDN = baseDN;
  }



  /**
   * Retrieves the maximum number of entries that the target subtree may contain
   * for it to be moved from one server to another.
   *
   * @return  The maximum number of entries that the target subtree may contain
   *          for it to be moved from one server to another, or zero if no
   *          client-side size limit should be enforced (although the server may
   *          still impose its own size limit).
   */
  public int getMaximumAllowedSubtreeSize()
  {
    return maximumAllowedSubtreeSize;
  }



  /**
   * Specifies the maximum number of entries that the target subtree may contain
   * for it to be moved from one server to another.  If the subtree contains
   * more than the maximum number of entries, then the attempt to move it will
   * be aborted before any changes are applied to the data in either server.
   *
   * @param  sizeLimit  The maximum number of entries tht the target subtree may
   *                    contain for it to be moved from one server to another.
   *                    A value that is less than or equal to zero indicates
   *                    that no client-side size limit should be imposed.  Note
   *                    that the server may also impose a size limit, and the
   *                    smaller of the client-side and server-side limits will
   *                    be in effect.
   */
  public void setMaximumAllowedSubtreeSize(final int sizeLimit)
  {
    if (sizeLimit > 0)
    {
      maximumAllowedSubtreeSize = sizeLimit;
    }
    else
    {
      maximumAllowedSubtreeSize = 0;
    }
  }



  /**
   * Indicates whether to use the
   * {@link SubtreeAccessibilityState#TO_BE_DELETED} subtree accessibility state
   * (as opposed to the {@code HIDDEN} state) for the target subtree on the
   * source server before beginning to remove entries from it.
   *
   * @return  {@code true} if the {@code TO_BE_DELETED} subtree accessibility
   *          state should be used, or {@code false} if the {@code HIDDEN} state
   *          should be used.
   */
  public boolean useToBeDeletedAccessibilityState()
  {
    return useToBeDeletedAccessibilityState;
  }



  /**
   * Specifies whether to use the
   * {@link SubtreeAccessibilityState#TO_BE_DELETED} subtree accessibility state
   * (as opposed to the {@code HIDDEN} state) for the target subtree on the
   * source server before beginning to remove entries from it.  Both the
   * {@code TO_BE_DELETED} and {@code HIDDEN} subtree accessibility states will
   * completely hide the target subtree from all clients expect those
   * authenticated as a designated bypass-user account, but the key differences
   * between these states include:
   * <UL>
   *   <LI>
   *     In some cases, the server may be able to process delete requests for
   *     entries in {@code TO_BE_DELETED} subtrees than for entries in subtrees
   *     with other accessibility states, including the {@code HIDDEN} state.
   *   </LI>
   *   <LI>
   *     Support for the {@code TO_BE_DELETED} subtree accessibility state was
   *     added to the Directory Server more recently than support for the
   *     {@code HIDDEN} state.  Older Directory Server instances may not support
   *     the {@code TO_BE_DELETED} state.
   *   </LI>
   *   <LI>
   *     A {@code HIDDEN} subtree can be updated to give it a different
   *     accessibility state, but once a subtree has been placed in a
   *     {@code TO_BE_DELETED} accessibility state, its state cannot be manually
   *     updated.
   *   </LI>
   *   <LI>
   *     The {@code TO_BE_DELETED} accessibility state will automatically be
   *     removed from a subtree once all entries have been removed from that
   *     subtree, while the {@code HIDDEN} state needs to be manually removed
   *     if it is no longer desired.
   *   </LI>
   * </UL>
   *
   * @param  useToBeDeletedState  Indicates whether to use the
   *                              {@code TO_BE_DELETED} subtree accessibility
   *                              state instead of the {@code HIDDEN} state for
   *                              the target subtree on the source server before
   *                              beginning to remove entries from it.
   */
  public void setUseToBeDeletedAccessibilityState(
                   final boolean useToBeDeletedState)
  {
    useToBeDeletedAccessibilityState = useToBeDeletedState;
  }



  /**
   * Indicates whether to suppress referential integrity updates when removing
   * entries from the source server.
   *
   * @return  {@code true} if referential integrity updates should be suppressed
   *          when removing entries from the source server, or {@code false} if
   *          not.
   */
  public boolean suppressReferentialIntegrityUpdates()
  {
    return suppressReferentialIntegrityUpdates;
  }



  /**
   * Specifies whether to suppress referential integrity updates when removing
   * entries from the source server.  By default, if the referential integrity
   * plugin is enabled, then removing a user entry will automatically remove
   * references to it from other entries, including things like static group
   * membership.  However, when moving entries from one server to another, and
   * especially in cases where the associated references are in other entries
   * that are also being moved, it may be desirable to suppress those
   * referential integrity updates.
   *
   * @param  suppressUpdates  Indicates whether to suppress referential
   *                          integrity updates when removing entries from the
   *                          source server.
   */
  public void setSuppressReferentialIntegrityUpdates(
                   final boolean suppressUpdates)
  {
    suppressReferentialIntegrityUpdates = suppressUpdates;
  }



  /**
   * Retrieves an operation purpose request control that should be included in
   * all requests sent to the source and target servers, if any.
   *
   * @return  An operation purpose request control that should be included in
   *          all requests sent ot the source and target servers, or
   *          {@code null} if no operation purpose request control should be
   *          used.
   */
  @Nullable()
  public OperationPurposeRequestControl getOperationPurposeRequestControl()
  {
    return operationPurposeRequestControl;
  }



  /**
   * Specifies an operation purpose request control that should be included in
   * all requests sent to the source and target servers.
   *
   * @param  control  An operation purpose request control that should be
   *                  included in all requests sent to the source and target
   *                  servers.  It may be {@code null} if no operation purpose
   *                  request control should be used.
   */
  public void setOperationPurposeRequestControl(
                   @Nullable final OperationPurposeRequestControl control)
  {
    operationPurposeRequestControl = control;
  }




  /**
   * Retrieves the listener that may be invoked during the course of moving
   * entries from the source server to the target server, if any.
   *
   * @return  The listener that may be invoked during the course of moving
   *          entries from the source server to the target server, or
   *          {@code null} if no move subtree listener has been configured.
   */
  @Nullable()
  public MoveSubtreeListener getMoveSubtreeListener()
  {
    return listener;
  }




  /**
   * Specifies a listener that may be invoked during the course of moving
   * entries from the source server to the target server.  The listener will be
   * invoked before and after adding an entry to the target server, and it will
   * be invoked before and after removing an entry from the source server.
   *
   * @param  listener  A listener that may be invoked during the course of
   *                   moving entries from the source server to the target
   *                   server.  It may be {@code null} if no listener is needed.
   */
  public void setMoveSubtreeListener(
                   @Nullable final MoveSubtreeListener listener)
  {
    this.listener = listener;
  }



  /**
   * Retrieves a string representation of the properties.
   *
   * @return  A string representation of the proprties.
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
   * Appends a string representation of the properties to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.  It
   *                 must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MoveSubtreeProperties(baseDN='");
    buffer.append(baseDN);
    buffer.append("', maximumAllowedSubtreeSize=");
    buffer.append(maximumAllowedSubtreeSize);
    buffer.append(", useToBeDeletedAccessibilityState=");
    buffer.append(useToBeDeletedAccessibilityState);
    buffer.append(", suppressReferentialIntegrityUpdates=");
    buffer.append(suppressReferentialIntegrityUpdates);
    buffer.append(", operationPurposeRequestControl=");
    buffer.append(operationPurposeRequestControl);
    buffer.append(", moveSubtreeListener=");
    buffer.append(listener);
    buffer.append(')');
  }
}
