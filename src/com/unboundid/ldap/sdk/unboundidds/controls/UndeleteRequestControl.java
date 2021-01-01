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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.List;
import java.util.ArrayList;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.matchingrules.BooleanMatchingRule;
import com.unboundid.ldap.matchingrules.OctetStringMatchingRule;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control which may be included in an add request
 * to indicate that the contents of the resulting entry should come not from the
 * data of the add request itself but instead from a soft-deleted entry.  This
 * can be used to recover an entry that was previously removed by a delete
 * request containing the {@link SoftDeleteRequestControl}.
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
 * <BR>
 * The criticality for this control should always be {@code TRUE}.  The
 * criticality will have no effect on servers that do support this control, but
 * a criticality of {@code TRUE} will ensure that a server which does not
 * support soft deletes does not attempt to process the add request.  If the
 * criticality were {@code FALSE}, then any server that does not support the
 * control would simply ignore it and attempt to add the entry specified in the
 * add request (which will have details about the undelete to be processed).
 * <BR><BR>
 * The control may optionally have a value.  If a value is provided, then it
 * must be the encoded representation of an empty ASN.1 sequence, like:
 * <PRE>
 *   UndeleteRequestValue ::= SEQUENCE {
 *     ... }
 * </PRE>
 * In the future, the value sequence may allow one or more elements to customize
 * the behavior of the undelete operation, but at present no such elements are
 * defined.
 * See the documentation for the {@link SoftDeleteRequestControl} class for an
 * example demonstrating the use of this control.
 *
 * @see  HardDeleteRequestControl
 * @see  SoftDeleteRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class UndeleteRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.23) for the undelete request control.
   */
  @NotNull public static final String UNDELETE_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.23";



  /**
   * The name of the optional attribute used to specify a set of changes to
   * apply to the soft-deleted entry during the course of the undelete.
   */
  @NotNull public static final String ATTR_CHANGES = "ds-undelete-changes";



  /**
   * The name of the optional attribute used to indicate whether the
   * newly-undeleted user account should be disabled and prevented from
   * authenticating.
   */
  @NotNull public static final String ATTR_DISABLE_ACCOUNT =
       "ds-undelete-disable-account";



  /**
   * The name of the optional attribute used to indicate whether the
   * newly-undeleted user will be required to change his/her password
   * immediately after authenticating and before being required to request any
   * other operations.
   */
  @NotNull public static final String ATTR_MUST_CHANGE_PASSWORD =
       "ds-undelete-must-change-password";



  /**
   * The name of the optional attribute used to specify the new password for use
   * in the newly-undeleted entry.
   */
  @NotNull public static final String ATTR_NEW_PASSWORD =
       "ds-undelete-new-password";



  /**
   * The name of the optional attribute used to specify the password currently
   * contained in the soft-deleted entry, to be validated as part of the
   * undelete process.
   */
  @NotNull public static final String ATTR_OLD_PASSWORD =
       "ds-undelete-old-password";



  /**
   * The name of the required attribute used to specify the DN of the
   * soft-deleted entry to be undeleted.
   */
  @NotNull public static final String ATTR_SOFT_DELETED_ENTRY_DN =
       "ds-undelete-from-dn";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5338045977962112876L;



  /**
   * Creates a undelete request control with a criticality of TRUE and no value.
   */
  public UndeleteRequestControl()
  {
    super(UNDELETE_REQUEST_OID, true, null);
  }



  /**
   * Creates a new undelete request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as an undelete request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         undelete request control.
   */
  public UndeleteRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      try
      {
        final ASN1Sequence valueSequence =
             ASN1Sequence.decodeAsSequence(control.getValue().getValue());
        final ASN1Element[] elements = valueSequence.elements();
        if (elements.length > 0)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_UNDELETE_REQUEST_UNSUPPORTED_VALUE_ELEMENT_TYPE.get(
                    StaticUtils.toHex(elements[0].getType())));
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw le;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNDELETE_REQUEST_CANNOT_DECODE_VALUE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
  }



  /**
   * Creates a new undelete request that may be used to recover the specified
   * soft-deleted entry.
   *
   * @param  targetDN            The DN to use for the entry recovered
   *                             from the soft-deleted entry contents.  It must
   *                             not be {@code null}.
   * @param  softDeletedEntryDN  The DN of the soft-deleted entry to be used in
   *                             the restore process.  It must not be
   *                             {@code null}.
   *
   * @return  An add request with an appropriate set of content
   */
  @NotNull()
  public static AddRequest createUndeleteRequest(@NotNull final String targetDN,
                                @NotNull final String softDeletedEntryDN)
  {
    return createUndeleteRequest(targetDN, softDeletedEntryDN, null, null, null,
         null, null);
  }



  /**
   * Creates a new undelete request that may be used to recover the specified
   * soft-deleted entry.
   *
   * @param  targetDN            The DN to use for the entry recovered
   *                             from the soft-deleted entry contents.  It must
   *                             not be {@code null}.
   * @param  softDeletedEntryDN  The DN of the soft-deleted entry to be used in
   *                             the restore process.  It must not be
   *                             {@code null}.
   * @param  changes             An optional set of changes that should be
   *                             applied to the entry during the course of
   *                             undelete processing.  It may be {@code null} or
   *                             empty if this element should be omitted from
   *                             the resulting add request.
   * @param  oldPassword         An optional copy of the password currently
   *                             contained in the soft-deleted entry to be
   *                             recovered.  If this is non-{@code null}, then
   *                             this password will be required to match that
   *                             contained in the target entry for the undelete
   *                             to succeed.
   * @param  newPassword         An optional new password to set for the user
   *                             as part of the undelete processing.  It may be
   *                             {@code null} if no new password should be
   *                             provided.
   * @param  mustChangePassword  Indicates whether the recovered user will be
   *                             required to change his/her password before
   *                             being allowed to request any other operations.
   *                             It may be {@code null} if this should be
   *                             omitted from the resulting add request.
   * @param  disableAccount      Indicates whether the undeleted entry should be
   *                             made disabled so that it cannot be used to
   *                             authenticate.  It may be {@code null} if this
   *                             should be omitted from the resulting add
   *                             request.
   *
   * @return  An add request with an appropriate set of content
   */
  @NotNull()
  public static AddRequest createUndeleteRequest(@NotNull final String targetDN,
                                @NotNull final String softDeletedEntryDN,
                                @Nullable final List<Modification> changes,
                                @Nullable final String oldPassword,
                                @Nullable final String newPassword,
                                @Nullable final Boolean mustChangePassword,
                                @Nullable final Boolean disableAccount)
  {
    final ArrayList<Attribute> attributes = new ArrayList<>(6);
    attributes.add(new Attribute(ATTR_SOFT_DELETED_ENTRY_DN,
         softDeletedEntryDN));

    if ((changes != null) && (! changes.isEmpty()))
    {
      // The changes attribute should be an LDIF-encoded representation of the
      // modification, with the first two lines (the DN and changetype)
      // removed.
      final LDIFModifyChangeRecord changeRecord =
           new LDIFModifyChangeRecord(targetDN, changes);
      final String[] modLdifLines = changeRecord.toLDIF(0);
      final StringBuilder modLDIFBuffer = new StringBuilder();
      for (int i=2; i < modLdifLines.length; i++)
      {
        modLDIFBuffer.append(modLdifLines[i]);
        modLDIFBuffer.append(StaticUtils.EOL);
      }
      attributes.add(new Attribute(ATTR_CHANGES,
           OctetStringMatchingRule.getInstance(), modLDIFBuffer.toString()));
    }

    if (oldPassword != null)
    {
      attributes.add(new Attribute(ATTR_OLD_PASSWORD,
           OctetStringMatchingRule.getInstance(), oldPassword));
    }

    if (newPassword != null)
    {
      attributes.add(new Attribute(ATTR_NEW_PASSWORD,
           OctetStringMatchingRule.getInstance(), newPassword));
    }

    if (mustChangePassword != null)
    {
      attributes.add(new Attribute(ATTR_MUST_CHANGE_PASSWORD,
           BooleanMatchingRule.getInstance(),
           (mustChangePassword ? "true" : "false")));
    }

    if (disableAccount != null)
    {
      attributes.add(new Attribute(ATTR_DISABLE_ACCOUNT,
           BooleanMatchingRule.getInstance(),
           (disableAccount ? "true" : "false")));
    }

    final Control[] controls =
    {
      new UndeleteRequestControl()
    };

    return new AddRequest(targetDN, attributes, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_UNDELETE_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("UndeleteRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
