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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a response control that holds information about the
 * soft-deleted entry that results from a soft delete request, and may also be
 * included in a search result entry which represents a soft-deleted entry.  The
 * value of this control will be the DN of the soft-deleted entry.
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
 * This control has an OID of 1.3.6.1.4.1.30221.2.5.21, a criticality of false,
 * and a value that is simply the string representation of the new DN for the
 * soft-deleted entry.
 * <BR><BR>
 * See the documentation for the {@link SoftDeleteRequestControl} class for an
 * example demonstrating the use of this control.
 *
 * @see  SoftDeleteRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SoftDeleteResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.21) for the soft delete response control.
   */
  @NotNull public static final String SOFT_DELETE_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.21";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3163679387266190228L;



  // The DN of the soft-deleted representation of the target entry.
  @NotNull private final String softDeletedEntryDN;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  SoftDeleteResponseControl()
  {
    softDeletedEntryDN = null;
  }



  /**
   * Creates a new soft delete response control with the provided information.
   *
   * @param  softDeletedEntryDN  The DN of the soft-deleted representation of
   *                             the target entry.
   */
  public SoftDeleteResponseControl(@NotNull final String softDeletedEntryDN)
  {
    super(SOFT_DELETE_RESPONSE_OID, false,
         new ASN1OctetString(softDeletedEntryDN));

    Validator.ensureNotNull(softDeletedEntryDN);

    this.softDeletedEntryDN = softDeletedEntryDN;
  }



  /**
   * Creates a new soft delete response control with the provided information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be considered
   *                     critical.
   * @param  value       The value for the control.
   *
   * @throws  LDAPException  If the provided information cannot be used to
   *                         create a valid soft delete response control.
   */
  public SoftDeleteResponseControl(@NotNull final String oid,
                                   final boolean isCritical,
                                   @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SOFT_DELETE_RESPONSE_NO_VALUE.get());
    }

    softDeletedEntryDN = value.stringValue();
    if (! DN.isValidDN(softDeletedEntryDN))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SOFT_DELETE_RESPONSE_VALUE_NOT_DN.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SoftDeleteResponseControl decodeControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new SoftDeleteResponseControl(oid, isCritical, value);
  }



  /**
   * Retrieves the DN of the entry containing the soft-deleted representation of
   * the target entry.
   *
   * @return  The DN of the entry containing the soft-deleted representation of
   *          the target entry.
   */
  @NotNull()
  public String getSoftDeletedEntryDN()
  {
    return softDeletedEntryDN;
  }



  /**
   * Extracts a soft delete response control from the provided delete result.
   *
   * @param  deleteResult  The delete result from which to retrieve the soft
   *                       delete response control.
   *
   * @return  The soft delete response control contained in the provided delete
   *          result, or {@code null} if the result did not contain a soft
   *          delete response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the soft delete response control contained
   *                         in the provided result.
   */
  @Nullable()
  public static SoftDeleteResponseControl get(
                     @NotNull final LDAPResult deleteResult)
         throws LDAPException
  {
    final Control c = deleteResult.getResponseControl(SOFT_DELETE_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof SoftDeleteResponseControl)
    {
      return (SoftDeleteResponseControl) c;
    }
    else
    {
      return new SoftDeleteResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SOFT_DELETE_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SoftDeleteResponseControl(softDeletedEntryDN='");
    buffer.append(softDeletedEntryDN);
    buffer.append("')");
  }
}
