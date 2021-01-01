/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that can be used
 * to retrieve backup compatibility data for a Directory Server backend.  This
 * includes both a token that can be used to compare compatibility data with
 * other servers (or potentially the same server at a later date, for example
 * to check compatibility after upgrading to a new version), and a set of
 * capability strings that may provide additional context about how the backup
 * descriptor may be used.
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
 * The OID for this extended request is 1.3.6.1.4.1.30221.2.6.30.  It must have
 * a value with the following encoding:
 * <PRE>
 *   GetBackupCompatibilityDescriptorRequest ::= SEQUENCE {
 *        baseDN     [0] OCTET STRING,
 *        ... }
 * </PRE>
 *
 * @see  GetBackupCompatibilityDescriptorExtendedResult
 * @see  IdentifyBackupCompatibilityProblemsExtendedRequest
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetBackupCompatibilityDescriptorExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.30) for the get backup compatibility
   * descriptor extended request.
   */
  @NotNull public static final String
       GET_BACKUP_COMPATIBILITY_DESCRIPTOR_REQUEST_OID =
            "1.3.6.1.4.1.30221.2.6.30";



  /**
   * The BER type for the base DN element in the value sequence.
   */
  private static final byte TYPE_BASE_DN = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8170562432854535935L;



  // The base DN for the backend for which to obtain the backup compatibility
  // descriptor.
  @NotNull private final String baseDN;



  /**
   * Creates a new get backup compatibility descriptor extended request with the
   * provided base DN.
   *
   * @param  baseDN    The base DN for the backend for which to obtain the
   *                   backup compatibility descriptor.  It must not be
   *                   {@code null}, and should be the base DN of a backend
   *                   defined in the server.
   * @param  controls  The set of controls to include in the request.  It may be
   *                   {@code null} or empty if no controls should be included.
   */
  public GetBackupCompatibilityDescriptorExtendedRequest(
              @NotNull final String baseDN,
              @Nullable final Control... controls)
  {
    super(GET_BACKUP_COMPATIBILITY_DESCRIPTOR_REQUEST_OID, encodeValue(baseDN),
         controls);

    this.baseDN = baseDN;
  }



  /**
   * Creates a new get backup compatibility descriptor extended request from the
   * provided generic extended request.
   *
   * @param  r  The generic extended request to decode as a get backup
   *            compatibility descriptor extended request.
   *
   * @throws LDAPException  If the provided request cannot be decoded as a get
   *                        backup compatibility descriptor extended request.
   */
  public GetBackupCompatibilityDescriptorExtendedRequest(
              @NotNull final ExtendedRequest r)
         throws LDAPException
  {
    super(r);

    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_BACKUP_COMPAT_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      baseDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_BACKUP_COMPAT_REQUEST_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into a format suitable for use as the
   * value of this extended request.
   *
   * @param  baseDN  The base DN for the backend for which to obtain the
   *                 backup compatibility descriptor.  It must not be
   *                 {@code null}, and should be the base DN of a backend
   *                 defined in the server.
   *
   * @return  The ASN.1 octet string containing the encoded representation of
   *          the provided information.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String baseDN)
  {
    Validator.ensureNotNull(baseDN);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(TYPE_BASE_DN, baseDN));
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Retrieves the base DN for the backend for which to obtain the backup
   * compatibility descriptor.
   *
   * @return  The base DN for the backend for which to obtain the backup
   *          compatibility descriptor.
   */
  @NotNull()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetBackupCompatibilityDescriptorExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new GetBackupCompatibilityDescriptorExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetBackupCompatibilityDescriptorExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetBackupCompatibilityDescriptorExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final GetBackupCompatibilityDescriptorExtendedRequest r =
         new GetBackupCompatibilityDescriptorExtendedRequest(baseDN, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_GET_BACKUP_COMPAT.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetBackupCompatibilityDescriptorExtendedRequest(baseDN='");
    buffer.append(baseDN);
    buffer.append('\'');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
