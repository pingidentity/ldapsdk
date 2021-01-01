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
 * to identify potential incompatibility problems between two backup
 * compatibility descriptor values.  This can be used to determine whether a
 * backup from one server (or an older version of the same server) could be
 * restored into another server (or a newer version of the same server).  It
 * may also be useful in determining whether replication initialization via
 * binary copy may be performed between two servers.
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
 * The OID for this extended request is 1.3.6.1.4.1.30221.2.6.32.  It must have
 * a value with the following encoding:
 * <PRE>
 *   IdentifyBackupCompatibilityProblemsRequest ::= SEQUENCE {
 *        sourceDescriptor     [0] OCTET STRING,
 *        targetDescriptor     [1] OCTET STRING,
 *        ... }
 * </PRE>
 *
 * @see  IdentifyBackupCompatibilityProblemsExtendedResult
 * @see  GetBackupCompatibilityDescriptorExtendedRequest
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IdentifyBackupCompatibilityProblemsExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.32) for the identify backup compatibility
   * problems extended request.
   */
  @NotNull public static final String
       IDENTIFY_BACKUP_COMPATIBILITY_PROBLEMS_REQUEST_OID =
            "1.3.6.1.4.1.30221.2.6.32";



  /**
   * The BER type for the source descriptor element in the value sequence.
   */
  private static final byte TYPE_SOURCE_DESCRIPTOR = (byte) 0x80;



  /**
   * The BER type for the target descriptor element in the value sequence.
   */
  private static final byte TYPE_TARGET_DESCRIPTOR = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6723590129573376599L;



  // The backup compatibility descriptor obtained from the source server, or
  // from a backup to be restored.
  @NotNull private final ASN1OctetString sourceDescriptor;

  // The backup compatibility descriptor obtained from the target server.
  @NotNull private final ASN1OctetString targetDescriptor;



  /**
   * Creates a new identify backup compatibility problems extended request with
   * the provided information.
   *
   * @param  sourceDescriptor  The backup compatibility descriptor obtained from
   *                           the source server, or from a backup to be
   *                           restored.  It must not be {@code null}.
   * @param  targetDescriptor  The backup compatibility descriptor obtained from
   *                           the target server.  It must not be {@code null}.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if no controls
   *                           should be included.
   */
  public IdentifyBackupCompatibilityProblemsExtendedRequest(
       @NotNull final ASN1OctetString sourceDescriptor,
       @NotNull final ASN1OctetString targetDescriptor,
       @Nullable final Control... controls)
  {
    super(IDENTIFY_BACKUP_COMPATIBILITY_PROBLEMS_REQUEST_OID,
         encodeValue(sourceDescriptor, targetDescriptor), controls);

    this.sourceDescriptor = new ASN1OctetString(TYPE_SOURCE_DESCRIPTOR,
         sourceDescriptor.getValue());
    this.targetDescriptor = new ASN1OctetString(TYPE_TARGET_DESCRIPTOR,
         targetDescriptor.getValue());
  }



  /**
   * Creates a new identify backup compatibility problems extended request from
   * the provided generic extended request.
   *
   * @param  r  The generic extended request to decode as an identify backup
   *            compatibility problems extended request.
   *
   * @throws LDAPException  If the provided request cannot be decoded as an
   *                        identify backup compatibility problems extended
   *                        request.
   */
  public IdentifyBackupCompatibilityProblemsExtendedRequest(
              @NotNull final ExtendedRequest r)
       throws LDAPException
  {
    super(r);

    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_IDENTIFY_BACKUP_COMPAT_PROBLEMS_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      sourceDescriptor =
           new ASN1OctetString(TYPE_SOURCE_DESCRIPTOR, elements[0].getValue());
      targetDescriptor =
           new ASN1OctetString(TYPE_SOURCE_DESCRIPTOR, elements[1].getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_IDENTIFY_BACKUP_COMPAT_PROBLEMS_REQUEST_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into a format suitable for use as the
   * value of this extended request.
   *
   * @param  sourceDescriptor  The backup compatibility descriptor obtained from
   *                           the source server, or from a backup to be
   *                           restored.  It must not be {@code null}.
   * @param  targetDescriptor  The backup compatibility descriptor obtained from
   *                           the target server.  It must not be {@code null}.
   *
   * @return  The ASN.1 octet string containing the encoded representation of
   *          the provided information.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final ASN1OctetString sourceDescriptor,
               @NotNull final ASN1OctetString targetDescriptor)
  {
    Validator.ensureNotNull(sourceDescriptor);
    Validator.ensureNotNull(targetDescriptor);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(TYPE_SOURCE_DESCRIPTOR,
              sourceDescriptor.getValue()),
         new ASN1OctetString(TYPE_TARGET_DESCRIPTOR,
              targetDescriptor.getValue()));

    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Retrieves the backup compatibility descriptor obtained from the source
   * server, or from a backup to be restored.
   *
   * @return  The backup compatibility descriptor obtained from the source
   *          server, or from a backup to be restored.
   */
  @NotNull()
  public ASN1OctetString getSourceDescriptor()
  {
    return sourceDescriptor;
  }



  /**
   * Retrieves the backup compatibility descriptor obtained from the target
   * server.
   *
   * @return  The backup compatibility descriptor obtained from the target
   *          server.
   */
  @NotNull()
  public ASN1OctetString getTargetDescriptor()
  {
    return targetDescriptor;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public IdentifyBackupCompatibilityProblemsExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new IdentifyBackupCompatibilityProblemsExtendedResult(
         extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public IdentifyBackupCompatibilityProblemsExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public IdentifyBackupCompatibilityProblemsExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final IdentifyBackupCompatibilityProblemsExtendedRequest r =
         new IdentifyBackupCompatibilityProblemsExtendedRequest(
              sourceDescriptor, targetDescriptor, controls);
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
    return INFO_EXTENDED_REQUEST_NAME_IDENTIFY_BACKUP_COMPAT_PROBLEMS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("IdentifyBackupCompatibilityProblemsExtendedRequest(" +
         "sourceDescriptorLength=");
    buffer.append(sourceDescriptor.getValueLength());
    buffer.append(", targetDescriptorLength=");
    buffer.append(targetDescriptor.getValueLength());

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
