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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.io.Serializable;
import java.util.ArrayList;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class defines a data structure that provides information about the
 * result of assured replication processing, either on a replication server (if
 * that is all that is needed to satisfy the desired level of assurance) or
 * on a directory server (if required by the desired level of assurance).
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
public final class AssuredReplicationServerResult
       implements Serializable
{
  /**
   * The BER type for the result code element.
   */
  private static final byte TYPE_RESULT_CODE = (byte) 0x80;


  /**
   * The BER type for the server ID element.
   */
  private static final byte TYPE_SERVER_ID = (byte) 0x81;


  /**
   * The BER type for the replica ID element.
   */
  private static final byte TYPE_REPLICA_ID = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3015162215769386343L;



  // The result code for this server result.
  @NotNull private final AssuredReplicationServerResultCode resultCode;

  // The replica ID of the associated directory server.
  @Nullable private final Short replicaID;

  // The server ID of the associated replication server.
  @Nullable private final Short replicationServerID;



  /**
   * Creates a new assured replication server result with the provided
   * information.
   *
   * @param  resultCode           The result code that indicates the state of
   *                              assurance processing for the associated
   *                              replication server and/or directory server.
   *                              It must not be {@code null}.
   * @param  replicationServerID  The server ID of the replication server from
   *                              which this server result was obtained.  It may
   *                              be {@code null} if no replication server ID is
   *                              available for this result.
   * @param  replicaID            The replica ID of the directory server with
   *                              which this result is associated.  It may be
   *                              {@code null} if no replica ID is available
   *                              for this result.
   */
  public AssuredReplicationServerResult(
       @NotNull final AssuredReplicationServerResultCode resultCode,
       @Nullable final Short replicationServerID,
       @Nullable final Short replicaID)
  {
    this.resultCode = resultCode;
    this.replicationServerID = replicationServerID;
    this.replicaID = replicaID;
  }



  /**
   * Retrieves the result code that indicates the state of assurance processing
   * for this server result.
   *
   * @return  The result code for this server result.
   */
  @NotNull()
  public AssuredReplicationServerResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the server ID for the replication server from which this server
   * result was obtained, if available.
   *
   * @return  The server ID for the replication server from which this server
   *          result was obtained, or {@code null} if no replication server ID
   *          is available.
   */
  @Nullable()
  public Short getReplicationServerID()
  {
    return replicationServerID;
  }



  /**
   * Retrieves the replica ID for the directory server with which this server
   * result is associated, if applicable.
   *
   * @return  The replica ID for the directory server with which this server
   *          result is associated, or {@code null} if there is no associated
   *          directory server.
   */
  @Nullable()
  public Short getReplicaID()
  {
    return replicaID;
  }



  /**
   * Encodes this assured replication server result to an ASN.1 element suitable
   * for use in a {@link AssuredReplicationResponseControl}.
   *
   * @return  The encoded representation of this assured replication server
   *          result.
   */
  @NotNull()
  ASN1Element encode()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(3);

    elements.add(new ASN1Enumerated(TYPE_RESULT_CODE, resultCode.intValue()));

    if (replicationServerID != null)
    {
      elements.add(new ASN1Integer(TYPE_SERVER_ID, replicationServerID));
    }

    if (replicaID != null)
    {
      elements.add(new ASN1Integer(TYPE_REPLICA_ID, replicaID));
    }

    return new ASN1Sequence(elements);
  }



  /**
   * Decodes the provided ASN.1 element as an assured replication server
   * result.
   *
   * @param  element  The ASN.1 element to be decoded.  It must not be
   *                  {@code null}.
   *
   * @return  The decoded assured replication server result.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the provided ASN.1 element as an assured
   *                         replication server result.
   */
  @NotNull()
  static AssuredReplicationServerResult decode(
              @NotNull final ASN1Element element)
         throws LDAPException
  {
    AssuredReplicationServerResultCode resultCode = null;
    Short serverID  = null;
    Short replicaID = null;

    try
    {
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(element).elements())
      {
        switch (e.getType())
        {
          case TYPE_RESULT_CODE:
            final int rcValue = ASN1Enumerated.decodeAsEnumerated(e).intValue();
            resultCode = AssuredReplicationServerResultCode.valueOf(rcValue);
            if (resultCode == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ASSURED_REPLICATION_SERVER_RESULT_INVALID_RESULT_CODE.
                        get(rcValue));
            }
            break;

          case TYPE_SERVER_ID:
            serverID = (short) ASN1Integer.decodeAsInteger(e).intValue();
            break;

          case TYPE_REPLICA_ID:
            replicaID = (short) ASN1Integer.decodeAsInteger(e).intValue();
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ASSURED_REPLICATION_SERVER_RESULT_UNEXPECTED_ELEMENT_TYPE.
                      get(StaticUtils.toHex(e.getType())));
        }
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
           ERR_ASSURED_REPLICATION_SERVER_RESULT_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (resultCode == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ASSURED_REPLICATION_SERVER_RESULT_NO_RESULT_CODE.get());
    }

    return new AssuredReplicationServerResult(resultCode, serverID, replicaID);
  }



  /**
   * Retrieves a string representation of this assured replication server
   * result.
   *
   * @return  A string representation of this assured replication server
   *          result.
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
   * Appends a string representation of this assured replication server result
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AssuredReplicationServerResult(resultCode=");
    buffer.append(resultCode.name());

    if (replicationServerID != null)
    {
      buffer.append(", replicationServerID=");
      buffer.append(replicationServerID);
    }

    if (replicaID != null)
    {
      buffer.append(", replicaID=");
      buffer.append(replicaID);
    }

    buffer.append(')');
  }
}
