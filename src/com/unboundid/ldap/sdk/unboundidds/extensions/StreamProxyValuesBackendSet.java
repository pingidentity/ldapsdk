/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides a data structure for holding information about the
 * configuration of backend sets as used by the stream proxy values extended
 * request.
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
public final class StreamProxyValuesBackendSet
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5437145469462592611L;



  // The backend set ID for this backend set.
  @NotNull private final ASN1OctetString backendSetID;

  // The ports of the directory servers in this backend set.
  @NotNull private final int[] ports;

  // The addresses of the directory servers in this backend set.
  @NotNull private final String[] hosts;



  /**
   * Creates a new backend set with the provided information.
   *
   * @param  backendSetID  The backend set ID for this backend set.  It must not
   *                       be {@code null}.
   * @param  hosts         The addresses of the servers for this backend set.
   *                       It must not be {@code null} or empty, and it must
   *                       have the same number of elements as the {@code ports}
   *                       array.
   * @param  ports         The ports of the servers for this backend set.  It
   *                       must not be {@code null} or empty, and it must have
   *                       the same number of elements as the {@code hosts}
   *                       array.
   */
  public StreamProxyValuesBackendSet(
              @NotNull final ASN1OctetString backendSetID,
              @NotNull final String[] hosts,
              @NotNull final int[] ports)
  {
    Validator.ensureNotNull(backendSetID, hosts, ports);
    Validator.ensureTrue(hosts.length > 0);
    Validator.ensureTrue(hosts.length == ports.length);

    this.backendSetID = backendSetID;
    this.hosts        = hosts;
    this.ports        = ports;
  }



  /**
   * Retrieves the backend set ID for this backend set.
   *
   * @return  The backend set ID for this backend set.
   */
  @NotNull()
  public ASN1OctetString getBackendSetID()
  {
    return backendSetID;
  }



  /**
   * Retrieves the addresses of the servers for this backend set.
   *
   * @return  The addresses of the servers for this backend set.
   */
  @NotNull()
  public String[] getHosts()
  {
    return hosts;
  }



  /**
   * Retrieves the ports of the servers for this backend set.
   *
   * @return  The ports of the servers for this backend set.
   */
  @NotNull()
  public int[] getPorts()
  {
    return ports;
  }



  /**
   * Encodes this backend set object in a form suitable for inclusion in the
   * value of the stream proxy values extended request.
   *
   * @return  The encoded representation of this backend set.
   */
  @NotNull()
  public ASN1Element encode()
  {
    final ASN1Element[] hostPortElements = new ASN1Element[hosts.length];
    for (int i=0; i < hosts.length; i++)
    {
      hostPortElements[i] = new ASN1Sequence(
           new ASN1OctetString(hosts[i]),
           new ASN1Integer(ports[i]));
    }

    return new ASN1Sequence(
         backendSetID,
         new ASN1Sequence(hostPortElements));
  }



  /**
   * Decodes the provided ASN.1 element as a backend set.
   *
   * @param  element  The element to be decoded as a backend set.
   *
   * @return  The decoded backend set.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a backend set.
   */
  @NotNull()
  public static StreamProxyValuesBackendSet decode(
              @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final ASN1OctetString backendSetID =
           ASN1OctetString.decodeAsOctetString(elements[0]);

      final ASN1Element[] hostPortElements =
           ASN1Sequence.decodeAsSequence(elements[1]).elements();
      final String[] hosts = new String[hostPortElements.length];
      final int[]    ports = new int[hostPortElements.length];
      for (int i=0; i < hostPortElements.length; i++)
      {
        final ASN1Element[] hpElements =
             ASN1Sequence.decodeAsSequence(hostPortElements[i]).elements();
        hosts[i] =
             ASN1OctetString.decodeAsOctetString(hpElements[0]).stringValue();
        ports[i] = ASN1Integer.decodeAsInteger(hpElements[1]).intValue();
      }

      return new StreamProxyValuesBackendSet(backendSetID, hosts, ports);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_STREAM_PROXY_VALUES_BACKEND_SET_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves a string representation of this stream proxy values backend set.
   *
   * @return  A string representation of this stream proxy values backend set.
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
   * Appends a string representation of this stream proxy values backend set to
   * the provided buffer.
   *
   * @param  buffer  The buffer to which the stream representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("StreamProxyValuesBackendSet(id=");
    backendSetID.toString(buffer);
    buffer.append(", servers={");

    for (int i=0; i < hosts.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      buffer.append(hosts[i]);
      buffer.append(':');
      buffer.append(ports[i]);
    }
    buffer.append("})");
  }
}
