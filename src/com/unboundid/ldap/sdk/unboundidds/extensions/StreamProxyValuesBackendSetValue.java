/*
 * Copyright 2009-2018 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a data structure for holding a value included in the
 * stream proxy values intermediate response.  It contains the value, and the ID
 * of the backend set with which the value is associated.
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
public final class StreamProxyValuesBackendSetValue
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -799860937140238448L;



  // The backend set ID for this backend set value.
  private final ASN1OctetString backendSetID;

  // The value for this backend set value.
  private final ASN1OctetString value;



  /**
   * Creates a new stream proxy values backend set value object with the
   * provided information.
   *
   * @param  backendSetID  The backend set ID for this backend set value.  It
   *                       must not be {@code null}.
   * @param  value         The value for this backend set value.  It must not be
   *                       {@code null}.
   */
  public StreamProxyValuesBackendSetValue(final ASN1OctetString backendSetID,
                                          final ASN1OctetString value)
  {
    ensureNotNull(backendSetID, value);

    this.backendSetID = backendSetID;
    this.value        = value;
  }



  /**
   * Retrieves the backend set ID for this backend set value.
   *
   * @return  The backend set ID for this backend set value.
   */
  public ASN1OctetString getBackendSetID()
  {
    return backendSetID;
  }



  /**
   * Retrieves the value for this backend set value.
   *
   * @return  The value for this backend set value.
   */
  public ASN1OctetString getValue()
  {
    return value;
  }



  /**
   * Encodes this backend set value in a form suitable for inclusion in a stream
   * proxy values intermediate response.
   *
   * @return  An ASN.1 element containing the encoded representation of this
   *          stream proxy values backend set value.
   */
  public ASN1Element encode()
  {
    return new ASN1Sequence(backendSetID, value);
  }



  /**
   * Decodes the provided ASN.1 element as a stream proxy values backend set
   * value.
   *
   * @param  element  The ASN.1 element to be decoded as a stream proxy values
   *                  backend set value.
   *
   * @return  The decoded stream proxy values backend set value.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided ASN.1 element as a stream proxy values
   *                         backend set value.
   */
  public static StreamProxyValuesBackendSetValue decode(
                                                      final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      return new StreamProxyValuesBackendSetValue(
           ASN1OctetString.decodeAsOctetString(elements[0]),
           ASN1OctetString.decodeAsOctetString(elements[1]));
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_STREAM_PROXY_VALUES_BACKEND_SET_VALUE_CANNOT_DECODE.get(
                getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves a string representation of this backend set value.
   *
   * @return  A string representation of this backend set value.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this backend set value to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("StreamProxyValuesBackendSetValue(backendSetID=");
    backendSetID.toString(buffer);
    buffer.append(", value=");
    value.toString(buffer);
    buffer.append(')');
  }
}
