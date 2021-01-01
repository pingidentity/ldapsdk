/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the server-side sort response
 * control, as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc2891.txt">RFC 2891</A>.  It may be used
 * to provide information about the result of server-side sort processing.  If
 * the corresponding search request included the
 * {@link ServerSideSortRequestControl}, then the search result done message
 * may include this response control to provide information about the state of
 * the sorting.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ServerSideSortResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.2.840.113556.1.4.474) for the server-side sort response control.
   */
  @NotNull public static final String SERVER_SIDE_SORT_RESPONSE_OID =
       "1.2.840.113556.1.4.474";



  /**
   * The BER type to use for the element that holds the attribute type.
   */
  private static final byte TYPE_ATTRIBUTE_TYPE = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8707533262822875822L;



  // The result code for this server-side sort response control.
  @NotNull private final ResultCode resultCode;

  // The name of the attribute associated with this result, if available.
  @Nullable private final String attributeName;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  ServerSideSortResponseControl()
  {
    resultCode    = null;
    attributeName = null;
  }



  /**
   * Creates a new server-side sort response control with the provided
   * information.
   *
   * @param  resultCode     The result code for this server-side sort response.
   * @param  attributeName  The name of the attribute associated with this
   *                        result.  It may be {@code null} if there is no
   *                        associated attribute name.
   */
  public ServerSideSortResponseControl(@NotNull final ResultCode resultCode,
                                       @Nullable final String attributeName)
  {
    this(resultCode, attributeName, false);
  }



  /**
   * Creates a new server-side sort response control with the provided
   * information.
   *
   * @param  resultCode     The result code for this server-side sort response.
   * @param  attributeName  The name of the attribute associated with this
   *                        result.  It may be {@code null} if there is no
   *                        associated attribute name.
   * @param  isCritical     Indicates whether this control should be marked
   *                        critical.  Response controls should generally not be
   *                        critical.
   */
  public ServerSideSortResponseControl(@NotNull final ResultCode resultCode,
                                       @Nullable final String attributeName,
                                       final boolean isCritical)
  {
    super(SERVER_SIDE_SORT_RESPONSE_OID, isCritical,
          encodeValue(resultCode, attributeName));

    this.resultCode    = resultCode;
    this.attributeName = attributeName;
  }



  /**
   * Creates a new server-side sort response control from the information
   * contained in the provided control.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided control as a server-side sort response
   *                         control.
   */
  public ServerSideSortResponseControl(@NotNull final String oid,
                                       final boolean isCritical,
                                       @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_RESPONSE_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement =
           ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_RESPONSE_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if ((valueElements.length < 1) || (valueElements.length > 2))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_RESPONSE_INVALID_ELEMENT_COUNT.get(
                                   valueElements.length));
    }

    try
    {
      final int rc =
           ASN1Enumerated.decodeAsEnumerated(valueElements[0]).intValue();
      resultCode = ResultCode.valueOf(rc);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_RESPONSE_FIRST_NOT_ENUM.get(ae), ae);
    }

    if (valueElements.length == 2)
    {
      attributeName =
           ASN1OctetString.decodeAsOctetString(valueElements[1]).stringValue();
    }
    else
    {
      attributeName = null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ServerSideSortResponseControl decodeControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new ServerSideSortResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a server-side sort response control from the provided result.
   *
   * @param  result  The result from which to retrieve the server-side sort
   *                 response control.
   *
   * @return  The server-side sort response control contained in the provided
   *          result, or {@code null} if the result did not contain a
   *          server-side sort response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the server-side sort response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static ServerSideSortResponseControl get(
                     @NotNull final SearchResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(SERVER_SIDE_SORT_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof ServerSideSortResponseControl)
    {
      return (ServerSideSortResponseControl) c;
    }
    else
    {
      return new ServerSideSortResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  resultCode     The result code for this server-side sort response
   *                        control.
   * @param  attributeName  The attribute name to include in the control, or
   *                        {@code null} if it should not be provided.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final ResultCode resultCode,
                      @Nullable final String attributeName)
  {
    final ASN1Element[] valueElements;
    if (attributeName == null)
    {
      valueElements = new ASN1Element[]
      {
        new ASN1Enumerated(resultCode.intValue())
      };
    }
    else
    {
      valueElements = new ASN1Element[]
      {
        new ASN1Enumerated(resultCode.intValue()),
        new ASN1OctetString(TYPE_ATTRIBUTE_TYPE, attributeName)
      };
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }



  /**
   * Retrieves the result code for this server-side sort response control.
   *
   * @return  The result code for this server-side sort response control.
   */
  @NotNull()
  public ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the attribute name for this server-side sort response control, if
   * available.
   *
   * @return  The attribute name for this server-side sort response control, or
   *          {@code null} if none was provided.
   */
  @Nullable()
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SORT_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ServerSideSortResponseControl(resultCode=");
    buffer.append(resultCode);

    if (attributeName != null)
    {
      buffer.append(", attributeName='");
      buffer.append(attributeName);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
