/*
 * Copyright 2008-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class defines an intermediate client response control, which can be used
 * to provide a server with information about the client and any downstream
 * clients that it may have.
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
 * <BR>
 * This control is not based on any public standard.  It was originally
 * developed for use with the Ping Identity, UnboundID, and Alcatel-Lucent 8661
 * Directory Server.  The value of this control uses the following encoding:
 * <BR><BR>
 * <PRE>
 * IntermediateClientResponse ::= SEQUENCE {
 *      upstreamResponse       [0] IntermediateClientResponse OPTIONAL,
 *      upstreamServerAddress  [1] OCTET STRING OPTIONAL,
 *      upstreamServerSecure   [2] BOOLEAN DEFAULT FALSE,
 *      serverName             [3] OCTET STRING OPTIONAL,
 *      serverSessionID        [4] OCTET STRING OPTIONAL,
 *      serverResponseID       [5] OCTET STRING OPTIONAL,
 *      ... }
 * </PRE>
 * See the documentation in the {@link IntermediateClientRequestControl} class
 * for an example of using the intermediate client request and response
 * controls.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IntermediateClientResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.2) for the intermediate client response
   * control.
   */
  public static final String INTERMEDIATE_CLIENT_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7476073413872875835L;



  // The value for this intermediate client response control.
  private final IntermediateClientResponseValue value;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  IntermediateClientResponseControl()
  {
    value = null;
  }



  /**
   * Creates a new intermediate client response control with the provided
   * information.  It will not be marked critical.
   *
   * @param  upstreamResponse       A wrapped intermediate client response from
   *                                an upstream server.  It may be {@code null}
   *                                if there is no wrapped upstream response.
   * @param  upstreamServerAddress  The IP address or resolvable name of the
   *                                upstream server system.  It may be
   *                                {@code null} if there is no upstream server
   *                                or its address is not available.
   * @param  upstreamServerSecure   Indicates whether communication with the
   *                                upstream server is secure.  It may be
   *                                {@code null} if there is no upstream server
   *                                or it is not known whether the communication
   *                                is secure.
   * @param  serverName             An identifier string that summarizes the
   *                                server application that created this
   *                                intermediate client response.  It may be
   *                                {@code null} if that information is not
   *                                available.
   * @param  serverSessionID        A string that may be used to identify the
   *                                session in the server application.  It may
   *                                be {@code null} if there is no available
   *                                session identifier.
   * @param  serverResponseID       A string that may be used to identify the
   *                                response in the server application.  It may
   *                                be {@code null} if there is no available
   *                                response identifier.
   */
  public IntermediateClientResponseControl(
              final IntermediateClientResponseValue upstreamResponse,
              final String upstreamServerAddress,
              final Boolean upstreamServerSecure, final String serverName,
              final String serverSessionID, final String serverResponseID)
  {
    this(false,
         new IntermediateClientResponseValue(upstreamResponse,
                  upstreamServerAddress, upstreamServerSecure, serverName,
                  serverSessionID, serverResponseID));
  }



  /**
   * Creates a new intermediate client response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         intermediate client response control.
   */
  public IntermediateClientResponseControl(final String oid,
                                           final boolean isCritical,
                                           final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ICRESP_CONTROL_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final Exception e)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ICRESP_CONTROL_VALUE_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    this.value = IntermediateClientResponseValue.decode(valueSequence);
  }



  /**
   * Creates a new intermediate client response control with the provided value.
   * It will be marked critical.
   *
   * @param  value  The value to use for this intermediate client response
   *                control.  It must not be {@code null}.
   */
  public IntermediateClientResponseControl(
              final IntermediateClientResponseValue value)
  {
    this(false, value);
  }



  /**
   * Creates a new intermediate client response control with the provided value.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.  Response controls should generally not be
   *                     critical.
   * @param  value       The value to use for this intermediate client response
   *                     control.  It must not be {@code null}.
   */
  public IntermediateClientResponseControl(final boolean isCritical,
              final IntermediateClientResponseValue value)
  {
    super(INTERMEDIATE_CLIENT_RESPONSE_OID, isCritical,
          new ASN1OctetString(value.encode().encode()));

    this.value = value;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public IntermediateClientResponseControl decodeControl(final String oid,
              final boolean isCritical, final ASN1OctetString value)
          throws LDAPException
  {
    return new IntermediateClientResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts an intermediate client response control from the provided result.
   *
   * @param  result  The result from which to retrieve the intermediate client
   *                 response control.
   *
   * @return  The intermediate client response control contained in the provided
   *          result, or {@code null} if the result did not contain an
   *          intermediate client response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the intermediate client response control
   *                         contained in the provided result.
   */
  public static IntermediateClientResponseControl get(final LDAPResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(INTERMEDIATE_CLIENT_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof IntermediateClientResponseControl)
    {
      return (IntermediateClientResponseControl) c;
    }
    else
    {
      return new IntermediateClientResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Retrieves the value for this intermediate client response.
   *
   * @return  The value for this intermediate client response.
   */
  public IntermediateClientResponseValue getResponseValue()
  {
    return value;
  }



  /**
   * Retrieves the wrapped response from an upstream server, if available.
   *
   * @return  The wrapped response from an upstream server, or {@code null} if
   *          there is none.
   */
  public IntermediateClientResponseValue getUpstreamResponse()
  {
    return value.getUpstreamResponse();
  }



  /**
   * Retrieves the IP address or resolvable name of the upstream server system,
   * if available.
   *
   * @return  The IP address or resolvable name of the upstream server system,
   *          {@code null} if there is no upstream server or its address is not
   *          available.
   */
  public String getUpstreamServerAddress()
  {
    return value.getUpstreamServerAddress();
  }



  /**
   * Indicates whether the communication with the communication with the
   * upstream server is secure (i.e., whether communication between the
   * server application and the upstream server is safe from interpretation or
   * undetectable alteration by a third party observer or interceptor).
   *
   *
   * @return  {@code Boolean.TRUE} if communication with the upstream server is
   *          secure, {@code Boolean.FALSE} if it is not secure, or
   *          {@code null} if there is no upstream server or it is not known
   *          whether the communication is secure.
   */
  public Boolean upstreamServerSecure()
  {
    return value.upstreamServerSecure();
  }



  /**
   * Retrieves a string that identifies the server application that created this
   * intermediate client response value.
   *
   * @return  A string that may be used to identify the server application that
   *          created this intermediate client response value.
   */
  public String getServerName()
  {
    return value.getServerName();
  }



  /**
   * Retrieves a string that may be used to identify the session in the server
   * application.
   *
   * @return  A string that may be used to identify the session in the server
   *          application, or {@code null} if there is none.
   */
  public String getServerSessionID()
  {
    return value.getServerSessionID();
  }



  /**
   * Retrieves a string that may be used to identify the response in the server
   * application.
   *
   * @return  A string that may be used to identify the response in the server
   *          application, or {@code null} if there is none.
   */
  public String getServerResponseID()
  {
    return value.getServerResponseID();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_INTERMEDIATE_CLIENT_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("IntermediateClientResponseControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", value=");
    value.toString(buffer);
    buffer.append(')');
  }
}
