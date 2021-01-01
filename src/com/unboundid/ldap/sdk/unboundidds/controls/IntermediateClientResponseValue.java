/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
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
 * This class implements a data structure which encapsulates the value of an
 * intermediate client response value.  It may recursively embed intermediate
 * client response values from upstream servers.
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
 * See the documentation in the {@link IntermediateClientRequestControl} class
 * for an example of using the intermediate client request and response
 * controls.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IntermediateClientResponseValue
       implements Serializable
{
  /**
   * The BER type for the upstreamResponse element.
   */
  private static final byte TYPE_UPSTREAM_RESPONSE = (byte) 0xA0;



  /**
   * The BER type for the upstreamServerAddress element.
   */
  private static final byte TYPE_UPSTREAM_SERVER_ADDRESS = (byte) 0x81;



  /**
   * The BER type for the upstreamServerSecure element.
   */
  private static final byte TYPE_UPSTREAM_SERVER_SECURE = (byte) 0x82;



  /**
   * The BER type for the serverName element.
   */
  private static final byte TYPE_SERVER_NAME = (byte) 0x83;



  /**
   * The BER type for the serverSessionID element.
   */
  private static final byte TYPE_SERVER_SESSION_ID = (byte) 0x84;



  /**
   * The BER type for the serverResponseID element.
   */
  private static final byte TYPE_SERVER_RESPONSE_ID = (byte) 0x85;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5165171788442351399L;



  // Indicates whether communication with the upstream server is secure.
  @Nullable private final Boolean upstreamServerSecure;

  // The upstream response, if available.
  @Nullable private final IntermediateClientResponseValue upstreamResponse;

  // The server name, which describes the server application, if present.
  @Nullable private final String serverName;

  // The server response ID, if present.
  @Nullable private final String serverResponseID;

  // The server session ID, if present.
  @Nullable private final String serverSessionID;

  // The address of the upstream server, if available.
  @Nullable private final String upstreamServerAddress;



  /**
   * Creates a new intermediate client response value with the provided
   * information.
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
  public IntermediateClientResponseValue(
              @Nullable final IntermediateClientResponseValue upstreamResponse,
              @Nullable final String upstreamServerAddress,
              @Nullable final Boolean upstreamServerSecure,
              @Nullable final String serverName,
              @Nullable final String serverSessionID,
              @Nullable final String serverResponseID)
  {
    this.upstreamResponse      = upstreamResponse;
    this.upstreamServerAddress = upstreamServerAddress;
    this.upstreamServerSecure  = upstreamServerSecure;
    this.serverName            = serverName;
    this.serverSessionID       = serverSessionID;
    this.serverResponseID      = serverResponseID;
  }



  /**
   * Retrieves the wrapped response from an upstream server, if available.
   *
   * @return  The wrapped response from an upstream server, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public IntermediateClientResponseValue getUpstreamResponse()
  {
    return upstreamResponse;
  }



  /**
   * Retrieves the IP address or resolvable name of the upstream server system,
   * if available.
   *
   * @return  The IP address or resolvable name of the upstream server system,
   *          {@code null} if there is no upstream server or its address is not
   *          available.
   */
  @Nullable()
  public String getUpstreamServerAddress()
  {
    return upstreamServerAddress;
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
  @Nullable()
  public Boolean upstreamServerSecure()
  {
    return upstreamServerSecure;
  }



  /**
   * Retrieves a string that identifies the server application that created this
   * intermediate client response value.
   *
   * @return  A string that may be used to identify the server application that
   *          created this intermediate client response value.
   */
  @Nullable()
  public String getServerName()
  {
    return serverName;
  }



  /**
   * Retrieves a string that may be used to identify the session in the server
   * application.
   *
   * @return  A string that may be used to identify the session in the server
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getServerSessionID()
  {
    return serverSessionID;
  }



  /**
   * Retrieves a string that may be used to identify the response in the server
   * application.
   *
   * @return  A string that may be used to identify the response in the server
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getServerResponseID()
  {
    return serverResponseID;
  }



  /**
   * Encodes this intermediate client response value to a form that may be
   * included in the response control.
   *
   * @return  An ASN.1 octet string containing the encoded client response
   *          value.
   */
  @NotNull()
  public ASN1Sequence encode()
  {
    return encode(ASN1Constants.UNIVERSAL_SEQUENCE_TYPE);
  }



  /**
   * Encodes this intermediate client response value to a form that may be
   * included in the response control.
   *
   * @param  type  The BER type to use for this element.
   *
   * @return  An ASN.1 octet string containing the encoded client response
   *          value.
   */
  @NotNull()
  private ASN1Sequence encode(final byte type)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(6);

    if (upstreamResponse != null)
    {
      elements.add(upstreamResponse.encode(TYPE_UPSTREAM_RESPONSE));
    }

    if (upstreamServerAddress != null)
    {
      elements.add(new ASN1OctetString(TYPE_UPSTREAM_SERVER_ADDRESS,
                                       upstreamServerAddress));
    }

    if (upstreamServerSecure != null)
    {
      elements.add(new ASN1Boolean(TYPE_UPSTREAM_SERVER_SECURE,
                                   upstreamServerSecure));
    }

    if (serverName != null)
    {
      elements.add(new ASN1OctetString(TYPE_SERVER_NAME,  serverName));
    }

    if (serverSessionID != null)
    {
      elements.add(new ASN1OctetString(TYPE_SERVER_SESSION_ID,
                                       serverSessionID));
    }

    if (serverResponseID != null)
    {
      elements.add(new ASN1OctetString(TYPE_SERVER_RESPONSE_ID,
                                       serverResponseID));
    }

    return new ASN1Sequence(type, elements);
  }



  /**
   * Decodes the provided ASN.1 sequence as an intermediate client response
   * value.
   *
   * @param  sequence  The sequence to be decoded as an intermediate client
   *                   response value.
   *
   * @return  The decoded intermediate client response value.
   *
   * @throws  LDAPException  If the provided sequence cannot be decoded as an
   *                         intermediate client response value.
   */
  @NotNull()
  public static IntermediateClientResponseValue decode(
                     @NotNull final ASN1Sequence sequence)
         throws LDAPException
  {
    Boolean                         upstreamServerSecure  = null;
    IntermediateClientResponseValue upstreamResponse      = null;
    String                          upstreamServerAddress = null;
    String                          serverName            = null;
    String                          serverResponseID      = null;
    String                          serverSessionID       = null;

    for (final ASN1Element element : sequence.elements())
    {
      switch (element.getType())
      {
        case TYPE_UPSTREAM_RESPONSE:
          try
          {
            final ASN1Sequence s = ASN1Sequence.decodeAsSequence(element);
            upstreamResponse = decode(s);
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ICRESP_CANNOT_DECODE_UPSTREAM_RESPONSE.get(
                      le.getMessage()), le);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ICRESP_CANNOT_DECODE_UPSTREAM_RESPONSE.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
          break;

        case TYPE_UPSTREAM_SERVER_ADDRESS:
          upstreamServerAddress =
               ASN1OctetString.decodeAsOctetString(element).stringValue();
          break;

        case TYPE_UPSTREAM_SERVER_SECURE:
          try
          {
            upstreamServerSecure =
                 ASN1Boolean.decodeAsBoolean(element).booleanValue();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ICRESP_CANNOT_DECODE_UPSTREAM_SECURE.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
          break;

        case TYPE_SERVER_NAME:
          serverName =
               ASN1OctetString.decodeAsOctetString(element).stringValue();
          break;

        case TYPE_SERVER_SESSION_ID:
          serverSessionID =
               ASN1OctetString.decodeAsOctetString(element).stringValue();
          break;

        case TYPE_SERVER_RESPONSE_ID:
          serverResponseID =
               ASN1OctetString.decodeAsOctetString(element).stringValue();
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_ICRESP_INVALID_ELEMENT_TYPE.get(
                    StaticUtils.toHex(element.getType())));
      }
    }

    return new IntermediateClientResponseValue(upstreamResponse,
                                               upstreamServerAddress,
                                               upstreamServerSecure,
                                               serverName, serverSessionID,
                                               serverResponseID);
  }



  /**
   * Generates a hash code for this intermediate client response value.
   *
   * @return  A hash code for this intermediate client response value.
   */
  @Override()
  public int hashCode()
  {
    int hashCode = 0;

    if (upstreamResponse != null)
    {
      hashCode += upstreamResponse.hashCode();
    }

    if (upstreamServerAddress != null)
    {
      hashCode += upstreamServerAddress.hashCode();
    }

    if (upstreamServerSecure != null)
    {
      hashCode += upstreamServerSecure.hashCode();
    }

    if (serverName != null)
    {
      hashCode += serverName.hashCode();
    }

    if (serverSessionID != null)
    {
      hashCode += serverSessionID.hashCode();
    }

    if (serverResponseID != null)
    {
      hashCode += serverResponseID.hashCode();
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this intermediate client
   * response value.  It will only be considered equal if the provided object is
   * also an intermediate client response value with all the same fields.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          intermediate client response value, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == this)
    {
      return true;
    }
    else if (o == null)
    {
      return false;
    }
    else if (! (o instanceof IntermediateClientResponseValue))
    {
      return false;
    }

    final IntermediateClientResponseValue v =
         (IntermediateClientResponseValue) o;

    if (upstreamResponse == null)
    {
      if (v.upstreamResponse != null)
      {
        return false;
      }
    }
    else
    {
      if (! upstreamResponse.equals(v.upstreamResponse))
      {
        return false;
      }
    }

    if (upstreamServerAddress == null)
    {
      if (v.upstreamServerAddress != null)
      {
        return false;
      }
    }
    else
    {
      if (! upstreamServerAddress.equals(v.upstreamServerAddress))
      {
        return false;
      }
    }

    if (upstreamServerSecure == null)
    {
      if (v.upstreamServerSecure != null)
      {
        return false;
      }
    }
    else
    {
      if (! upstreamServerSecure.equals(v.upstreamServerSecure))
      {
        return false;
      }
    }

    if (serverName == null)
    {
      if (v.serverName != null)
      {
        return false;
      }
    }
    else
    {
      if (! serverName.equals(v.serverName))
      {
        return false;
      }
    }

    if (serverSessionID == null)
    {
      if (v.serverSessionID != null)
      {
        return false;
      }
    }
    else
    {
      if (! serverSessionID.equals(v.serverSessionID))
      {
        return false;
      }
    }

    if (serverResponseID == null)
    {
      if (v.serverResponseID != null)
      {
        return false;
      }
    }
    else
    {
      if (! serverResponseID.equals(v.serverResponseID))
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Retrieves a string representation of this intermediate client response
   * value.
   *
   * @return  A string representation of this intermediate client response
   *          value.
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
   * Appends a string representation of this intermediate client response value
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information is to be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("IntermediateClientResponseValue(");

    boolean added = false;
    if (upstreamResponse != null)
    {
      buffer.append("upstreamResponse=");
      upstreamResponse.toString(buffer);
      added = true;
    }

    if (upstreamServerAddress != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("upstreamServerAddress='");
      buffer.append(upstreamServerAddress);
      buffer.append('\'');
    }

    if (upstreamServerSecure != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("upstreamServerSecure='");
      buffer.append(upstreamServerSecure);
      buffer.append('\'');
    }

    if (serverName != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("serverName='");
      buffer.append(serverName);
      buffer.append('\'');
    }

    if (serverSessionID != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("serverSessionID='");
      buffer.append(serverSessionID);
      buffer.append('\'');
    }

    if (serverResponseID != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("serverResponseID='");
      buffer.append(serverResponseID);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
