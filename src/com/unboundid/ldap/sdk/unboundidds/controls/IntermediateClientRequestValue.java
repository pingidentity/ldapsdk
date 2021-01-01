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
 * intermediate client request value.  It may recursively embed intermediate
 * client request values from downstream clients.
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
public final class IntermediateClientRequestValue
       implements Serializable
{
  /**
   * The BER type for the downstreamRequest element.
   */
  private static final byte TYPE_DOWNSTREAM_REQUEST = (byte) 0xA0;



  /**
   * The BER type for the downstreamClientAddress element.
   */
  private static final byte TYPE_DOWNSTREAM_CLIENT_ADDRESS = (byte) 0x81;



  /**
   * The BER type for the downstreamClientSecure element.
   */
  private static final byte TYPE_DOWNSTREAM_CLIENT_SECURE = (byte) 0x82;



  /**
   * The BER type for the clientIdentity element.
   */
  private static final byte TYPE_CLIENT_IDENTITY = (byte) 0x83;



  /**
   * The BER type for the clientName element.
   */
  private static final byte TYPE_CLIENT_NAME = (byte) 0x84;



  /**
   * The BER type for the clientSessionID element.
   */
  private static final byte TYPE_CLIENT_SESSION_ID = (byte) 0x85;



  /**
   * The BER type for the clientRequestID element.
   */
  private static final byte TYPE_CLIENT_REQUEST_ID = (byte) 0x86;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -794887520013838259L;



  // Indicates whether the communication with the downstream client is secure.
  @Nullable private final Boolean downstreamClientSecure;

  // The downstream request value, if present.
  @Nullable private final IntermediateClientRequestValue downstreamRequest;

  // The requested client authorization identity, if present.
  @Nullable private final String clientIdentity;

  // The downstream client address, if present.
  @Nullable private final String downstreamClientAddress;

  // The client name, which describes the client application, if present.
  @Nullable private final String clientName;

  // The client request ID, if present.
  @Nullable private final String clientRequestID;

  // The client session ID, if present.
  @Nullable private final String clientSessionID;



  /**
   * Creates a new intermediate client request value with the provided
   * information.
   *
   * @param  downstreamRequest        A wrapped intermediate client request from
   *                                  a downstream client.  It may be
   *                                  {@code null} if there is no downstream
   *                                  request.
   * @param  downstreamClientAddress  The IP address or resolvable name of the
   *                                  downstream client system.  It may be
   *                                  {@code null} if there is no downstream
   *                                  client or its address is not available.
   * @param  downstreamClientSecure   Indicates whether communication with the
   *                                  downstream client is secure.  It may be
   *                                  {@code null} if there is no downstream
   *                                  client or it is not known whether the
   *                                  communication is secure.
   * @param  clientIdentity           The requested client authorization
   *                                  identity.  It may be {@code null} if there
   *                                  is no requested authorization identity.
   * @param  clientName               An identifier string that summarizes the
   *                                  client application that created this
   *                                  intermediate client request.  It may be
   *                                  {@code null} if that information is not
   *                                  available.
   * @param  clientSessionID          A string that may be used to identify the
   *                                  session in the client application.  It may
   *                                  be {@code null} if there is no available
   *                                  session identifier.
   * @param  clientRequestID          A string that may be used to identify the
   *                                  request in the client application.  It may
   *                                  be {@code null} if there is no available
   *                                  request identifier.
   */
  public IntermediateClientRequestValue(
              @Nullable final IntermediateClientRequestValue downstreamRequest,
              @Nullable final String downstreamClientAddress,
              @Nullable final Boolean downstreamClientSecure,
              @Nullable final String clientIdentity,
              @Nullable final String clientName,
              @Nullable final String clientSessionID,
              @Nullable final String clientRequestID)
  {
    this.downstreamRequest       = downstreamRequest;
    this.downstreamClientAddress = downstreamClientAddress;
    this.downstreamClientSecure  = downstreamClientSecure;
    this.clientIdentity          = clientIdentity;
    this.clientName              = clientName;
    this.clientSessionID         = clientSessionID;
    this.clientRequestID         = clientRequestID;
  }



  /**
   * Retrieves the wrapped request from a downstream client, if available.
   *
   * @return  The wrapped request from a downstream client, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public IntermediateClientRequestValue getDownstreamRequest()
  {
    return downstreamRequest;
  }



  /**
   * Retrieves the requested client authorization identity, if available.
   *
   * @return  The requested client authorization identity, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public String getClientIdentity()
  {
    return clientIdentity;
  }



  /**
   * Retrieves the IP address or resolvable name of the downstream client
   * system, if available.
   *
   * @return  The IP address or resolvable name of the downstream client system,
   *          or {@code null} if there is no downstream client or its address is
   *          not available.
   */
  @Nullable()
  public String getDownstreamClientAddress()
  {
    return downstreamClientAddress;
  }



  /**
   * Indicates whether the communication with the communication with the
   * downstream client is secure (i.e., whether communication between the
   * client application and the downstream client is safe from interpretation or
   * undetectable alteration by a third party observer or interceptor).
   *
   *
   * @return  {@code Boolean.TRUE} if communication with the downstream client
   *          is secure, {@code Boolean.FALSE} if it is not secure, or
   *          {@code null} if there is no downstream client or it is not known
   *          whether the communication is secure.
   */
  @Nullable()
  public Boolean downstreamClientSecure()
  {
    return downstreamClientSecure;
  }



  /**
   * Retrieves a string that identifies the client application that created this
   * intermediate client request value.
   *
   * @return  A string that may be used to identify the client application that
   *          created this intermediate client request value.
   */
  @Nullable()
  public String getClientName()
  {
    return clientName;
  }



  /**
   * Retrieves a string that may be used to identify the session in the client
   * application.
   *
   * @return  A string that may be used to identify the session in the client
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getClientSessionID()
  {
    return clientSessionID;
  }



  /**
   * Retrieves a string that may be used to identify the request in the client
   * application.
   *
   * @return  A string that may be used to identify the request in the client
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getClientRequestID()
  {
    return clientRequestID;
  }



  /**
   * Encodes this intermediate client request value to a form that may be
   * included in the request control.
   *
   * @return  An ASN.1 octet string containing the encoded client request value.
   */
  @NotNull()
  public ASN1Sequence encode()
  {
    return encode(ASN1Constants.UNIVERSAL_SEQUENCE_TYPE);
  }



  /**
   * Encodes this intermediate client request value to a form that may be
   * included in the request control.
   *
   * @param  type  The BER type to use for this element.
   *
   * @return  An ASN.1 octet string containing the encoded client request value.
   */
  @NotNull()
  private ASN1Sequence encode(final byte type)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(7);

    if (downstreamRequest != null)
    {
      elements.add(downstreamRequest.encode(TYPE_DOWNSTREAM_REQUEST));
    }

    if (downstreamClientAddress != null)
    {
      elements.add(new ASN1OctetString(TYPE_DOWNSTREAM_CLIENT_ADDRESS,
                                       downstreamClientAddress));
    }

    if (downstreamClientSecure != null)
    {
      elements.add(new ASN1Boolean(TYPE_DOWNSTREAM_CLIENT_SECURE,
                                   downstreamClientSecure));
    }

    if (clientIdentity != null)
    {
      elements.add(new ASN1OctetString(TYPE_CLIENT_IDENTITY, clientIdentity));
    }

    if (clientName != null)
    {
      elements.add(new ASN1OctetString(TYPE_CLIENT_NAME,  clientName));
    }

    if (clientSessionID != null)
    {
      elements.add(new ASN1OctetString(TYPE_CLIENT_SESSION_ID,
                                       clientSessionID));
    }

    if (clientRequestID != null)
    {
      elements.add(new ASN1OctetString(TYPE_CLIENT_REQUEST_ID,
                                       clientRequestID));
    }

    return new ASN1Sequence(type, elements);
  }



  /**
   * Decodes the provided ASN.1 sequence as an intermediate client request
   * value.
   *
   * @param  sequence  The sequence to be decoded as an intermediate client
   *                   request value.
   *
   * @return  The decoded intermediate client request value.
   *
   * @throws  LDAPException  If the provided sequence cannot be decoded as an
   *                         intermediate client request value.
   */
  @NotNull()
  public static IntermediateClientRequestValue decode(
                     @NotNull final ASN1Sequence sequence)
         throws LDAPException
  {
    Boolean                        downstreamClientSecure  = null;
    IntermediateClientRequestValue downstreamRequest       = null;
    String                         clientIdentity          = null;
    String                         downstreamClientAddress = null;
    String                         clientName              = null;
    String                         clientRequestID         = null;
    String                         clientSessionID         = null;

    for (final ASN1Element element : sequence.elements())
    {
      switch (element.getType())
      {
        case TYPE_DOWNSTREAM_REQUEST:
          try
          {
            final ASN1Sequence s = ASN1Sequence.decodeAsSequence(element);
            downstreamRequest = decode(s);
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ICREQ_CANNOT_DECODE_DOWNSTREAM_REQUEST.get(
                      le.getMessage()), le);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ICREQ_CANNOT_DECODE_DOWNSTREAM_REQUEST.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
          break;

        case TYPE_DOWNSTREAM_CLIENT_ADDRESS:
          downstreamClientAddress =
               ASN1OctetString.decodeAsOctetString(element).stringValue();
          break;

        case TYPE_DOWNSTREAM_CLIENT_SECURE:
          try
          {
            downstreamClientSecure =
                 ASN1Boolean.decodeAsBoolean(element).booleanValue();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ICREQ_CANNOT_DECODE_DOWNSTREAM_SECURE.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
          break;

        case TYPE_CLIENT_IDENTITY:
          clientIdentity =
               ASN1OctetString.decodeAsOctetString(element).stringValue();
          break;

        case TYPE_CLIENT_NAME:
          clientName =
               ASN1OctetString.decodeAsOctetString(element).stringValue();
          break;

        case TYPE_CLIENT_SESSION_ID:
          clientSessionID =
               ASN1OctetString.decodeAsOctetString(element).stringValue();
          break;

        case TYPE_CLIENT_REQUEST_ID:
          clientRequestID =
               ASN1OctetString.decodeAsOctetString(element).stringValue();
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_ICREQ_INVALID_ELEMENT_TYPE.get(
                    StaticUtils.toHex(element.getType())));
      }
    }

    return new IntermediateClientRequestValue(downstreamRequest,
                                              downstreamClientAddress,
                                              downstreamClientSecure,
                                              clientIdentity, clientName,
                                              clientSessionID, clientRequestID);
  }



  /**
   * Generates a hash code for this intermediate client request value.
   *
   * @return  A hash code for this intermediate client request value.
   */
  @Override()
  public int hashCode()
  {
    int hashCode = 0;

    if (downstreamRequest != null)
    {
      hashCode += downstreamRequest.hashCode();
    }

    if (downstreamClientAddress != null)
    {
      hashCode += downstreamClientAddress.hashCode();
    }

    if (downstreamClientSecure != null)
    {
      hashCode += downstreamClientSecure.hashCode();
    }

    if (clientIdentity != null)
    {
      hashCode += clientIdentity.hashCode();
    }

    if (clientName != null)
    {
      hashCode += clientName.hashCode();
    }

    if (clientSessionID != null)
    {
      hashCode += clientSessionID.hashCode();
    }

    if (clientRequestID != null)
    {
      hashCode += clientRequestID.hashCode();
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this intermediate client
   * request value.  It will only be considered equal if the provided object is
   * also an intermediate client request value with all the same fields.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          intermediate client request value, or {@code false} if not.
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
    else if (! (o instanceof IntermediateClientRequestValue))
    {
      return false;
    }

    final IntermediateClientRequestValue v = (IntermediateClientRequestValue) o;

    if (downstreamRequest == null)
    {
      if (v.downstreamRequest != null)
      {
        return false;
      }
    }
    else
    {
      if (! downstreamRequest.equals(v.downstreamRequest))
      {
        return false;
      }
    }

    if (downstreamClientAddress == null)
    {
      if (v.downstreamClientAddress != null)
      {
        return false;
      }
    }
    else
    {
      if (! downstreamClientAddress.equals(v.downstreamClientAddress))
      {
        return false;
      }
    }

    if (downstreamClientSecure == null)
    {
      if (v.downstreamClientSecure != null)
      {
        return false;
      }
    }
    else
    {
      if (! downstreamClientSecure.equals(v.downstreamClientSecure))
      {
        return false;
      }
    }

    if (clientIdentity == null)
    {
      if (v.clientIdentity != null)
      {
        return false;
      }
    }
    else
    {
      if (! clientIdentity.equals(v.clientIdentity))
      {
        return false;
      }
    }

    if (clientName == null)
    {
      if (v.clientName != null)
      {
        return false;
      }
    }
    else
    {
      if (! clientName.equals(v.clientName))
      {
        return false;
      }
    }

    if (clientSessionID == null)
    {
      if (v.clientSessionID != null)
      {
        return false;
      }
    }
    else
    {
      if (! clientSessionID.equals(v.clientSessionID))
      {
        return false;
      }
    }

    if (clientRequestID == null)
    {
      if (v.clientRequestID != null)
      {
        return false;
      }
    }
    else
    {
      if (! clientRequestID.equals(v.clientRequestID))
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Retrieves a string representation of this intermediate client request
   * value.
   *
   * @return  A string representation of this intermediate client request value.
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
   * Appends a string representation of this intermediate client request value
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information is to be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("IntermediateClientRequestValue(");

    boolean added = false;
    if (downstreamRequest != null)
    {
      buffer.append("downstreamRequest=");
      downstreamRequest.toString(buffer);
      added = true;
    }

    if (clientIdentity != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("clientIdentity='");
      buffer.append(clientIdentity);
      buffer.append('\'');
    }

    if (downstreamClientAddress != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("downstreamClientAddress='");
      buffer.append(downstreamClientAddress);
      buffer.append('\'');
    }

    if (downstreamClientSecure != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("downstreamClientSecure='");
      buffer.append(downstreamClientSecure);
      buffer.append('\'');
    }

    if (clientName != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("clientName='");
      buffer.append(clientName);
      buffer.append('\'');
    }

    if (clientSessionID != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("clientSessionID='");
      buffer.append(clientSessionID);
      buffer.append('\'');
    }

    if (clientRequestID != null)
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append("clientRequestID='");
      buffer.append(clientRequestID);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
