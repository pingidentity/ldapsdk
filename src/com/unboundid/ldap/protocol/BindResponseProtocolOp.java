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
package com.unboundid.ldap.protocol;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;



/**
 * This class provides an implementation of a bind response protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BindResponseProtocolOp
       implements ProtocolOp
{
  /**
   * The BER type for the server SASL credentials element.
   */
  public static final byte TYPE_SERVER_SASL_CREDENTIALS = (byte) 0x87;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7757619031268544913L;



  // The server SASL credentials for this bind response.
  @Nullable private final ASN1OctetString serverSASLCredentials;

  // The result code for this bind response.
  private final int resultCode;

  // The referral URLs for this bind response.
  @NotNull private final List<String> referralURLs;

  // The diagnostic message for this bind response.
  @Nullable private final String diagnosticMessage;

  // The matched DN for this bind response.
  @Nullable private final String matchedDN;



  /**
   * Creates a new instance of this bind response protocol op with the provided
   * information.
   *
   * @param  resultCode             The result code for this response.
   * @param  matchedDN              The matched DN for this response, if
   *                                available.
   * @param  diagnosticMessage      The diagnostic message for this response, if
   *                                any.
   * @param  referralURLs           The list of referral URLs for this response,
   *                                if any.
   * @param  serverSASLCredentials  The server SASL credentials for this
   *                                response, if available.
   */
  public BindResponseProtocolOp(final int resultCode,
              @Nullable final String matchedDN,
              @Nullable final String diagnosticMessage,
              @Nullable final List<String> referralURLs,
              @Nullable final ASN1OctetString serverSASLCredentials)
  {
    this.resultCode            = resultCode;
    this.matchedDN             = matchedDN;
    this.diagnosticMessage     = diagnosticMessage;

    if (referralURLs == null)
    {
      this.referralURLs = Collections.emptyList();
    }
    else
    {
      this.referralURLs = Collections.unmodifiableList(referralURLs);
    }

    if (serverSASLCredentials == null)
    {
      this.serverSASLCredentials = null;
    }
    else
    {
      this.serverSASLCredentials = new ASN1OctetString(
           TYPE_SERVER_SASL_CREDENTIALS, serverSASLCredentials.getValue());
    }
  }



  /**
   * Creates a new bind response protocol op from the provided bind result
   * object.
   *
   * @param  result  The LDAP result object to use to create this protocol op.
   */
  public BindResponseProtocolOp(@NotNull final LDAPResult result)
  {
    resultCode            = result.getResultCode().intValue();
    matchedDN             = result.getMatchedDN();
    diagnosticMessage     = result.getDiagnosticMessage();
    referralURLs          = StaticUtils.toList(result.getReferralURLs());

    if (result instanceof BindResult)
    {
      final BindResult br = (BindResult) result;
      serverSASLCredentials = br.getServerSASLCredentials();
    }
    else
    {
      serverSASLCredentials = null;
    }
  }



  /**
   * Creates a new bind response protocol op read from the provided ASN.1 stream
   * reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the bind
   *                 response.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         bind response.
   */
  BindResponseProtocolOp(@NotNull final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();
      resultCode = reader.readEnumerated();

      String s = reader.readString();
      Validator.ensureNotNull(s);
      if (s.isEmpty())
      {
        matchedDN = null;
      }
      else
      {
        matchedDN = s;
      }

      s = reader.readString();
      Validator.ensureNotNull(s);
      if (s.isEmpty())
      {
        diagnosticMessage = null;
      }
      else
      {
        diagnosticMessage = s;
      }

      ASN1OctetString creds = null;
      final ArrayList<String> refs = new ArrayList<>(1);
      while (opSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        if (type == GenericResponseProtocolOp.TYPE_REFERRALS)
        {
          final ASN1StreamReaderSequence refSequence = reader.beginSequence();
          while (refSequence.hasMoreElements())
          {
            refs.add(reader.readString());
          }
        }
        else if (type == TYPE_SERVER_SASL_CREDENTIALS)
        {
          creds = new ASN1OctetString(type, reader.readBytes());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_BIND_RESPONSE_INVALID_ELEMENT.get(StaticUtils.toHex(type)));
        }
      }

      referralURLs = Collections.unmodifiableList(refs);
      serverSASLCredentials = creds;
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
           ERR_BIND_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the result code for this bind response.
   *
   * @return  The result code for this bind response.
   */
  public int getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the matched DN for this bind response, if any.
   *
   * @return  The matched DN for this bind response, or {@code null} if there is
   *          no matched DN.
   */
  @Nullable()
  public String getMatchedDN()
  {
    return matchedDN;
  }



  /**
   * Retrieves the diagnostic message for this bind response, if any.
   *
   * @return  The diagnostic message for this bind response, or {@code null} if
   *          there is no diagnostic message.
   */
  @Nullable()
  public String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }



  /**
   * Retrieves the list of referral URLs for this bind response.
   *
   * @return  The list of referral URLs for this bind response, or an empty list
   *          if there are no referral URLs.
   */
  @NotNull()
  public List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * Retrieves the server SASL credentials for this bind response, if any.
   *
   * @return  The server SASL credentials for this bind response, or
   *          {@code null} if there are no server SASL credentials.
   */
  @Nullable()
  public ASN1OctetString getServerSASLCredentials()
  {
    return serverSASLCredentials;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(5);
    elements.add(new ASN1Enumerated(getResultCode()));

    final String mDN = getMatchedDN();
    if (mDN == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(mDN));
    }

    final String dm = getDiagnosticMessage();
    if (dm == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(dm));
    }

    final List<String> refs = getReferralURLs();
    if (! refs.isEmpty())
    {
      final ArrayList<ASN1Element> refElements = new ArrayList<>(refs.size());
      for (final String r : refs)
      {
        refElements.add(new ASN1OctetString(r));
      }
      elements.add(new ASN1Sequence(GenericResponseProtocolOp.TYPE_REFERRALS,
           refElements));
    }

    if (serverSASLCredentials != null)
    {
      elements.add(serverSASLCredentials);
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE,
         elements);
  }



  /**
   * Decodes the provided ASN.1 element as a bind response protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded bind response protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a bind response protocol op.
   */
  @NotNull()
  public static BindResponseProtocolOp decodeProtocolOp(
                                            @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final int resultCode =
           ASN1Enumerated.decodeAsEnumerated(elements[0]).intValue();

      final String matchedDN;
      final String md =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
      if (! md.isEmpty())
      {
        matchedDN = md;
      }
      else
      {
        matchedDN = null;
      }

      final String diagnosticMessage;
      final String dm =
           ASN1OctetString.decodeAsOctetString(elements[2]).stringValue();
      if (! dm.isEmpty())
      {
        diagnosticMessage = dm;
      }
      else
      {
        diagnosticMessage = null;
      }

      ASN1OctetString serverSASLCredentials = null;
      List<String> referralURLs = null;
      if (elements.length > 3)
      {
        for (int i=3; i < elements.length; i++)
        {
          switch (elements[i].getType())
          {
            case GenericResponseProtocolOp.TYPE_REFERRALS:
              final ASN1Element[] refElements =
                   ASN1Sequence.decodeAsSequence(elements[3]).elements();
              referralURLs = new ArrayList<>(refElements.length);
              for (final ASN1Element e : refElements)
              {
                referralURLs.add(
                     ASN1OctetString.decodeAsOctetString(e).stringValue());
              }
              break;

            case TYPE_SERVER_SASL_CREDENTIALS:
              serverSASLCredentials =
                   ASN1OctetString.decodeAsOctetString(elements[i]);
              break;

            default:
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_BIND_RESPONSE_INVALID_ELEMENT.get(
                        StaticUtils.toHex(elements[i].getType())));
          }
        }
      }

      return new BindResponseProtocolOp(resultCode, matchedDN,
           diagnosticMessage, referralURLs, serverSASLCredentials);
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
           ERR_BIND_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE);
    buffer.addEnumerated(resultCode);
    buffer.addOctetString(matchedDN);
    buffer.addOctetString(diagnosticMessage);

    if (! referralURLs.isEmpty())
    {
      final ASN1BufferSequence refSequence =
           buffer.beginSequence(GenericResponseProtocolOp.TYPE_REFERRALS);
      for (final String s : referralURLs)
      {
        buffer.addOctetString(s);
      }
      refSequence.end();
    }

    if (serverSASLCredentials != null)
    {
      buffer.addElement(serverSASLCredentials);
    }

    opSequence.end();
  }



  /**
   * Creates a new LDAP result object from this response protocol op.
   *
   * @param  controls  The set of controls to include in the LDAP result.  It
   *                   may be empty or {@code null} if no controls should be
   *                   included.
   *
   * @return  The LDAP result that was created.
   */
  @NotNull()
  public BindResult toBindResult(@Nullable final Control... controls)
  {
    final String[] refs;
    if (referralURLs.isEmpty())
    {
      refs = StaticUtils.NO_STRINGS;
    }
    else
    {
      refs = new String[referralURLs.size()];
      referralURLs.toArray(refs);
    }

    return new BindResult(-1, ResultCode.valueOf(resultCode), diagnosticMessage,
         matchedDN, refs, controls, serverSASLCredentials);
  }



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
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
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("BindResponseProtocolOp(resultCode=");
    buffer.append(resultCode);

    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    if (! referralURLs.isEmpty())
    {
      buffer.append(", referralURLs={");

      final Iterator<String> iterator = referralURLs.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');
        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
    }
    buffer.append(')');
  }
}
