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
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
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

import static com.unboundid.ldap.protocol.ProtocolMessages.*;



/**
 * This class provides an implementation of a modify response protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ModifyResponseProtocolOp
       extends GenericResponseProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6850364658234891786L;



  /**
   * Creates a new instance of this modify response protocol op with the
   * provided information.
   *
   * @param  resultCode         The result code for this response.
   * @param  matchedDN          The matched DN for this response, if available.
   * @param  diagnosticMessage  The diagnostic message for this response, if
   *                            any.
   * @param  referralURLs       The list of referral URLs for this response, if
   *                            any.
   */
  public ModifyResponseProtocolOp(final int resultCode,
                                  @Nullable final String matchedDN,
                                  @Nullable final String diagnosticMessage,
                                  @Nullable final List<String> referralURLs)
  {
    super(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_RESPONSE, resultCode, matchedDN,
          diagnosticMessage, referralURLs);
  }



  /**
   * Creates a new modify response protocol op from the provided LDAP result
   * object.
   *
   * @param  result  The LDAP result object to use to create this protocol op.
   */
  public ModifyResponseProtocolOp(@NotNull final LDAPResult result)
  {
    super(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_RESPONSE,
         result.getResultCode().intValue(), result.getMatchedDN(),
         result.getDiagnosticMessage(),
         StaticUtils.toList(result.getReferralURLs()));
  }



  /**
   * Creates a new modify response protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the modify
   *                 response protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         modify response.
   */
  ModifyResponseProtocolOp(@NotNull final ASN1StreamReader reader)
       throws LDAPException
  {
    super(reader);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(4);
    elements.add(new ASN1Enumerated(getResultCode()));

    final String matchedDN = getMatchedDN();
    if (matchedDN == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(matchedDN));
    }

    final String diagnosticMessage = getDiagnosticMessage();
    if (diagnosticMessage == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(diagnosticMessage));
    }

    final List<String> referralURLs = getReferralURLs();
    if (! referralURLs.isEmpty())
    {
      final ArrayList<ASN1Element> refElements =
           new ArrayList<>(referralURLs.size());
      for (final String r : referralURLs)
      {
        refElements.add(new ASN1OctetString(r));
      }
      elements.add(new ASN1Sequence(TYPE_REFERRALS, refElements));
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_RESPONSE,
         elements);
  }



  /**
   * Decodes the provided ASN.1 element as a modify response protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded modify response protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a modify response protocol op.
   */
  @NotNull()
  public static ModifyResponseProtocolOp decodeProtocolOp(
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

      final List<String> referralURLs;
      if (elements.length == 4)
      {
        final ASN1Element[] refElements =
             ASN1Sequence.decodeAsSequence(elements[3]).elements();
        referralURLs = new ArrayList<>(refElements.length);
        for (final ASN1Element e : refElements)
        {
          referralURLs.add(
               ASN1OctetString.decodeAsOctetString(e).stringValue());
        }
      }
      else
      {
        referralURLs = null;
      }

      return new ModifyResponseProtocolOp(resultCode, matchedDN,
           diagnosticMessage, referralURLs);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MODIFY_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }
}
