/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
import com.unboundid.util.NotMutable;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;



/**
 * This class provides an implementation of a delete response protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DeleteResponseProtocolOp
       extends GenericResponseProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7372719058693583245L;



  /**
   * Creates a new instance of this delete response protocol op with the
   * provided information.
   *
   * @param  resultCode         The result code for this response.
   * @param  matchedDN          The matched DN for this response, if available.
   * @param  diagnosticMessage  The diagnostic message for this response, if
   *                            any.
   * @param  referralURLs       The list of referral URLs for this response, if
   *                            any.
   */
  public DeleteResponseProtocolOp(final int resultCode, final String matchedDN,
                                final String diagnosticMessage,
                                final List<String> referralURLs)
  {
    super(LDAPMessage.PROTOCOL_OP_TYPE_DELETE_RESPONSE, resultCode, matchedDN,
          diagnosticMessage, referralURLs);
  }



  /**
   * Creates a new delete response protocol op from the provided LDAP result
   * object.
   *
   * @param  result  The LDAP result object to use to create this protocol op.
   */
  public DeleteResponseProtocolOp(final LDAPResult result)
  {
    super(LDAPMessage.PROTOCOL_OP_TYPE_DELETE_RESPONSE,
         result.getResultCode().intValue(), result.getMatchedDN(),
         result.getDiagnosticMessage(),
         StaticUtils.toList(result.getReferralURLs()));
  }



  /**
   * Creates a new delete response protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the delete
   *                 response protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         delete response.
   */
  DeleteResponseProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    super(reader);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(4);
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
           new ArrayList<ASN1Element>(referralURLs.size());
      for (final String r : referralURLs)
      {
        refElements.add(new ASN1OctetString(r));
      }
      elements.add(new ASN1Sequence(TYPE_REFERRALS, refElements));
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_DELETE_RESPONSE,
         elements);
  }



  /**
   * Decodes the provided ASN.1 element as a delete response protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded delete response protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a delete response protocol op.
   */
  public static DeleteResponseProtocolOp decodeProtocolOp(
                                              final ASN1Element element)
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
      if (md.length() > 0)
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
      if (dm.length() > 0)
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
        referralURLs = new ArrayList<String>(refElements.length);
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

      return new DeleteResponseProtocolOp(resultCode, matchedDN,
           diagnosticMessage, referralURLs);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DELETE_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }
}
