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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.NotMutable;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an implementation of an LDAP search result reference
 * protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultReferenceProtocolOp
       implements ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1526778443581862609L;



  // The list of referral URLs for this search result reference.
  private final List<String> referralURLs;



  /**
   * Creates a new search result reference protocol op with the provided
   * information.
   *
   * @param  referralURLs  The list of referral URLs for this search result
   *                       reference.
   */
  public SearchResultReferenceProtocolOp(final List<String> referralURLs)
  {
    this.referralURLs = Collections.unmodifiableList(referralURLs);
  }



  /**
   * Creates a new search result reference protocol op from the provided search
   * result reference.
   *
   * @param  reference  The search result reference to use to create this
   *                    protocol op.
   */
  public SearchResultReferenceProtocolOp(final SearchResultReference reference)
  {
    referralURLs = toList(reference.getReferralURLs());
  }



  /**
   * Creates a new search result reference protocol op read from the provided
   * ASN.1 stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the search
   *                 result reference protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         search result reference.
   */
  SearchResultReferenceProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ArrayList<String> refs = new ArrayList<String>(5);
      final ASN1StreamReaderSequence refSequence = reader.beginSequence();
      while (refSequence.hasMoreElements())
      {
        refs.add(reader.readString());
      }

      referralURLs = Collections.unmodifiableList(refs);
    }
    catch (final Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_REFERENCE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the list of referral URLs for this search result reference.
   *
   * @return  The list of referral URLs for this search result reference.
   */
  public List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> urlElements =
         new ArrayList<ASN1Element>(referralURLs.size());
    for (final String url : referralURLs)
    {
      urlElements.add(new ASN1OctetString(url));
    }

    return new ASN1Sequence(
         LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE,
         urlElements);
  }



  /**
   * Decodes the provided ASN.1 element as a search result reference protocol
   * op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded search result reference protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a search result reference protocol op.
   */
  public static SearchResultReferenceProtocolOp decodeProtocolOp(
                                                     final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] urlElements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final ArrayList<String> referralURLs =
           new ArrayList<String>(urlElements.length);
      for (final ASN1Element e : urlElements)
      {
        referralURLs.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
      }

      return new SearchResultReferenceProtocolOp(referralURLs);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_REFERENCE_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence = buffer.beginSequence(
         LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE);
    for (final String s : referralURLs)
    {
      buffer.addOctetString(s);
    }
    opSequence.end();
  }



  /**
   * Creates a search result reference from this protocol op.
   *
   * @param  controls  The set of controls to include in the search result
   *                   reference.  It may be empty or {@code null} if no
   *                   controls should be included.
   *
   * @return  The search result reference that was created.
   */
  public SearchResultReference toSearchResultReference(
                                    final Control... controls)
  {
    final String[] referralArray = new String[referralURLs.size()];
    referralURLs.toArray(referralArray);

    return new SearchResultReference(referralArray, controls);
  }



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
   */
  @Override()
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
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SearchResultReferenceProtocolOp(referralURLs={");

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

    buffer.append("})");
  }
}
