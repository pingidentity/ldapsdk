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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a control that may be included in a
 * search result entry in response to a join request control to provide a set of
 * entries related to the search result entry.    See the class-level
 * documentation for the {@link JoinRequestControl} class for additional
 * information and an example demonstrating its use.
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
 * The value of the join result control is encoded as follows:
 * <PRE>
 *   JoinResult ::= SEQUENCE {
 *        COMPONENTS OF LDAPResult,
 *        entries     [4] SEQUENCE OF JoinedEntry }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JoinResultControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.9) for the join result control.
   */
  @NotNull public static final String JOIN_RESULT_OID =
       "1.3.6.1.4.1.30221.2.5.9";



  /**
   * The BER type for the referral URLs element.
   */
  private static final byte TYPE_REFERRAL_URLS = (byte) 0xA3;



  /**
   * The BER type for the join results element.
   */
  private static final byte TYPE_JOIN_RESULTS = (byte) 0xA4;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 681831114773253358L;



  // The set of entries which have been joined with the associated search result
  // entry.
  @NotNull private final List<JoinedEntry> joinResults;

  // The set of referral URLs for this join result.
  @NotNull private final List<String> referralURLs;

  // The result code for this join result.
  @NotNull private final ResultCode resultCode;

  // The diagnostic message for this join result.
  @Nullable private final String diagnosticMessage;

  // The matched DN for this join result.
  @Nullable private final String matchedDN;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  JoinResultControl()
  {
    resultCode        = null;
    diagnosticMessage = null;
    matchedDN         = null;
    referralURLs      = null;
    joinResults       = null;
  }



  /**
   * Creates a new join result control indicating a successful join.
   *
   * @param  joinResults  The set of entries that have been joined with the
   *                      associated search result entry.  It may be
   *                      {@code null} or empty if no entries were joined with
   *                      the search result entry.
   */
  public JoinResultControl(@Nullable final List<JoinedEntry> joinResults)
  {
    this(ResultCode.SUCCESS, null, null, null, joinResults);
  }



  /**
   * Creates a new join result control with the provided information.
   *
   * @param  resultCode         The result code for the join processing.  It
   *                            must not be {@code null}.
   * @param  diagnosticMessage  A message with additional information about the
   *                            result of the join processing.  It may be
   *                            {@code null} if no message is needed.
   * @param  matchedDN          The matched DN for the join processing.  It may
   *                            be {@code null} if no matched DN is needed.
   * @param  referralURLs       The set of referral URLs for any referrals
   *                            encountered while processing the join.  It may
   *                            be {@code null} or empty if no referral URLs
   *                            are needed.
   * @param  joinResults        The set of entries that have been joined with
   *                            associated search result entry.    It may be
   *                            {@code null} or empty if no entries were joined
   *                            with the search result entry.
   */
  public JoinResultControl(@NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final List<String> referralURLs,
              @Nullable final List<JoinedEntry> joinResults)
  {
    super(JOIN_RESULT_OID, false,
          encodeValue(resultCode, diagnosticMessage, matchedDN, referralURLs,
                      joinResults));

    this.resultCode        = resultCode;
    this.diagnosticMessage = diagnosticMessage;
    this.matchedDN         = matchedDN;

    if (referralURLs == null)
    {
      this.referralURLs = Collections.emptyList();
    }
    else
    {
      this.referralURLs = Collections.unmodifiableList(referralURLs);
    }

    if (joinResults == null)
    {
      this.joinResults = Collections.emptyList();
    }
    else
    {
      this.joinResults = Collections.unmodifiableList(joinResults);
    }
  }



  /**
   * Creates a new join result control with the provided information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         account usable response control.
   */
  public JoinResultControl(@NotNull final String oid, final boolean isCritical,
                           @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_RESULT_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();

      resultCode = ResultCode.valueOf(
           ASN1Enumerated.decodeAsEnumerated(elements[0]).intValue());

      final String matchedDNStr =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
      if (matchedDNStr.isEmpty())
      {
        matchedDN = null;
      }
      else
      {
        matchedDN = matchedDNStr;
      }

      final String diagnosticMessageStr =
           ASN1OctetString.decodeAsOctetString(elements[2]).stringValue();
      if (diagnosticMessageStr.isEmpty())
      {
        diagnosticMessage = null;
      }
      else
      {
        diagnosticMessage = diagnosticMessageStr;
      }

      final ArrayList<String>      refs    = new ArrayList<>(5);
      final ArrayList<JoinedEntry> entries = new ArrayList<>(20);
      for (int i=3; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_REFERRAL_URLS:
            final ASN1Element[] refElements =
                 ASN1Sequence.decodeAsSequence(elements[i]).elements();
            for (final ASN1Element e : refElements)
            {
              refs.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
            }
            break;

          case TYPE_JOIN_RESULTS:
            final ASN1Element[] entryElements =
                 ASN1Sequence.decodeAsSequence(elements[i]).elements();
            for (final ASN1Element e : entryElements)
            {
              entries.add(JoinedEntry.decode(e));
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_JOIN_RESULT_INVALID_ELEMENT_TYPE.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }

      referralURLs = Collections.unmodifiableList(refs);
      joinResults  = Collections.unmodifiableList(entries);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOIN_RESULT_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information as appropriate for use as the value of
   * this control.
   *
   * @param  resultCode         The result code for the join processing.  It
   *                            must not be {@code null}.
   * @param  diagnosticMessage  A message with additional information about the
   *                            result of the join processing.  It may be
   *                            {@code null} if no message is needed.
   * @param  matchedDN          The matched DN for the join processing.  It may
   *                            be {@code null} if no matched DN is needed.
   * @param  referralURLs       The set of referral URLs for any referrals
   *                            encountered while processing the join.  It may
   *                            be {@code null} or empty if no referral URLs
   *                            are needed.
   * @param  joinResults        The set of entries that have been joined with
   *                            associated search result entry.    It may be
   *                            {@code null} or empty if no entries were joined
   *                            with the search result entry.
   *
   * @return  An ASN.1 element containing an encoded representation of the
   *          value for this control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final ResultCode resultCode,
                      @Nullable final String diagnosticMessage,
                      @Nullable final String matchedDN,
                      @Nullable final List<String> referralURLs,
                      @Nullable final List<JoinedEntry> joinResults)
  {
    Validator.ensureNotNull(resultCode);

    final ArrayList<ASN1Element> elements = new ArrayList<>(5);
    elements.add(new ASN1Enumerated(resultCode.intValue()));

    if (matchedDN == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(matchedDN));
    }

    if (diagnosticMessage == null)
    {
      elements.add(new ASN1OctetString());
    }
    else
    {
      elements.add(new ASN1OctetString(diagnosticMessage));
    }

    if ((referralURLs != null) && (! referralURLs.isEmpty()))
    {
      final ArrayList<ASN1Element> refElements =
           new ArrayList<>(referralURLs.size());
      for (final String s : referralURLs)
      {
        refElements.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_REFERRAL_URLS, refElements));
    }

    if ((joinResults == null) || joinResults.isEmpty())
    {
      elements.add(new ASN1Sequence(TYPE_JOIN_RESULTS));
    }
    else
    {
      final ArrayList<ASN1Element> entryElements =
           new ArrayList<>(joinResults.size());
      for (final JoinedEntry e : joinResults)
      {
        entryElements.add(e.encode());
      }
      elements.add(new ASN1Sequence(TYPE_JOIN_RESULTS, entryElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the result code for this join result.
   *
   * @return  The result code for this join result.
   */
  @NotNull()
  public ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the diagnostic message for this join result.
   *
   * @return  The diagnostic message for this join result, or {@code null} if
   *          there is no diagnostic message.
   */
  @Nullable()
  public String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }



  /**
   * Retrieves the matched DN for this join result.
   *
   * @return  The matched DN for this join result, or {@code null} if there is
   *          no matched DN.
   */
  @Nullable()
  public String getMatchedDN()
  {
    return matchedDN;
  }



  /**
   * Retrieves the set of referral URLs for this join result.
   *
   * @return  The set of referral URLs for this join result, or an empty list
   *          if there are no referral URLs.
   */
  @NotNull()
  public List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * Retrieves the set of entries that have been joined with the associated
   * search result entry.
   *
   * @return  The set of entries that have been joined with the associated
   *          search result entry.
   */
  @NotNull()
  public List<JoinedEntry> getJoinResults()
  {
    return joinResults;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JoinResultControl decodeControl(@NotNull final String oid,
                                         final boolean isCritical,
                                         @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new JoinResultControl(oid, isCritical, value);
  }



  /**
   * Extracts a join result control from the provided search result entry.
   *
   * @param  entry  The search result entry from which to retrieve the join
   *                result control.
   *
   * @return  The join result control contained in the provided search result
   *          entry, or {@code null} if the entry did not contain a join result
   *          control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the join result control contained in the
   *                         provided search result entry.
   */
  @Nullable()
  public static JoinResultControl get(@NotNull final SearchResultEntry entry)
         throws LDAPException
  {
    final Control c = entry.getControl(JOIN_RESULT_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof JoinResultControl)
    {
      return (JoinResultControl) c;
    }
    else
    {
      return new JoinResultControl(c.getOID(), c.isCritical(), c.getValue());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_JOIN_RESULT.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("JoinResultControl(resultCode='");
    buffer.append(resultCode.getName());
    buffer.append("', diagnosticMessage='");

    if (diagnosticMessage != null)
    {
      buffer.append(diagnosticMessage);
    }

    buffer.append("', matchedDN='");
    if (matchedDN != null)
    {
      buffer.append(matchedDN);
    }

    buffer.append("', referralURLs={");
    final Iterator<String> refIterator = referralURLs.iterator();
    while (refIterator.hasNext())
    {
      buffer.append(refIterator.next());
      if (refIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, joinResults={");
    final Iterator<JoinedEntry> entryIterator = joinResults.iterator();
    while (entryIterator.hasNext())
    {
      entryIterator.next().toString(buffer);
      if (entryIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
