/*
 * Copyright 2014-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2023 Ping Identity Corporation
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
 * Copyright (C) 2014-2023 Ping Identity Corporation
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
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a response control that may be used to provide
 * information about the number of entries that match a given set of search
 * criteria.  The control will be included in the search result done message
 * for any successful search operation in which the request contained a matching
 * entry count request control.
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
 * The matching entry count response control has an OID of
 * "1.3.6.1.4.1.30221.2.5.37", a criticality of false, and a value with the
 * following encoding:
 * <PRE>
 *   MatchingEntryCountResponse ::= SEQUENCE {
 *        entryCount               CHOICE {
 *             examinedCount            [0] INTEGER,
 *             unexaminedCount          [1] INTEGER,
 *             upperBound               [2] INTEGER,
 *             unknown                  [3] NULL,
 *             ... }
 *        debugInfo                [0] SEQUENCE OF OCTET STRING OPTIONAL,
 *        searchIndexed            [1] BOOLEAN DEFAULT TRUE,
 *        shortCircuited           [2] BOOLEAN OPTIONAL,
 *        fullyIndexed             [3] BOOLEAN OPTIONAL,
 *        candidatesAreInScope     [4] BOOLEAN OPTIONAL,
 *        remainingFilter          [5] Filter OPTIONAL,
 *        ... }
 * </PRE>
 *
 * @see  MatchingEntryCountRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MatchingEntryCountResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.37) for the matching entry count response
   * control.
   */
  @NotNull public static final String MATCHING_ENTRY_COUNT_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.37";



  /**
   * The BER type for the element used to hold the list of debug messages.
   */
  private static final byte TYPE_DEBUG_INFO = (byte) 0xA0;



  /**
   * The BER type for the element used to indicate whether the search criteria
   * is at least partially indexed.
   */
  private static final byte TYPE_SEARCH_INDEXED = (byte) 0x81;



  /**
   * The BER type for the element used to indicate whether the server
   * short-circuited during candidate set processing before evaluating all
   * elements of the search criteria (the filter and scope).
   */
  private static final byte TYPE_SHORT_CIRCUITED = (byte) 0x82;



  /**
   * The BER type for the element used to indicate whether the search criteria
   * is fully indexed.
   */
  private static final byte TYPE_FULLY_INDEXED = (byte) 0x83;



  /**
   * The BER type for the element used to indicate whether all the identified
   * candidate entries are within the scope of the search.
   */
  private static final byte TYPE_CANDIDATES_ARE_IN_SCOPE = (byte) 0x84;



  /**
   * The BER type for the element used to provide the remaining filter for the
   * search operation, which is the portion of the filter that was determined
   * to be unindexed, or that was unevaluated if processing short-circuited in
   * the course of building the candidate set.
   */
  private static final byte TYPE_REMAINING_FILTER = (byte) 0xA5;



  /**
   * The name of the field used to hold the candidates are in scope flag in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_CANDIDATES_ARE_IN_SCOPE =
       "candidates-are-in-scope";



  /**
   * The name of the field used to hold the count type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_COUNT_TYPE = "count-type";



  /**
   * The name of the field used to hold the count value in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_COUNT_VALUE = "count-value";



  /**
   * The name of the field used to hold the debug info in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_DEBUG_INFO = "debug-info";



  /**
   * The name of the field used to hold the fully indexed flag in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_FULLY_INDEXED =
       "fully-indexed";



  /**
   * The name of the field used to hold the remaining filter in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_REMAINING_FILTER =
       "remaining-filter";



  /**
   * The name of the field used to hold the search indexed flag in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SEARCH_INDEXED =
       "search-indexed";



  /**
   * The name of the field used to hold the short-circuited flag in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SHORT_CIRCUITED =
       "short-circuited";



  /**
   * The result-type value that will be used for an examined count in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_COUNT_TYPE_EXAMINED_COUNT =
       "examined-count";



  /**
   * The result-type value that will be used for an unexamined count in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_COUNT_TYPE_UNEXAMINED_COUNT =
       "unexamined-count";



  /**
   * The result-type value that will be used for an unknown count in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_COUNT_TYPE_UNKNOWN = "unknown";



  /**
   * The result-type value that will be used for an upper-bound count in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_COUNT_TYPE_UPPER_BOUND =
       "upper-bound";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7808452580964236458L;



  // Indicates whether the search criteria is considered at least partially
  // indexed by the server.
  private final boolean searchIndexed;

  // Indicates whether all the identified candidate entries are within the scope
  // of the search.
  @Nullable private final Boolean candidatesAreInScope;

  // Indicates whether the search criteria is considered fully indexed.
  @Nullable private final Boolean fullyIndexed;

  // Indicates whether the server short-circuited during candidate set
  // processing before evaluating all elements of the search criteria (the
  // filter and scope).
  @Nullable private final Boolean shortCircuited;

  // The portion of the filter that was either identified as unindexed or that
  // was not evaluated in the course of building the candidate set.
  @Nullable private final Filter remainingFilter;

  // The count value for this matching entry count response control.
  private final int countValue;

  // A list of messages providing debug information about the processing
  // performed by the server.
  @NotNull private final List<String> debugInfo;

  // The count type for this matching entry count response control.
  @NotNull private final MatchingEntryCountType countType;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  MatchingEntryCountResponseControl()
  {
    searchIndexed = false;
    candidatesAreInScope = null;
    fullyIndexed = null;
    shortCircuited = null;
    remainingFilter = null;
    countValue = -1;
    countType = null;
    debugInfo = null;
  }



  /**
   * Creates a new matching entry count response control with the provided
   * information.
   *
   * @param  countType             The matching entry count type.  It must not
   *                               be {@code null}.
   * @param  countValue            The matching entry count value.  It must be
   *                               greater than or equal to zero for a count
   *                               type of either {@code EXAMINED_COUNT} or
   *                               {@code UNEXAMINED_COUNT}.  It must be greater
   *                               than zero for a count type of
   *                               {@code UPPER_BOUND}.  It must be -1 for a
   *                               count type of {@code UNKNOWN}.
   * @param  searchIndexed         Indicates whether the search criteria is
   *                               considered at least partially indexed and
   *                               could be processed more efficiently than
   *                               examining all entries with a full database
   *                               scan.
   * @param  shortCircuited        Indicates whether the server short-circuited
   *                               during candidate set processing before
   *                               evaluating all elements of the search
   *                               criteria (the filter and scope).  This may be
   *                               {@code null} if it is not available (e.g.,
   *                               because extended response data was not
   *                               requested).
   * @param  fullyIndexed          Indicates whether the search is considered
   *                               fully indexed.  Note that this may be
   *                               {@code false} even if the filter is actually
   *                               fully indexed if server index processing
   *                               short-circuited before evaluating all
   *                               components of the filter.  To avoid this,
   *                               issue the request control with both fast and
   *                               slow short-circuit thresholds set to zero.
   *                               This may be {@code null} if this is not
   *                               available (e.g., because extended response
   *                               data was not requested).
   * @param  candidatesAreInScope  Indicates whether all the identified
   *                               candidate entries are within the scope of
   *                               the search.  It may be {@code null} if this
   *                               is not available (e.g., because extended
   *                               response data was not requested).
   * @param  remainingFilter       The portion of the filter that was either
   *                               identified as unindexed or that was not
   *                               evaluated because processing short-circuited
   *                               in the course of building the candidate set.
   *                               It may be {@code null} if there is no
   *                               remaining filter or if this information is
   *                               not available (e.g., because extended
   *                               response data was not requested).
   * @param  debugInfo             An optional list of messages providing debug
   *                               information about the processing performed by
   *                               the server.  It may be {@code null} or empty
   *                               if no debug messages should be included.
   */
  private MatchingEntryCountResponseControl(
               @NotNull final MatchingEntryCountType countType,
               final int countValue,
               final boolean searchIndexed,
               @Nullable final Boolean shortCircuited,
               @Nullable final Boolean fullyIndexed,
               @Nullable final Boolean candidatesAreInScope,
               @Nullable final Filter remainingFilter,
               @Nullable final Collection<String> debugInfo)
  {
    super(MATCHING_ENTRY_COUNT_RESPONSE_OID, false,
         encodeValue(countType, countValue, searchIndexed, shortCircuited,
              fullyIndexed, candidatesAreInScope, remainingFilter, debugInfo));

    this.countType = countType;
    this.countValue = countValue;
    this.searchIndexed = searchIndexed;
    this.shortCircuited = shortCircuited;
    this.fullyIndexed = fullyIndexed;
    this.candidatesAreInScope = candidatesAreInScope;
    this.remainingFilter = remainingFilter;

    if (debugInfo == null)
    {
      this.debugInfo = Collections.emptyList();
    }
    else
    {
      this.debugInfo =
           Collections.unmodifiableList(new ArrayList<>(debugInfo));
    }
  }



  /**
   * Creates a new matching entry count response control decoded from the given
   * generic control contents.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.
   *
   * @throws LDAPException  If a problem occurs while attempting to decode the
   *                        generic control as a matching entry count response
   *                        control.
   */
  public MatchingEntryCountResponseControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MATCHING_ENTRY_COUNT_RESPONSE_MISSING_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      countType = MatchingEntryCountType.valueOf(elements[0].getType());
      if (countType == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MATCHING_ENTRY_COUNT_RESPONSE_INVALID_COUNT_TYPE.get(
                  StaticUtils.toHex(elements[0].getType())));
      }

      switch (countType)
      {
        case EXAMINED_COUNT:
        case UNEXAMINED_COUNT:
          countValue = ASN1Integer.decodeAsInteger(elements[0]).intValue();
          if (countValue < 0)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_MATCHING_ENTRY_COUNT_RESPONSE_NEGATIVE_EXACT_COUNT.get());
          }
          break;

        case UPPER_BOUND:
          countValue = ASN1Integer.decodeAsInteger(elements[0]).intValue();
          if (countValue <= 0)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_MATCHING_ENTRY_COUNT_RESPONSE_NON_POSITIVE_UPPER_BOUND.
                      get());
          }
          break;

        case UNKNOWN:
        default:
          countValue = -1;
          break;
      }

      boolean decodedSearchIndexed =
           (countType != MatchingEntryCountType.UNKNOWN);
      Boolean decodedFullyIndexed = null;
      Boolean decodedCandidatesAreInScope = null;
      Boolean decodedShortCircuited = null;
      Filter decodedRemainingFilter = null;
      List<String> debugMessages = Collections.emptyList();
      for (int i=1; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_DEBUG_INFO:
            final ASN1Element[] debugElements =
                 ASN1Sequence.decodeAsSequence(elements[i]).elements();
            debugMessages = new ArrayList<>(debugElements.length);
            for (final ASN1Element e : debugElements)
            {
              debugMessages.add(
                   ASN1OctetString.decodeAsOctetString(e).stringValue());
            }
            break;

          case TYPE_SEARCH_INDEXED:
            decodedSearchIndexed =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_SHORT_CIRCUITED:
            decodedShortCircuited =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_FULLY_INDEXED:
            decodedFullyIndexed =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_CANDIDATES_ARE_IN_SCOPE:
            decodedCandidatesAreInScope =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_REMAINING_FILTER:
            final ASN1Element filterElement =
                 ASN1Element.decode(elements[i].getValue());
            decodedRemainingFilter = Filter.decode(filterElement);
            break;
        }
      }

      searchIndexed = decodedSearchIndexed;
      shortCircuited = decodedShortCircuited;
      fullyIndexed = decodedFullyIndexed;
      candidatesAreInScope = decodedCandidatesAreInScope;
      remainingFilter = decodedRemainingFilter;
      debugInfo = Collections.unmodifiableList(debugMessages);
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
           ERR_GET_BACKEND_SET_ID_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new matching entry count response control for the case in which
   * the exact number of matching entries is known.
   *
   * @param  count      The exact number of entries matching the associated
   *                    search criteria.  It must be greater than or equal to
   *                    zero.
   * @param  examined   Indicates whether the server examined the entries to
   *                    exclude those entries that would not be returned to the
   *                    client in a normal search with the same criteria.
   * @param  debugInfo  An optional list of messages providing debug information
   *                    about the processing performed by the server.  It may be
   *                    {@code null} or empty if no debug messages should be
   *                    included.
   *
   * @return  The matching entry count response control that was created.
   */
  @NotNull()
  public static MatchingEntryCountResponseControl createExactCountResponse(
                     final int count, final boolean examined,
                     @Nullable final Collection<String> debugInfo)
  {
    return createExactCountResponse(count, examined, true, debugInfo);
  }



  /**
   * Creates a new matching entry count response control for the case in which
   * the exact number of matching entries is known.
   *
   * @param  count          The exact number of entries matching the associated
   *                        search criteria.  It must be greater than or equal
   *                        to zero.
   * @param  examined       Indicates whether the server examined the entries to
   *                        exclude those entries that would not be returned to
   *                        the client in a normal search with the same
   *                        criteria.
   * @param  searchIndexed  Indicates whether the search criteria is considered
   *                        at least partially indexed and could be processed
   *                        more efficiently than examining all entries with a
   *                        full database scan.
   * @param  debugInfo      An optional list of messages providing debug
   *                        information about the processing performed by the
   *                        server.  It may be {@code null} or empty if no debug
   *                        messages should be included.
   *
   * @return  The matching entry count response control that was created.
   */
  @NotNull()
  public static MatchingEntryCountResponseControl createExactCountResponse(
                     final int count, final boolean examined,
                     final boolean searchIndexed,
                     @Nullable final Collection<String> debugInfo)
  {
    return createExactCountResponse(count, examined, searchIndexed, null, null,
         null, null, debugInfo);
  }



  /**
   * Creates a new matching entry count response control for the case in which
   * the exact number of matching entries is known.
   *
   * @param  count                 The exact number of entries matching the
   *                               associated search criteria.  It must be
   *                               greater than or equal to zero.
   * @param  examined              Indicates whether the server examined the
   *                               entries to exclude those entries that would
   *                               not be returned to the client in a normal
   *                               search with the same criteria.
   * @param  searchIndexed         Indicates whether the search criteria is
   *                               considered at least partially indexed and
   *                               could be processed more efficiently than
   *                               examining all entries with a full database
   *                               scan.
   * @param  shortCircuited        Indicates whether the server short-circuited
   *                               during candidate set processing before
   *                               evaluating all elements of the search
   *                               criteria (the filter and scope).  This may be
   *                               {@code null} if it is not available (e.g.,
   *                               because extended response data was not
   *                               requested).
   * @param  fullyIndexed          Indicates whether the search is considered
   *                               fully indexed.  Note that this may be
   *                               {@code false} even if the filter is actually
   *                               fully indexed if server index processing
   *                               short-circuited before evaluating all
   *                               components of the filter.  To avoid this,
   *                               issue the request control with both fast and
   *                               slow short-circuit thresholds set to zero.
   *                               This may be {@code null} if this is not
   *                               available (e.g., because extended response
   *                               data was not requested).
   * @param  candidatesAreInScope  Indicates whether all the identified
   *                               candidate entries are within the scope of
   *                               the search.  It may be {@code null} if this
   *                               is not available (e.g., because extended
   *                               response data was not requested).
   * @param  remainingFilter       The portion of the filter that was either
   *                               identified as unindexed or that was not
   *                               evaluated because processing short-circuited
   *                               in the course of building the candidate set.
   *                               It may be {@code null} if there is no
   *                               remaining filter or if this information is
   *                               not available (e.g., because extended
   *                               response data was not requested).
   * @param  debugInfo             An optional list of messages providing debug
   *                               information about the processing performed by
   *                               the server.  It may be {@code null} or empty
   *                               if no debug messages should be included.
   *
   * @return  The matching entry count response control that was created.
   */
  @NotNull()
  public static MatchingEntryCountResponseControl createExactCountResponse(
                     final int count, final boolean examined,
                     final boolean searchIndexed,
                     @Nullable final Boolean shortCircuited,
                     @Nullable final Boolean fullyIndexed,
                     @Nullable final Boolean candidatesAreInScope,
                     @Nullable final Filter remainingFilter,
                     @Nullable final Collection<String> debugInfo)
  {
    Validator.ensureTrue(count >= 0);

    final MatchingEntryCountType countType;
    if (examined)
    {
      countType = MatchingEntryCountType.EXAMINED_COUNT;
    }
    else
    {
      countType = MatchingEntryCountType.UNEXAMINED_COUNT;
    }

    return new MatchingEntryCountResponseControl(countType, count,
         searchIndexed, shortCircuited, fullyIndexed, candidatesAreInScope,
         remainingFilter, debugInfo);
  }



  /**
   * Creates a new matching entry count response control for the case in which
   * the exact number of matching entries is not known, but the server was able
   * to determine an upper bound on the number of matching entries.  This upper
   * bound count may include entries that do not match the search filter, that
   * are outside the scope of the search, and/or that match the search criteria
   * but would not have been returned to the client in a normal search with the
   * same criteria.
   *
   * @param  upperBound  The upper bound on the number of entries that match the
   *                     associated search criteria.  It must be greater than
   *                     zero.
   * @param  debugInfo   An optional list of messages providing debug
   *                     information about the processing performed by the
   *                     server.  It may be {@code null} or empty if no debug
   *                     messages should be included.
   *
   * @return  The matching entry count response control that was created.
   */
  @NotNull()
  public static MatchingEntryCountResponseControl createUpperBoundResponse(
                     final int upperBound,
                     @Nullable final Collection<String> debugInfo)
  {
    return createUpperBoundResponse(upperBound, true, debugInfo);
  }



  /**
   * Creates a new matching entry count response control for the case in which
   * the exact number of matching entries is not known, but the server was able
   * to determine an upper bound on the number of matching entries.  This upper
   * bound count may include entries that do not match the search filter, that
   * are outside the scope of the search, and/or that match the search criteria
   * but would not have been returned to the client in a normal search with the
   * same criteria.
   *
   * @param  upperBound     The upper bound on the number of entries that match
   *                        the associated search criteria.  It must be greater
   *                        than zero.
   * @param  searchIndexed  Indicates whether the search criteria is considered
   *                        at least partially indexed and could be processed
   *                        more efficiently than examining all entries with a
   *                        full database scan.
   * @param  debugInfo      An optional list of messages providing debug
   *                        information about the processing performed by the
   *                        server.  It may be {@code null} or empty if no debug
   *                        messages should be included.
   *
   * @return  The matching entry count response control that was created.
   */
  @NotNull()
  public static MatchingEntryCountResponseControl createUpperBoundResponse(
                     final int upperBound, final boolean searchIndexed,
                     @Nullable final Collection<String> debugInfo)
  {
    return createUpperBoundResponse(upperBound, searchIndexed, null, null, null,
         null, debugInfo);
  }



  /**
   * Creates a new matching entry count response control for the case in which
   * the exact number of matching entries is not known, but the server was able
   * to determine an upper bound on the number of matching entries.  This upper
   * bound count may include entries that do not match the search filter, that
   * are outside the scope of the search, and/or that match the search criteria
   * but would not have been returned to the client in a normal search with the
   * same criteria.
   *
   * @param  upperBound            The upper bound on the number of entries that
   *                               match the associated search criteria.  It
   *                               must be greater than zero.
   * @param  searchIndexed         Indicates whether the search criteria is
   *                               considered at least partially indexed and
   *                               could be processed more efficiently than
   *                               examining all entries with a full database
   *                               scan.
   * @param  shortCircuited        Indicates whether the server short-circuited
   *                               during candidate set processing before
   *                               evaluating all elements of the search
   *                               criteria (the filter and scope).  This may be
   *                               {@code null} if it is not available (e.g.,
   *                               because extended response data was not
   *                               requested).
   * @param  fullyIndexed          Indicates whether the search is considered
   *                               fully indexed.  Note that this may be
   *                               {@code false} even if the filter is actually
   *                               fully indexed if server index processing
   *                               short-circuited before evaluating all
   *                               components of the filter.  To avoid this,
   *                               issue the request control with both fast and
   *                               slow short-circuit thresholds set to zero.
   *                               This may be {@code null} if this is not
   *                               available (e.g., because extended response
   *                               data was not requested).
   * @param  candidatesAreInScope  Indicates whether all the identified
   *                               candidate entries are within the scope of
   *                               the search.  It may be {@code null} if this
   *                               is not available (e.g., because extended
   *                               response data was not requested).
   * @param  remainingFilter       The portion of the filter that was either
   *                               identified as unindexed or that was not
   *                               evaluated because processing short-circuited
   *                               in the course of building the candidate set.
   *                               It may be {@code null} if there is no
   *                               remaining filter or if this information is
   *                               not available (e.g., because extended
   *                               response data was not requested).
   * @param  debugInfo             An optional list of messages providing debug
   *                               information about the processing performed by
   *                               the server.  It may be {@code null} or empty
   *                               if no debug messages should be included.
   *
   * @return  The matching entry count response control that was created.
   */
  @NotNull()
  public static MatchingEntryCountResponseControl createUpperBoundResponse(
                     final int upperBound, final boolean searchIndexed,
                     @Nullable final Boolean shortCircuited,
                     @Nullable final Boolean fullyIndexed,
                     @Nullable final Boolean candidatesAreInScope,
                     @Nullable final Filter remainingFilter,
                     @Nullable final Collection<String> debugInfo)
  {
    Validator.ensureTrue(upperBound > 0);

    return new MatchingEntryCountResponseControl(
         MatchingEntryCountType.UPPER_BOUND, upperBound, searchIndexed,
         shortCircuited, fullyIndexed, candidatesAreInScope, remainingFilter,
         debugInfo);
  }



  /**
   * Creates a new matching entry count response control for the case in which
   * the server was unable to make any meaningful determination about the number
   * of entries matching the search criteria.
   *
   * @param  debugInfo  An optional list of messages providing debug information
   *                    about the processing performed by the server.  It may be
   *                    {@code null} or empty if no debug messages should be
   *                    included.
   *
   * @return  The matching entry count response control that was created.
   */
  @NotNull()
  public static MatchingEntryCountResponseControl createUnknownCountResponse(
                     @Nullable final Collection<String> debugInfo)
  {
    return new MatchingEntryCountResponseControl(MatchingEntryCountType.UNKNOWN,
         -1, false, null, null, null, null, debugInfo);
  }



  /**
   * Encodes a control value with the provided information.
   *
   * @param  countType             The matching entry count type.  It must not
   *                               be {@code null}.
   * @param  countValue            The matching entry count value.  It must be
   *                               greater than or equal to zero for a count
   *                               type of either {@code EXAMINED_COUNT} or
   *                               {@code UNEXAMINED_COUNT}.  It must be greater
   *                               than zero for a count type of
   *                               {@code UPPER_BOUND}.  It must be -1 for a
   *                               count type of {@code UNKNOWN}.
   * @param  searchIndexed         Indicates whether the search criteria is
   *                               considered at least partially indexed and
   *                               could be processed more efficiently than
   *                               examining all entries with a full database
   *                               scan.
   * @param  shortCircuited        Indicates whether the server short-circuited
   *                               during candidate set processing before
   *                               evaluating all elements of the search
   *                               criteria (the filter and scope).  This may be
   *                               {@code null} if it is not available (e.g.,
   *                               because extended response data was not
   *                               requested).
   * @param  fullyIndexed          Indicates whether the search is considered
   *                               fully indexed.  Note that this may be
   *                               {@code false} even if the filter is actually
   *                               fully indexed if server index processing
   *                               short-circuited before evaluating all
   *                               components of the filter.  To avoid this,
   *                               issue the request control with both fast and
   *                               slow short-circuit thresholds set to zero.
   *                               This may be {@code null} if this is not
   *                               available (e.g., because extended response
   *                               data was not requested).
   * @param  candidatesAreInScope  Indicates whether all the identified
   *                               candidate entries are within the scope of
   *                               the search.  It may be {@code null} if this
   *                               is not available (e.g., because extended
   *                               response data was not requested).
   * @param  remainingFilter       The portion of the filter that was either
   *                               identified as unindexed or that was not
   *                               evaluated because processing short-circuited
   *                               in the course of building the candidate set.
   *                               It may be {@code null} if there is no
   *                               remaining filter or if this information is
   *                               not available (e.g., because extended
   *                               response data was not requested).
   * @param  debugInfo             An optional list of messages providing debug
   *                               information about the processing performed by
   *                               the server.  It may be {@code null} or empty
   *                               if no debug messages should be included.
   *
   * @return  The encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final MatchingEntryCountType countType,
               final int countValue, final boolean searchIndexed,
               @Nullable final Boolean shortCircuited,
               @Nullable final Boolean fullyIndexed,
               @Nullable final Boolean candidatesAreInScope,
               @Nullable final Filter remainingFilter,
               @Nullable final Collection<String> debugInfo)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(3);

    switch (countType)
    {
      case EXAMINED_COUNT:
      case UNEXAMINED_COUNT:
      case UPPER_BOUND:
        elements.add(new ASN1Integer(countType.getBERType(), countValue));
        break;
      case UNKNOWN:
        elements.add(new ASN1Null(countType.getBERType()));
        break;
    }

    if (debugInfo != null)
    {
      final ArrayList<ASN1Element> debugElements =
           new ArrayList<>(debugInfo.size());
      for (final String s : debugInfo)
      {
        debugElements.add(new ASN1OctetString(s));
      }

      elements.add(new ASN1Sequence(TYPE_DEBUG_INFO, debugElements));
    }

    if (! searchIndexed)
    {
      elements.add(new ASN1Boolean(TYPE_SEARCH_INDEXED, searchIndexed));
    }

    if (shortCircuited != null)
    {
      elements.add(new ASN1Boolean(TYPE_SHORT_CIRCUITED, shortCircuited));
    }

    if (fullyIndexed != null)
    {
      elements.add(new ASN1Boolean(TYPE_FULLY_INDEXED, fullyIndexed));
    }

    if (candidatesAreInScope != null)
    {
      elements.add(new ASN1Boolean(TYPE_CANDIDATES_ARE_IN_SCOPE,
           candidatesAreInScope));
    }

    if (remainingFilter != null)
    {
      elements.add(new ASN1OctetString(TYPE_REMAINING_FILTER,
           remainingFilter.encode().encode()));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the matching entry count type for the response control.
   *
   * @return  The matching entry count type for the response control.
   */
  @NotNull()
  public MatchingEntryCountType getCountType()
  {
    return countType;
  }



  /**
   * Retrieves the matching entry count value for the response control.  For a
   * count type of {@code EXAMINED_COUNT} or {@code UNEXAMINED_COUNT}, this is
   * the exact number of matching entries.  For a count type of
   * {@code UPPER_BOUND}, this is the maximum number of entries that may match
   * the search criteria, but it may also include entries that do not match the
   * criteria.  For a count type of {@code UNKNOWN}, this will always be -1.
   *
   * @return  The exact count or upper bound of the number of entries in the
   *          server that may match the search criteria, or -1 if the server
   *          could not determine the number of matching entries.
   */
  public int getCountValue()
  {
    return countValue;
  }



  /**
   * Indicates whether the server considers the search criteria to be indexed
   * and therefore it could be processed more efficiently than examining all
   * entries with a full database scan.
   *
   * @return  {@code true} if the server considers the search criteria to be
   *          indexed, or {@code false} if not.
   */
  public boolean searchIndexed()
  {
    return searchIndexed;
  }



  /**
   * Indicates whether the server short-circuited during candidate set
   * processing before evaluating all elements of the search criteria (the
   * filter and scope).
   *
   * @return  {@code Boolean.TRUE} if the server did short-circuit during
   *          candidate set processing before evaluating all elements of the
   *          search criteria, {@code Boolean.FALSE} if the server evaluated all
   *          elements of the search criteria, or {@code null} if this
   *          information is not available (e.g., because extended response data
   *          was not requested).
   */
  @Nullable()
  public Boolean getShortCircuited()
  {
    return shortCircuited;
  }



  /**
   * Indicates whether the server considers the search criteria to be fully
   * indexed.  Note that if the server short-circuited during candidate set
   * processing before evaluating all search criteria (the filter and scope),
   * this may be {@code Boolean.FALSE} even if the search is actually completely
   * indexed.
   *
   * @return  {@code Boolean.TRUE} if the server considers the search criteria
   *          to be fully indexed, {@code Boolean.FALSE} if the search criteria
   *          is not known to be fully indexed, or {@code null} if this
   *          information is not available (e.g., because extended response data
   *          was not requested).
   */
  @Nullable()
  public Boolean getFullyIndexed()
  {
    return fullyIndexed;
  }



  /**
   * Indicates whether the server can determine that all the identified
   * candidates are within the scope of the search.  Note that even if the
   * server returns {@code Boolean.FALSE}, it does not necessarily mean that
   * not all the candidates are within the scope of the search, but just that
   * the server is not certain that is the case.
   *
   * @return  {@code Boolean.TRUE} if the server can determine that all the
   *          identified candidates are within the scope of the search,
   *          {@code Boolean.FALSE} if the server cannot determine that all the
   *          identified candidates are within the scope of the search, or
   *          {@code null} if this information is not available (e.g., because
   *          extended response data was not requested).
   */
  @Nullable()
  public Boolean getCandidatesAreInScope()
  {
    return candidatesAreInScope;
  }



  /**
   * Retrieves the portion of the filter that was either identified as not
   * indexed or that was not evaluated during candidate processing (e.g.,
   * because the server short-circuited processing before examining all filter
   * components).
   *
   * @return  The portion of the filter that was either identified as not
   *          indexed or that was not evaluated during candidate processing, or
   *          {@code null} if there was no remaining filter or if this
   *          information is not available (e.g., because extended response data
   *          was not requested).
   */
  @Nullable()
  public Filter getRemainingFilter()
  {
    return remainingFilter;
  }



  /**
   * Retrieves a list of messages with debug information about the processing
   * performed by the server in the course of obtaining the matching entry
   * count.  These messages are intended to be human-readable rather than
   * machine-parsable.
   *
   * @return  A list of messages with debug information about the processing
   *          performed by the server in the course of obtaining the matching
   *          entry count, or an empty list if no debug messages were provided.
   */
  @NotNull()
  public List<String> getDebugInfo()
  {
    return debugInfo;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public MatchingEntryCountResponseControl decodeControl(
              @NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new MatchingEntryCountResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a matching entry count response control from the provided search
   * result.
   *
   * @param  result  The search result from which to retrieve the matching entry
   *                 count response control.
   *
   * @return  The matching entry count response control contained in the
   *          provided result, or {@code null} if the result did not contain a
   *          matching entry count response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the matching entry count response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static MatchingEntryCountResponseControl get(
                     @NotNull final SearchResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(MATCHING_ENTRY_COUNT_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof MatchingEntryCountResponseControl)
    {
      return (MatchingEntryCountResponseControl) c;
    }
    else
    {
      return new MatchingEntryCountResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_MATCHING_ENTRY_COUNT_RESPONSE.get();
  }



  /**
   * Retrieves a representation of this matching entry count response control as
   * a JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the matching entry count response
   *     control, the OID is "1.3.6.1.4.1.30221.2.5.37".
   *   </LI>
   *   <LI>
   *     {@code control-name} -- An optional string field whose value is a
   *     human-readable name for this control.  This field is only intended for
   *     descriptive purposes, and when decoding a control, the {@code oid}
   *     field should be used to identify the type of control.
   *   </LI>
   *   <LI>
   *     {@code criticality} -- A mandatory Boolean field used to indicate
   *     whether this control is considered critical.
   *   </LI>
   *   <LI>
   *     {@code value-base64} -- An optional string field whose value is a
   *     base64-encoded representation of the raw value for this matching entry
   *     count response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this matching entry count
   *     response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code count-type} -- A string field whose value indicates how
   *         accurate the count is.  The value will be one of
   *         "{@code examined-count}", "{@code unexamined-count}",
   *         "{@code upper-bound}", or "{@code unknown}".
   *       </LI>
   *       <LI>
   *         {@code count-value} -- An optional integer field whose value is the
   *         matching entry count estimate returned by the server.  This will
   *         be absent for a {@code count-type} value of "{@code unknown}", and
   *         will be present for other {@code count-type} values.
   *       </LI>
   *       <LI>
   *         {@code search-indexed} -- A Boolean field that indicates whether
   *         the server considers the search to be at least partially indexed.
   *       </LI>
   *       <LI>
   *         {@code fully-indexed} -- An optional Boolean field that indicates
   *         whether the server considers the search to be fully indexed.
   *       </LI>
   *       <LI>
   *         {@code short-circuited} -- An optional Boolean field that indicates
   *         whether the server short-circuited at any point in evaluating the
   *         search criteria.
   *       </LI>
   *       <LI>
   *         {@code candidates-are-in-scope} -- An optional Boolean field that
   *         indicates whether the server knows that all identified candidate
   *         entries are within the scope of the search.
   *       </LI>
   *       <LI>
   *         {@code remaining-filter} -- An optional string field whose value is
   *         the portion of the filter that was not evaluated during the course
   *         of coming up with the estimate.
   *       </LI>
   *       <LI>
   *         {@code debug-info} -- An optional array field whose values are
   *         strings with debug information about the processing performed by
   *         the server in the course of determining the matching entry count
   *         estimate.
   *       </LI>
   *     </UL>
   *   </LI>
   * </UL>
   *
   * @return  A JSON object that contains a representation of this control.
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final Map<String,JSONValue> valueFields = new LinkedHashMap<>();

    switch (countType)
    {
      case EXAMINED_COUNT:
        valueFields.put(JSON_FIELD_COUNT_TYPE,
             new JSONString(JSON_COUNT_TYPE_EXAMINED_COUNT));
        valueFields.put(JSON_FIELD_COUNT_VALUE, new JSONNumber(countValue));
        break;
      case UNEXAMINED_COUNT:
        valueFields.put(JSON_FIELD_COUNT_TYPE,
             new JSONString(JSON_COUNT_TYPE_UNEXAMINED_COUNT));
        valueFields.put(JSON_FIELD_COUNT_VALUE, new JSONNumber(countValue));
        break;
      case UPPER_BOUND:
        valueFields.put(JSON_FIELD_COUNT_TYPE,
             new JSONString(JSON_COUNT_TYPE_UPPER_BOUND));
        valueFields.put(JSON_FIELD_COUNT_VALUE, new JSONNumber(countValue));
        break;
      case UNKNOWN:
        valueFields.put(JSON_FIELD_COUNT_TYPE,
             new JSONString(JSON_COUNT_TYPE_UNKNOWN));
        break;
    }

    valueFields.put(JSON_FIELD_SEARCH_INDEXED, new JSONBoolean(searchIndexed));

    if (fullyIndexed != null)
    {
      valueFields.put(JSON_FIELD_FULLY_INDEXED,
           new JSONBoolean(fullyIndexed));
    }

    if (shortCircuited != null)
    {
      valueFields.put(JSON_FIELD_SHORT_CIRCUITED,
           new JSONBoolean(shortCircuited));
    }

    if (candidatesAreInScope != null)
    {
      valueFields.put(JSON_FIELD_CANDIDATES_ARE_IN_SCOPE,
           new JSONBoolean(candidatesAreInScope));
    }

    if (remainingFilter != null)
    {
      valueFields.put(JSON_FIELD_REMAINING_FILTER,
           new JSONString(remainingFilter.toString()));
    }

    if ((debugInfo != null) && (! debugInfo.isEmpty()))
    {
      final List<JSONString> debugInfoValues =
           new ArrayList<>(debugInfo.size());
      for (final String s : debugInfo)
      {
        debugInfoValues.add(new JSONString(s));
      }

      valueFields.put(JSON_FIELD_DEBUG_INFO, new JSONArray(debugInfoValues));
    }


    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              MATCHING_ENTRY_COUNT_RESPONSE_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_MATCHING_ENTRY_COUNT_RESPONSE.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * matching entry count response control.
   *
   * @param  controlObject  The JSON object to be decoded.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The matching entry count response control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid matching entry count response control.
   */
  @NotNull()
  public static MatchingEntryCountResponseControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new MatchingEntryCountResponseControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final MatchingEntryCountType countType;
    final String countTypeStr =
         valueObject.getFieldAsString(JSON_FIELD_COUNT_TYPE);
    Integer countValue = valueObject.getFieldAsInteger(JSON_FIELD_COUNT_VALUE);
    if (countTypeStr == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_COUNT_TYPE));
    }

    switch (countTypeStr)
    {
      case JSON_COUNT_TYPE_EXAMINED_COUNT:
        countType = MatchingEntryCountType.EXAMINED_COUNT;
        if (countValue == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_MISSING_COUNT_VALUE.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_COUNT_VALUE, JSON_FIELD_COUNT_TYPE,
                    countTypeStr));
        }
        break;

      case JSON_COUNT_TYPE_UNEXAMINED_COUNT:
        countType = MatchingEntryCountType.UNEXAMINED_COUNT;
        if (countValue == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_MISSING_COUNT_VALUE.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_COUNT_VALUE, JSON_FIELD_COUNT_TYPE,
                    countTypeStr));
        }
        break;

      case JSON_COUNT_TYPE_UPPER_BOUND:
        countType = MatchingEntryCountType.UPPER_BOUND;
        if (countValue == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_MISSING_COUNT_VALUE.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_COUNT_VALUE, JSON_FIELD_COUNT_TYPE,
                    countTypeStr));
        }
        break;

      case JSON_COUNT_TYPE_UNKNOWN:
        countType = MatchingEntryCountType.UNKNOWN;
        if (countValue == null)
        {
          countValue = -1;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_UNEXPECTED_COUNT_VALUE.
                    get(controlObject.toSingleLineString(),
                         JSON_FIELD_COUNT_VALUE, JSON_FIELD_COUNT_TYPE,
                         countTypeStr));
        }
        break;

      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_UNKNOWN_COUNT_TYPE.get(
                  controlObject.toSingleLineString(),
                  JSON_FIELD_COUNT_TYPE, countTypeStr));
    }


    final Boolean searchIndexed =
         valueObject.getFieldAsBoolean(JSON_FIELD_SEARCH_INDEXED);
    if (searchIndexed == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_SEARCH_INDEXED));
    }


    final Boolean fullyIndexed =
         valueObject.getFieldAsBoolean(JSON_FIELD_FULLY_INDEXED);
    final Boolean shortCircuited =
         valueObject.getFieldAsBoolean(JSON_FIELD_SHORT_CIRCUITED);
    final Boolean candidatesAreInScope =
         valueObject.getFieldAsBoolean(JSON_FIELD_CANDIDATES_ARE_IN_SCOPE);


    final Filter remainingFilter;
    final String remainingFilterStr =
         valueObject.getFieldAsString(JSON_FIELD_REMAINING_FILTER);
    if (remainingFilterStr == null)
    {
      remainingFilter = null;
    }
    else
    {
      try
      {
        remainingFilter = Filter.create(remainingFilterStr);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_INVALID_FILTER.get(
                  controlObject.toSingleLineString(),
                  JSON_FIELD_REMAINING_FILTER, remainingFilterStr),
             e);
      }
    }


    final List<String> debugInfo;
    final List<JSONValue> debugInfoValues =
         valueObject.getFieldAsArray(JSON_FIELD_DEBUG_INFO);
    if (debugInfoValues == null)
    {
      debugInfo = null;
    }
    else
    {
      debugInfo = new ArrayList<>(debugInfoValues.size());
      for (final JSONValue v : debugInfoValues)
      {
        if (v instanceof JSONString)
        {
          debugInfo.add(((JSONString) v).stringValue());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_DEBUG_INFO_NOT_STRING.get(
                    controlObject.toSingleLineString(), JSON_FIELD_DEBUG_INFO));
        }
      }
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_COUNT_TYPE, JSON_FIELD_COUNT_VALUE,
                JSON_FIELD_SEARCH_INDEXED, JSON_FIELD_FULLY_INDEXED,
                JSON_FIELD_SHORT_CIRCUITED, JSON_FIELD_CANDIDATES_ARE_IN_SCOPE,
                JSON_FIELD_REMAINING_FILTER, JSON_FIELD_DEBUG_INFO);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new MatchingEntryCountResponseControl(countType, countValue,
         searchIndexed, shortCircuited, fullyIndexed, candidatesAreInScope,
         remainingFilter, debugInfo);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MatchingEntryCountResponseControl(countType='");
    buffer.append(countType.name());
    buffer.append('\'');

    switch (countType)
    {
      case EXAMINED_COUNT:
      case UNEXAMINED_COUNT:
        buffer.append(", count=");
        buffer.append(countValue);
        break;

      case UPPER_BOUND:
        buffer.append(", upperBound=");
        buffer.append(countValue);
        break;
    }

    buffer.append(", searchIndexed=");
    buffer.append(searchIndexed);

    if (shortCircuited != null)
    {
      buffer.append(", shortCircuited=");
      buffer.append(shortCircuited);
    }

    if (fullyIndexed != null)
    {
      buffer.append(", fullyIndexed=");
      buffer.append(fullyIndexed);
    }

    if (candidatesAreInScope != null)
    {
      buffer.append(", candidatesAreInScope=");
      buffer.append(candidatesAreInScope);
    }

    if (remainingFilter != null)
    {
      buffer.append(", remainingFilter='");
      remainingFilter.toString(buffer);
      buffer.append('\'');
    }

    if (! debugInfo.isEmpty())
    {
      buffer.append(", debugInfo={");

      final Iterator<String> iterator = debugInfo.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    buffer.append(')');
  }
}
