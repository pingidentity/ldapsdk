/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Null;
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
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

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
 *        entryCount        CHOICE {
 *             examinedCount       [0] INTEGER,
 *             unexaminedCount     [1] INTEGER,
 *             upperBound          [2] INTEGER,
 *             unknown             [3] NULL,
 *             ... }
 *        debugInfo         [0] SEQUENCE OF OCTET STRING OPTIONAL,
 *        searchIndexed     [1] BOOLEAN DEFAULT TRUE,
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
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5488025806310455564L;



  // Indicates whether the search criteria is considered at least partially
  // indexed by the server.
  private final boolean searchIndexed;

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
    countType     = null;
    countValue    = -1;
    debugInfo     = null;
  }



  /**
   * Creates a new matching entry count response control with the provided
   * information.
   *
   * @param  countType      The matching entry count type.  It must not be
   *                        {@code null}.
   * @param  countValue     The matching entry count value.  It must be greater
   *                        than or equal to zero for a count type of either
   *                        {@code EXAMINED_COUNT} or {@code UNEXAMINED_COUNT}.
   *                        It must be greater than zero for a count type of
   *                        {@code UPPER_BOUND}.  It must be -1 for a count type
   *                        of {@code UNKNOWN}.
   * @param  searchIndexed  Indicates whether the search criteria is considered
   *                        at least partially indexed and could be processed
   *                        more efficiently than examining all entries with a
   *                        full database scan.
   * @param  debugInfo      An optional list of messages providing debug
   *                        information about the processing performed by the
   *                        server.  It may be {@code null} or empty if no debug
   *                        messages should be included.
   */
  private MatchingEntryCountResponseControl(
               @NotNull final MatchingEntryCountType countType,
               final int countValue,
               final boolean searchIndexed,
               @Nullable final Collection<String> debugInfo)
  {
    super(MATCHING_ENTRY_COUNT_RESPONSE_OID, false,
         encodeValue(countType, countValue, searchIndexed, debugInfo));

    this.countType     = countType;
    this.countValue    = countValue;
    this.searchIndexed = searchIndexed;

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

      boolean isIndexed = (countType != MatchingEntryCountType.UNKNOWN);
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
            isIndexed = ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_MATCHING_ENTRY_COUNT_RESPONSE_UNKNOWN_ELEMENT_TYPE.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }

      searchIndexed = isIndexed;
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
         searchIndexed, debugInfo);
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
    Validator.ensureTrue(upperBound > 0);

    return new MatchingEntryCountResponseControl(
         MatchingEntryCountType.UPPER_BOUND, upperBound, searchIndexed,
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
         -1, false, debugInfo);
  }



  /**
   * Encodes a control value with the provided information.
   *
   * @param  countType      The matching entry count type.  It must not be
   *                        {@code null}.
   * @param  countValue     The matching entry count value.  It must be greater
   *                        than or equal to zero for a count type of either
   *                        {@code EXAMINED_COUNT} or {@code UNEXAMINED_COUNT}.
   *                        It must be greater than zero for a count type of
   *                        {@code UPPER_BOUND}.  It must be -1 for a count type
   *                        of {@code UNKNOWN}.
   * @param  searchIndexed  Indicates whether the search criteria is considered
   *                        at least partially indexed and could be processed
   *                        more efficiently than examining all entries with a
   *                        full database scan.
   * @param  debugInfo      An optional list of messages providing debug
   *                        information about the processing performed by the
   *                        server.  It may be {@code null} or empty if no debug
   *                        messages should be included.
   *
   * @return  The encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final MatchingEntryCountType countType,
               final int countValue,
               final boolean searchIndexed,
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
