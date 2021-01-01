/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an extended result that may be used to obtain information
 * about the results of processing a get changelog batch extended request.
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
 * The changelog batch result value is encoded as follows:
 * <PRE>
 *   ChangelogBatchResult ::= SEQUENCE {
 *        resumeToken                   [0] OCTET STRING OPTIONAL,
 *        moreChangesAvailable          [1] BOOLEAN,
 *        changesAlreadyPurged          [2] BOOLEAN DEFAULT FALSE,
 *        additionalInfo                [3] OCTET STRING OPTIONAL,
 *        estimatedChangesRemaining     [4] INTEGER (0 .. MAXINT) OPTIONAL,
 *        ... }
 * </PRE>
 * <BR><BR>
 * See the documentation for the {@link GetChangelogBatchExtendedRequest} class
 * for an example demonstrating its use.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetChangelogBatchExtendedResult
       extends ExtendedResult
{
  /**
   * The BER type for the resume token element.
   */
  private static final byte TYPE_RESUME_TOKEN = (byte) 0x80;



  /**
   * The BER type for the more changes available element.
   */
  private static final byte TYPE_MORE_CHANGES_AVAILABLE = (byte) 0x81;



  /**
   * The BER type for the changes already purged element.
   */
  private static final byte TYPE_CHANGES_ALREADY_PURGED = (byte) 0x82;



  /**
   * The BER type for the additional info element.
   */
  private static final byte TYPE_ADDITIONAL_INFO = (byte) 0x83;



  /**
   * The BER type for the estimated changes remaining element.
   */
  private static final byte TYPE_ESTIMATED_CHANGES_REMAINING = (byte) 0x84;



  /**
   * The serial version UID for this serializable object.
   */
  private static final long serialVersionUID = -1997815252100989148L;



  // The resume token for this extended result.
  @Nullable private final ASN1OctetString resumeToken;

  // Indicates whether some changes in the requested batch may have already
  // been purged.
  private final boolean changesAlreadyPurged;

  // Indicates whether the server has additional results that are immediately
  // available without waiting.
  private final boolean moreChangesAvailable;

  // The estimated number of remaining changes, if available.
  private final int estimatedChangesRemaining;

  // The number of entries returned to the client.
  private final int entryCount;

  // A list of the entries returned to the client.
  @Nullable private final List<ChangelogEntryIntermediateResponse> entryList;

  // A message with additional information about the result.
  @Nullable private final String additionalInfo;



  /**
   * Creates a new get changelog batch extended result with only the generic
   * LDAP result information and no extended value.
   *
   * @param  r  An LDAP result with general details of the response.  It must
   *            not be {@code null}.
   */
  public GetChangelogBatchExtendedResult(@NotNull final LDAPResult r)
  {
    super(r.getMessageID(), r.getResultCode(), r.getDiagnosticMessage(),
         r.getMatchedDN(), r.getReferralURLs(), null, null,
         r.getResponseControls());

    resumeToken               = null;
    changesAlreadyPurged      = false;
    moreChangesAvailable      = false;
    estimatedChangesRemaining = -1;
    entryCount                = -1;
    entryList                 = null;
    additionalInfo            = null;
  }



  /**
   * Creates a new get changelog batch extended result with the provided
   * information.
   *
   * @param  r                     An LDAP result with general details of the
   *                               response.  It must not be {@code null}.
   * @param  entryCount            The number of entries returned.  It may be
   *                               less than zero to indicate that the number of
   *                               entries is unknown.
   * @param  resumeToken           A token which may be used to resume
   *                               retrieving changes at the point immediately
   *                               after the last change returned.  It may be
   *                               {@code null} only if this result represents
   *                               an error that prevented the operation from
   *                               being successfully processed.
   * @param  moreChangesAvailable  Indicates whether there may be more changes
   *                               immediately available to retrieve from the
   *                               server.
   * @param  changesAlreadyPurged  Indicates whether the server may have already
   *                               purged changes after the starting point
   *                               referenced by the associated request.
   * @param  additionalInfo        A message with additional information about
   *                               the status of the processing.  It may be
   *                               {@code null} if no additional message is
   *                               available.
   */
  public GetChangelogBatchExtendedResult(@NotNull final LDAPResult r,
              final int entryCount,
              @Nullable final ASN1OctetString resumeToken,
              final boolean moreChangesAvailable,
              final boolean changesAlreadyPurged,
              @Nullable final String additionalInfo)
  {
    this(r, entryCount, resumeToken, moreChangesAvailable, -1,
         changesAlreadyPurged, additionalInfo);
  }



  /**
   * Creates a new get changelog batch extended result with the provided
   * information.
   *
   * @param  r                          An LDAP result with general details of
   *                                    the response.  It must not be
   *                                    {@code null}.
   * @param  entryCount                 The number of entries returned.  It may
   *                                    be less than zero to indicate that the
   *                                    number of entries is unknown.
   * @param  resumeToken                A token which may be used to resume
   *                                    retrieving changes at the point
   *                                    immediately after the last change
   *                                    returned.  It may be {@code null} only
   *                                    if this result represents an error that
   *                                    prevented the operation from being
   *                                    successfully processed.
   * @param  moreChangesAvailable       Indicates whether there may be more
   *                                    changes immediately available to
   *                                    retrieve from the server.
   * @param  estimatedChangesRemaining  An estimate of the number of changes
   *                                    remaining to be retrieved.  A value less
   *                                    than zero will be interpreted as
   *                                    "unknown".
   * @param  changesAlreadyPurged       Indicates whether the server may have
   *                                    already purged changes after the
   *                                    starting point referenced by the
   *                                    associated request.
   * @param  additionalInfo             A message with additional information
   *                                    about the status of the processing.  It
   *                                    may be {@code null} if no additional
   *                                    message is available.
   */
  public GetChangelogBatchExtendedResult(@NotNull final LDAPResult r,
              final int entryCount,
              @Nullable final ASN1OctetString resumeToken,
              final boolean moreChangesAvailable,
              final int estimatedChangesRemaining,
              final boolean changesAlreadyPurged,
              @Nullable final String additionalInfo)
  {
    super(r.getMessageID(), r.getResultCode(), r.getDiagnosticMessage(),
         r.getMatchedDN(), r.getReferralURLs(), null,
         encodeValue(resumeToken, moreChangesAvailable,
              estimatedChangesRemaining, changesAlreadyPurged, additionalInfo),
         r.getResponseControls());

    this.resumeToken          = resumeToken;
    this.moreChangesAvailable = moreChangesAvailable;
    this.changesAlreadyPurged = changesAlreadyPurged;
    this.additionalInfo       = additionalInfo;

    if (estimatedChangesRemaining >= 0)
    {
      this.estimatedChangesRemaining = estimatedChangesRemaining;
    }
    else
    {
      this.estimatedChangesRemaining = -1;
    }

    entryList = null;
    if (entryCount < 0)
    {
      this.entryCount = -1;
    }
    else
    {
      this.entryCount = entryCount;
    }
  }



  /**
   * Creates a new get changelog batch extended result with the provided
   * information.
   *
   * @param  extendedResult  A generic extended result to be parsed as a get
   *                         changelog batch extended result.  It must not be
   *                         {@code null}.
   * @param  entryCount      The number of entries returned to the client.  It
   *                         may be less than zero to indicate that the entry
   *                         count is unknown.
   *
   * @throws  LDAPException  If the provided extended result cannot be parsed as
   *                         a get changelog batch result.
   */
  public GetChangelogBatchExtendedResult(
              @NotNull final ExtendedResult extendedResult,
              final int entryCount)
         throws LDAPException
  {
    this(extendedResult, entryCount, null);
  }



  /**
   * Creates a new get changelog batch extended result with the provided
   * information.
   *
   * @param  extendedResult  A generic extended result to be parsed as a get
   *                         changelog batch extended result.  It must not be
   *                         {@code null}.
   * @param  entryList       A list of the entries returned to the client.  It
   *                         may be empty to indicate that no entries were
   *                         returned, but it must not be {@code null}.
   *
   * @throws  LDAPException  If the provided extended result cannot be parsed as
   *                         a get changelog batch result.
   */
  public GetChangelogBatchExtendedResult(
              @NotNull final ExtendedResult extendedResult,
              @NotNull final List<ChangelogEntryIntermediateResponse> entryList)
         throws LDAPException
  {
    this(extendedResult, entryList.size(), entryList);
  }



  /**
   * Creates a new get changelog batch extended result with the provided
   * information.
   *
   * @param  r           A generic extended result to be parsed as a get
   *                     changelog batch extended result.  It must not be
   *                     {@code null}.
   * @param  entryCount  The number of entries returned to the client.  It may
   *                     be less than zero to indicate that the entry count is
   *                     unknown.
   * @param  entryList   A list of the entries returned to the client.  It may
   *                     be empty to indicate that no entries were returned, or
   *                     {@code null} if the entry list is not available.
   *
   * @throws  LDAPException  If the provided extended result cannot be parsed as
   *                         a get changelog batch result.
   */
  private GetChangelogBatchExtendedResult(@NotNull final ExtendedResult r,
       final int entryCount,
       @Nullable final List<ChangelogEntryIntermediateResponse> entryList)
       throws LDAPException
  {
    super(r);

    if (entryList == null)
    {
      this.entryList = null;
    }
    else
    {
      this.entryList = Collections.unmodifiableList(entryList);
    }

    if (entryCount < 0)
    {
      this.entryCount = -1;
    }
    else
    {
      this.entryCount = entryCount;
    }

    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      // See if an entry list was provided and we can get a resume token from
      // it.
      if ((entryList != null) && (! entryList.isEmpty()))
      {
        resumeToken = entryList.get(entryList.size() - 1).getResumeToken();
      }
      else
      {
        resumeToken = null;
      }

      moreChangesAvailable      = false;
      estimatedChangesRemaining = -1;
      changesAlreadyPurged      = false;
      additionalInfo            = null;
      return;
    }

    final ASN1Element[] valueElements;
    try
    {
      valueElements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_CHANGELOG_BATCH_RES_VALUE_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    ASN1OctetString token = null;
    Boolean moreChanges = null;
    boolean missingChanges = false;
    int changesRemaining = -1;
    String message = null;

    try
    {
      for (final ASN1Element e : valueElements)
      {
        final byte type = e.getType();
        switch (type)
        {
          case TYPE_RESUME_TOKEN:
            token = ASN1OctetString.decodeAsOctetString(e);
            break;
          case TYPE_MORE_CHANGES_AVAILABLE:
            moreChanges = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_CHANGES_ALREADY_PURGED:
            missingChanges = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_ADDITIONAL_INFO:
            message = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_ESTIMATED_CHANGES_REMAINING:
            changesRemaining = ASN1Integer.decodeAsInteger(e).intValue();
            if (changesRemaining < 0)
            {
              changesRemaining = -1;
            }
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_CHANGELOG_BATCH_RES_UNEXPECTED_VALUE_ELEMENT.get(
                      StaticUtils.toHex(type)));
        }
      }
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
           ERR_GET_CHANGELOG_BATCH_RES_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    if (moreChanges == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_CHANGELOG_BATCH_RES_MISSING_MORE.get());
    }

    resumeToken               = token;
    moreChangesAvailable      = moreChanges;
    changesAlreadyPurged      = missingChanges;
    estimatedChangesRemaining = changesRemaining;
    additionalInfo            = message;
  }



  /**
   * Encodes the provided information in a form suitable for use as the value of
   * this extended result.
   *
   * @param  resumeToken                A token which may be used to resume
   *                                    retrieving changes at the point
   *                                    immediately after the last change
   *                                    returned.  It may be {@code null} only
   *                                    if this result represents an error that
   *                                    prevented the operation from being
   *                                    successfully processed.
   * @param  moreChangesAvailable       Indicates whether there may be more
   *                                    changes immediately available to
   *                                    retrieve from the server.
   * @param  estimatedChangesRemaining  An estimate of the number of changes
   *                                    remaining to be retrieved.  A value less
   *                                    than zero will be interpreted as
   *                                    "unknown".
   * @param  changesAlreadyPurged       Indicates whether the server may have
   *                                    already purged changes after the
   *                                    starting point referenced by the
   *                                    associated request.
   * @param  additionalInfo             A message with additional information
   *                                    about the status of the processing.  It
   *                                    may be {@code null} if no additional
   *                                    message is available.
   *
   * @return  The ASN.1 octet string to use as the result, or {@code null} if
   *          there should be no value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
               @Nullable final ASN1OctetString resumeToken,
               final boolean moreChangesAvailable,
               final int estimatedChangesRemaining,
               final boolean changesAlreadyPurged,
               @Nullable final String additionalInfo)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(5);

    if (resumeToken != null)
    {
      elements.add(new ASN1OctetString(TYPE_RESUME_TOKEN,
           resumeToken.getValue()));
    }

    elements.add(new ASN1Boolean(TYPE_MORE_CHANGES_AVAILABLE,
         moreChangesAvailable));

    if (estimatedChangesRemaining >= 0)
    {
      elements.add(new ASN1Integer(TYPE_ESTIMATED_CHANGES_REMAINING,
           estimatedChangesRemaining));
    }

    if (changesAlreadyPurged)
    {
      elements.add(new ASN1Boolean(TYPE_CHANGES_ALREADY_PURGED,
           changesAlreadyPurged));
    }

    if (additionalInfo != null)
    {
      elements.add(new ASN1OctetString(TYPE_ADDITIONAL_INFO, additionalInfo));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves a token that may be used to resume the process of retrieving
   * changes at the point after the last change received.  It may be
   * {@code null} if this result represents an error that prevented the
   * operation from being processed successfully.
   *
   * @return  A token that may be used to resume the process of retrieving
   *          changes at the point after the last change received, or
   *          {@code null} if none is available.
   */
  @Nullable()
  public ASN1OctetString getResumeToken()
  {
    return resumeToken;
  }



  /**
   * Indicates whether the server indicated that more changes may be immediately
   * available without waiting.  The value of this argument is only meaningful
   * if {@link #hasValue()} returns {@code true}.
   *
   * @return  {@code true} if the server indicated that more changes may be
   *          immediately available without waiting, or {@code false} if not.
   */
  public boolean moreChangesAvailable()
  {
    return moreChangesAvailable;
  }



  /**
   * Retrieves an estimate of the number of changes that may be immediately
   * available to be retrieved from the server, if available.
   *
   * @return  An estimate of the number of changes that may be immediately
   *          available to be retrieved from the server, or -1 if that
   *          information is not available.
   */
  public int getEstimatedChangesRemaining()
  {
    return estimatedChangesRemaining;
  }



  /**
   * Indicates whether the server indicated that it may have already purged one
   * or more changes after the starting point for the associated request and
   * therefore the results returned may be missing changes.  The value of this
   * argument is only meaningful if {@link #hasValue()} returns {@code true}.
   *
   * @return  {@code true} if the server indicated that it may have already
   *          purged one or more changes after the starting point, or
   *          {@code false} if not.
   */
  public boolean changesAlreadyPurged()
  {
    return changesAlreadyPurged;
  }



  /**
   * Retrieves a message with additional information about the processing that
   * occurred, if available.
   *
   * @return  A message with additional information about the processing that
   *          occurred, or {@code null} if none is available.
   */
  @Nullable()
  public String getAdditionalInfo()
  {
    return additionalInfo;
  }



  /**
   * Retrieves the number of entries returned by the server in the course of
   * processing the extended operation.  A value of -1 indicates that the entry
   * count is not known.
   *
   * @return  The number of entries returned by the server in the course of
   *          processing the extended operation, 0 if no entries were returned,
   *          or -1 if the entry count is not known.
   */
  public int getEntryCount()
  {
    return entryCount;
  }



  /**
   * Retrieves a list containing the entries that were returned by the server in
   * the course of processing the extended operation, if available.  An entry
   * list will not be available if a custom {@link ChangelogEntryListener} was
   * used for the request, and it may not be available if an error was
   * encountered during processing.
   *
   * @return  A list containing the entries that were returned by the server in
   *          the course of processing the extended operation, or {@code null}
   *          if an entry list is not available.
   */
  @Nullable()
  public List<ChangelogEntryIntermediateResponse> getChangelogEntries()
  {
    return entryList;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_GET_CHANGELOG_BATCH_RES_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    final String diagnosticMessage = getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    final String matchedDN = getMatchedDN();
    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    final String[] referralURLs = getReferralURLs();
    if (referralURLs.length > 0)
    {
      buffer.append(", referralURLs={");
      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(referralURLs[i]);
      }
      buffer.append('}');
    }

    if (resumeToken != null)
    {
      buffer.append(", resumeToken='");
      Base64.encode(resumeToken.getValue(), buffer);
      buffer.append('\'');
    }

    buffer.append(", moreChangesAvailable=");
    buffer.append(moreChangesAvailable);

    buffer.append(", estimatedChangesRemaining=");
    buffer.append(estimatedChangesRemaining);

    buffer.append(", changesAlreadyPurged=");
    buffer.append(changesAlreadyPurged);

    if (additionalInfo != null)
    {
      buffer.append(", additionalInfo='");
      buffer.append(additionalInfo);
      buffer.append('\'');
    }

    buffer.append(", entryCount=");
    buffer.append(entryCount);


    final Control[] responseControls = getResponseControls();
    if (responseControls.length > 0)
    {
      buffer.append(", responseControls={");
      for (int i=0; i < responseControls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(responseControls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
