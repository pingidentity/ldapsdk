/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure for holding information about the result
 * of processing a search request.  This includes the elements of the
 * {@link LDAPResult} object, but also contains additional information specific
 * to the search operation.  This includes:
 * <UL>
 *   <LI>The number of {@link SearchResultEntry} objects returned from the
 *       server.  This will be available regardless of whether the entries are
 *       included in this search result object or were returned through a
 *       {@link SearchResultListener}.</LI>
 *   <LI>The number of {@link SearchResultReference} objects returned from the
 *       server.  This will be available regardless of whether the entries are
 *       included in this search result object or were returned through a
 *       {@link SearchResultListener}.</LI>
 *   <LI>A list of the {@link SearchResultEntry} objects returned from the
 *       server.  This will be {@code null} if a {@link SearchResultListener}
 *       was used to return the entries.</LI>
 *   <LI>A list of the {@link SearchResultReference} objects returned from the
 *       server.  This will be {@code null} if a {@link SearchResultListener}
 *       was used to return the entries.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResult
       extends LDAPResult
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1938208530894131198L;



  // The number of matching entries returned for this search.
  private int numEntries;

  // The number of search result references returned for this search.
  private int numReferences;

  // A list that may be used to hold the search result entries returned for
  // this search.
  @Nullable private List<SearchResultEntry> searchEntries;

  // A list that may be used to hold the search result references returned for
  // this search.
  @Nullable private List<SearchResultReference> searchReferences;



  /**
   * Creates a new search result object with the provided information.  This
   * version of the constructor should be used if the search result entries and
   * references were returned to the client via the {@code SearchResultListener}
   * interface.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the search result done
   *                            response.
   * @param  diagnosticMessage  The diagnostic message from the search result
   *                            done response, if available.
   * @param  matchedDN          The matched DN from the search result done
   *                            response, if available.
   * @param  referralURLs       The set of referral URLs from the search result
   *                            done response, if available.
   * @param  numEntries         The number of search result entries returned
   *                            for this search.
   * @param  numReferences      The number of search result references returned
   *                            for this search.
   * @param  responseControls   The set of controls from the search result done
   *                            response, if available.
   */
  public SearchResult(final int messageID, @NotNull final ResultCode resultCode,
                      @Nullable final String diagnosticMessage,
                      @Nullable final String matchedDN,
                      @Nullable final String[] referralURLs,
                      final int numEntries, final int numReferences,
                      @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          responseControls);

    this.numEntries    = numEntries;
    this.numReferences = numReferences;

    searchEntries    = null;
    searchReferences = null;
  }



  /**
   * Creates a new search result object with the provided information.  This
   * version of the constructor should be used if the search result entries and
   * references were collected in lists rather than returned to the requester
   * through the {@code SearchResultListener} interface.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the search result done
   *                            response.
   * @param  diagnosticMessage  The diagnostic message from the search result
   *                            done response, if available.
   * @param  matchedDN          The matched DN from the search result done
   *                            response, if available.
   * @param  referralURLs       The set of referral URLs from the search result
   *                            done response, if available.
   * @param  searchEntries      A list containing the set of search result
   *                            entries returned by the server.  It may only be
   *                            {@code null} if the search result entries were
   *                            returned through the
   *                            {@code SearchResultListener} interface.
   * @param  searchReferences   A list containing the set of search result
   *                            references returned by the server.  It may only
   *                            be {@code null} if the search result entries
   *                            were returned through the
   *                            {@code SearchResultListener} interface.
   * @param  numEntries         The number of search result entries returned
   *                            for this search.
   * @param  numReferences      The number of search result references returned
   *                            for this search.
   * @param  responseControls   The set of controls from the search result done
   *                            response, if available.
   */
  public SearchResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final List<SearchResultEntry> searchEntries,
              @Nullable final List<SearchResultReference> searchReferences,
              final int numEntries, final int numReferences,
              @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          responseControls);

    this.numEntries       = numEntries;
    this.numReferences    = numReferences;
    this.searchEntries    = searchEntries;
    this.searchReferences = searchReferences;
  }



  /**
   * Creates a new search result object with the information from the provided
   * LDAP result.
   *
   * @param  ldapResult  The LDAP result to use to create the contents of this
   *                     search result.
   */
  public SearchResult(@NotNull final LDAPResult ldapResult)
  {
    super(ldapResult);

    if (ldapResult instanceof SearchResult)
    {
      final SearchResult searchResult = (SearchResult) ldapResult;
      numEntries       = searchResult.numEntries;
      numReferences    = searchResult.numReferences;
      searchEntries    = searchResult.searchEntries;
      searchReferences = searchResult.searchReferences;
    }
    else
    {
      numEntries       = -1;
      numReferences    = -1;
      searchEntries    = null;
      searchReferences = null;
    }
  }



  /**
   * Creates a new search result object with the information from the provided
   * LDAP exception.
   *
   * @param  ldapException  The LDAP exception to use to create the contents of
   *                        this search result.
   */
  public SearchResult(@NotNull final LDAPException ldapException)
  {
    this(ldapException.toLDAPResult());
  }



  /**
   * Creates a new search result object with the provided message ID and with
   * the protocol op and controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this LDAP result.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded search result object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @NotNull()
  static SearchResult readSearchResultFrom(final int messageID,
              @NotNull final ASN1StreamReaderSequence messageSequence,
              @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    final LDAPResult r =
         LDAPResult.readLDAPResultFrom(messageID, messageSequence, reader);

    return new SearchResult(messageID, r.getResultCode(),
         r.getDiagnosticMessage(), r.getMatchedDN(), r.getReferralURLs(),
         -1, -1, r.getResponseControls());
  }



  /**
   * Retrieves the number of matching entries returned for the search operation.
   *
   * @return  The number of matching entries returned for the search operation.
   */
  public int getEntryCount()
  {
    return numEntries;
  }



  /**
   * Retrieves the number of search references returned for the search
   * operation.  This may be zero even if search references were received if the
   * connection used when processing the search was configured to automatically
   * follow referrals.
   *
   * @return  The number of search references returned for the search operation.
   */
  public int getReferenceCount()
  {
    return numReferences;
  }



  /**
   * Retrieves a list containing the matching entries returned from the search
   * operation.  This will only be available if a {@code SearchResultListener}
   * was not used during the search.
   *
   * @return  A list containing the matching entries returned from the search
   *          operation, or {@code null} if a {@code SearchResultListener} was
   *          used during the search.
   */
  @Nullable()
  public List<SearchResultEntry> getSearchEntries()
  {
    if (searchEntries == null)
    {
      return null;
    }

    return Collections.unmodifiableList(searchEntries);
  }



  /**
   * Retrieves the search result entry with the specified DN from the set of
   * entries returned.  This will only be available if a
   * {@code SearchResultListener} was not used during the search.
   *
   * @param  dn  The DN of the search result entry to retrieve.  It must not
   *             be {@code null}.
   *
   * @return  The search result entry with the provided DN, or {@code null} if
   *          the specified entry was not returned, or if a
   *          {@code SearchResultListener} was used for the search.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         parse the provided DN or a search entry DN.
   */
  @Nullable()
  public SearchResultEntry getSearchEntry(@NotNull final String dn)
         throws LDAPException
  {
    if (searchEntries == null)
    {
      return null;
    }

    final DN parsedDN = new DN(dn);
    for (final SearchResultEntry e : searchEntries)
    {
      if (parsedDN.equals(e.getParsedDN()))
      {
        return e;
      }
    }

    return null;
  }



  /**
   * Retrieves a list containing the search references returned from the search
   * operation.  This will only be available if a {@code SearchResultListener}
   * was not used during the search, and may be empty even if search references
   * were received if the connection used when processing the search was
   * configured to automatically follow referrals.
   *
   * @return  A list containing the search references returned from the search
   *          operation, or {@code null} if a {@code SearchResultListener} was
   *          used during the search.
   */
  @Nullable()
  public List<SearchResultReference> getSearchReferences()
  {
    if (searchReferences == null)
    {
      return null;
    }

    return Collections.unmodifiableList(searchReferences);
  }



  /**
   * Provides information about the entries and references returned for the
   * search operation.  This must only be called when a search result is created
   * and the search result must not be altered at any point after that.
   *
   * @param  numEntries        The number of entries returned for the search
   *                           operation.
   * @param  searchEntries     A list containing the entries returned from the
   *                           search operation, or {@code null} if a
   *                           {@code SearchResultListener} was used during the
   *                           search.
   * @param  numReferences     The number of references returned for the search
   *                           operation.
   * @param  searchReferences  A list containing the search references returned
   *                           from the search operation, or {@code null} if a
   *                           {@code SearchResultListener} was used during the
   *                           search.
   */
  void setCounts(final int numEntries,
                 @Nullable final List<SearchResultEntry> searchEntries,
                 final int numReferences,
                 @Nullable final List<SearchResultReference> searchReferences)
  {
    this.numEntries    = numEntries;
    this.numReferences = numReferences;

    if (searchEntries == null)
    {
      this.searchEntries = null;
    }
    else
    {
      this.searchEntries = Collections.unmodifiableList(searchEntries);
    }

    if (searchReferences == null)
    {
      this.searchReferences = null;
    }
    else
    {
      this.searchReferences = Collections.unmodifiableList(searchReferences);
    }
  }



  /**
   * Appends a string representation of this LDAP result to the provided buffer.
   *
   * @param  buffer  The buffer to which to append a string representation of
   *                 this LDAP result.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SearchResult(resultCode=");
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

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }
      buffer.append('}');
    }

    if (numEntries >= 0)
    {
      buffer.append(", entriesReturned=");
      buffer.append(numEntries);
    }

    if (numReferences >= 0)
    {
      buffer.append(", referencesReturned=");
      buffer.append(numReferences);
    }

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
