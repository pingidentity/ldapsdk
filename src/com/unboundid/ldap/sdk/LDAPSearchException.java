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



import java.util.List;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an exception that can be thrown if a problem occurs while
 * performing LDAP-related processing.  It includes all of the elements of the
 * {@link SearchResult} object, potentially including entries and references
 * returned before the failure result.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPSearchException
       extends LDAPException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 350230437196125113L;



  // The search result with information from this exception.
  @NotNull private final SearchResult searchResult;



  /**
   * Creates a new LDAP search exception with the provided information.
   *
   * @param  resultCode    The result code for this LDAP search exception.
   * @param  errorMessage  The error message for this LDAP search exception.
   */
  public LDAPSearchException(@NotNull final ResultCode resultCode,
                             @NotNull final String errorMessage)
  {
    super(resultCode, errorMessage);

    searchResult = new SearchResult(-1, resultCode, errorMessage, null,
         StaticUtils.NO_STRINGS, 0, 0, StaticUtils.NO_CONTROLS);
  }



  /**
   * Creates a new LDAP search exception with the provided information.
   *
   * @param  resultCode    The result code for this LDAP search exception.
   * @param  errorMessage  The error message for this LDAP search exception.
   * @param  cause         The underlying exception that triggered this LDAP
   *                       search exception.
   */
  public LDAPSearchException(@NotNull final ResultCode resultCode,
                             @NotNull final String errorMessage,
                             @Nullable final Throwable cause)
  {
    super(resultCode, errorMessage, cause);

    searchResult = new SearchResult(-1, resultCode, errorMessage, null,
         StaticUtils.NO_STRINGS , 0, 0, StaticUtils.NO_CONTROLS);
  }



  /**
   * Creates a new LDAP search exception from the provided exception.
   *
   * @param  ldapException  The LDAP exception with the information to include
   *                        in this LDAP search exception.
   */
  public LDAPSearchException(@NotNull final LDAPException ldapException)
  {
    super(ldapException.getResultCode(), ldapException.getMessage(),
          ldapException.getMatchedDN(), ldapException.getReferralURLs(),
          ldapException.getResponseControls(), ldapException);

    if (ldapException instanceof LDAPSearchException)
    {
      final LDAPSearchException lse = (LDAPSearchException) ldapException;
      searchResult = lse.searchResult;
    }
    else
    {
      searchResult = new SearchResult(-1, ldapException.getResultCode(),
                                      ldapException.getMessage(),
                                      ldapException.getMatchedDN(),
                                      ldapException.getReferralURLs(), 0, 0,
                                      ldapException.getResponseControls());
    }
  }



  /**
   * Creates a new LDAP search exception with the provided result.
   *
   * @param  searchResult  The search result to use to create this LDAP search
   *                       exception.
   */
  public LDAPSearchException(@NotNull final SearchResult searchResult)
  {
    super(searchResult);

    this.searchResult = searchResult;
  }



  /**
   * Retrieves the search result object associated with this LDAP search
   * exception.
   *
   * @return  The search result object associated with this LDAP search
   *          exception.
   */
  @NotNull()
  public SearchResult getSearchResult()
  {
    return searchResult;
  }



  /**
   * Retrieves the number of matching entries returned for the search operation
   * before this exception was thrown.
   *
   * @return  The number of matching entries returned for the search operation
   *          before this exception was thrown.
   */
  public int getEntryCount()
  {
    return searchResult.getEntryCount();
  }



  /**
   * Retrieves the number of search references returned for the search
   * operation before this exception was thrown.
   *
   * @return  The number of search references returned for the search operation
   *          before this exception was thrown.
   */
  public int getReferenceCount()
  {
    return searchResult.getReferenceCount();
  }



  /**
   * Retrieves a list containing the matching entries returned from the search
   * operation before this exception was thrown.  This will only be available if
   * a {@code SearchResultListener} was not used during the search.
   *
   * @return  A list containing the matching entries returned from the search
   *          operation before this exception was thrown, or {@code null} if a
   *          {@code SearchResultListener} was used during the search.
   */
  @Nullable()
  public List<SearchResultEntry> getSearchEntries()
  {
    return searchResult.getSearchEntries();
  }



  /**
   * Retrieves a list containing the search references returned from the search
   * operation before this exception was thrown.  This will only be available if
   * a {@code SearchResultListener} was not used during the search.
   *
   * @return  A list containing the search references returned from the search
   *          operation before this exception was thrown, or {@code null} if a
   *          {@code SearchResultListener} was used during the search.
   */
  @Nullable()
  public List<SearchResultReference> getSearchReferences()
  {
    return searchResult.getSearchReferences();
  }



  /**
   * Creates a new {@code SearchResult} object from this exception.
   *
   * @return  The {@code SearchResult} object created from this exception.
   */
  @Override()
  @NotNull()
  public SearchResult toLDAPResult()
  {
    return searchResult;
  }



  /**
   * Appends a string representation of this LDAP exception to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append a string representation of
   *                 this LDAP exception.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    super.toString(buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer,
                       final boolean includeCause,
                       final boolean includeStackTrace)
  {
    buffer.append("LDAPException(resultCode=");
    buffer.append(getResultCode());
    buffer.append(", numEntries=");
    buffer.append(searchResult.getEntryCount());
    buffer.append(", numReferences=");
    buffer.append(searchResult.getReferenceCount());

    final String errorMessage = getMessage();
    final String diagnosticMessage = getDiagnosticMessage();
    if ((errorMessage != null) && (! errorMessage.equals(diagnosticMessage)))
    {
      buffer.append(", errorMessage='");
      buffer.append(errorMessage);
      buffer.append('\'');
    }

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

    if (includeStackTrace)
    {
      buffer.append(", trace='");
      StaticUtils.getStackTrace(getStackTrace(), buffer);
      buffer.append('\'');
    }

    if (includeCause || includeStackTrace)
    {
      final Throwable cause = getCause();
      if (cause != null)
      {
        buffer.append(", cause=");
        buffer.append(StaticUtils.getExceptionMessage(cause, true,
             includeStackTrace));
      }
    }

    final String ldapSDKVersionString = ", ldapSDKVersion=" +
         Version.NUMERIC_VERSION_STRING + ", revision=" + Version.REVISION_ID;
    if (buffer.indexOf(ldapSDKVersionString) < 0)
    {
      buffer.append(ldapSDKVersionString);
    }

    buffer.append("')");
  }
}
