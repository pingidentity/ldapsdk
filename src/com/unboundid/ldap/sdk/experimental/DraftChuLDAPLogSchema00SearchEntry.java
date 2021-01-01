/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class represents an entry that holds information about a search
 * operation processed by an LDAP server, as per the specification described in
 * draft-chu-ldap-logschema-00.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftChuLDAPLogSchema00SearchEntry
       extends DraftChuLDAPLogSchema00Entry
{
  /**
   * The name of the attribute used to hold the alias dereference policy.
   */
  @NotNull public static final String ATTR_DEREFERENCE_POLICY =
       "reqDerefAliases";



  /**
   * The name of the attribute used to hold the number of entries returned.
   */
  @NotNull public static final String ATTR_ENTRIES_RETURNED = "reqEntries";



  /**
   * The name of the attribute used to hold the search filter.
   */
  @NotNull public static final String ATTR_FILTER = "reqFilter";



  /**
   * The name of the attribute used to hold a requested attribute.
   */
  @NotNull public static final String ATTR_REQUESTED_ATTRIBUTE = "reqAttr";



  /**
   * The name of the attribute used to hold the search scope.
   */
  @NotNull public static final String ATTR_SCOPE = "reqScope";



  /**
   * The name of the attribute used to hold the requested size limit.
   */
  @NotNull public static final String ATTR_SIZE_LIMIT = "reqSizeLimit";



  /**
   * The name of the attribute used to hold the requested time limit in seconds.
   */
  @NotNull public static final String ATTR_TIME_LIMIT_SECONDS = "reqTimeLimit";



  /**
   * The name of the attribute used to hold the value of the typesOnly flag.
   */
  @NotNull public static final String ATTR_TYPES_ONLY = "reqAttrsOnly";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 948178493925578134L;



  // The types only flag.
  private final boolean typesOnly;

  // The alias dereference policy.
  @NotNull private final DereferencePolicy dereferencePolicy;

  // The search filter.
  @Nullable private final Filter filter;

  // The number of entries returned.
  @Nullable private final Integer entriesReturned;

  // The requested size limit.
  @Nullable private final Integer requestedSizeLimit;

  // The requested time limit in seconds.
  @Nullable private final Integer requestedTimeLimitSeconds;

  // The list of requested attributes.
  @NotNull private final List<String> requestedAttributes;

  // The search scope.
  @NotNull private final SearchScope scope;



  /**
   * Creates a new instance of this search access log entry from the provided
   * entry.
   *
   * @param  entry  The entry used to create this search access log entry.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         search access log entry as per the specification
   *                         contained in draft-chu-ldap-logschema-00.
   */
  public DraftChuLDAPLogSchema00SearchEntry(@NotNull final Entry entry)
         throws LDAPException
  {
    super(entry, OperationType.SEARCH);


    // Get the scope.
    final String scopeStr = entry.getAttributeValue(ATTR_SCOPE);
    if (scopeStr == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_SCOPE));
    }

    final String lowerScope = StaticUtils.toLowerCase(scopeStr);
    if (lowerScope.equals("base"))
    {
      scope = SearchScope.BASE;
    }
    else if (lowerScope.equals("one"))
    {
      scope = SearchScope.ONE;
    }
    else if (lowerScope.equals("sub"))
    {
      scope = SearchScope.SUB;
    }
    else if (lowerScope.equals("subord"))
    {
      scope = SearchScope.SUBORDINATE_SUBTREE;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_SEARCH_SCOPE_ERROR.get(entry.getDN(),
                ATTR_SCOPE, scopeStr));
    }


    // Get the dereference policy.
    final String derefStr = entry.getAttributeValue(ATTR_DEREFERENCE_POLICY);
    if (derefStr == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_DEREFERENCE_POLICY));
    }

    final String lowerDeref = StaticUtils.toLowerCase(derefStr);
    if (lowerDeref.equals("never"))
    {
      dereferencePolicy = DereferencePolicy.NEVER;
    }
    else if (lowerDeref.equals("searching"))
    {
      dereferencePolicy = DereferencePolicy.SEARCHING;
    }
    else if (lowerDeref.equals("finding"))
    {
      dereferencePolicy = DereferencePolicy.FINDING;
    }
    else if (lowerDeref.equals("always"))
    {
      dereferencePolicy = DereferencePolicy.ALWAYS;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_SEARCH_DEREF_ERROR.get(entry.getDN(),
                ATTR_DEREFERENCE_POLICY, derefStr));
    }


    // Get the typesOnly flag.
    final String typesOnlyStr = entry.getAttributeValue(ATTR_TYPES_ONLY);
    if (typesOnlyStr == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_TYPES_ONLY));
    }

    final String lowerTypesOnly = StaticUtils.toLowerCase(typesOnlyStr);
    if (lowerTypesOnly.equals("true"))
    {
      typesOnly = true;
    }
    else if (lowerTypesOnly.equals("false"))
    {
      typesOnly = false;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_SEARCH_TYPES_ONLY_ERROR.get(entry.getDN(),
                ATTR_TYPES_ONLY, typesOnlyStr));
    }


    // Get the filter.  For some strange reason, this is allowed to be
    // undefined.
    final String filterStr = entry.getAttributeValue(ATTR_FILTER);
    if (filterStr == null)
    {
      filter = null;
    }
    else
    {
      try
      {
        filter = Filter.create(filterStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_SEARCH_FILTER_ERROR.get(entry.getDN(),
                  ATTR_FILTER, filterStr),
             e);
      }
    }


    // Get the set of requested attributes.
    final String[] requestedAttrArray =
         entry.getAttributeValues(ATTR_REQUESTED_ATTRIBUTE);
    if ((requestedAttrArray == null) || (requestedAttrArray.length == 0))
    {
      requestedAttributes = Collections.emptyList();
    }
    else
    {
      requestedAttributes =
           Collections.unmodifiableList(StaticUtils.toList(requestedAttrArray));
    }


    // Get the requested size limit.
    final String sizeLimitStr = entry.getAttributeValue(ATTR_SIZE_LIMIT);
    if (sizeLimitStr == null)
    {
      requestedSizeLimit = null;
    }
    else
    {
      try
      {
        requestedSizeLimit = Integer.parseInt(sizeLimitStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_SEARCH_INT_ERROR.get(entry.getDN(),
                  ATTR_SIZE_LIMIT, sizeLimitStr),
             e);
      }
    }


    // Get the requested time limit.
    final String timeLimitStr =
         entry.getAttributeValue(ATTR_TIME_LIMIT_SECONDS);
    if (timeLimitStr == null)
    {
      requestedTimeLimitSeconds = null;
    }
    else
    {
      try
      {
        requestedTimeLimitSeconds = Integer.parseInt(timeLimitStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_SEARCH_INT_ERROR.get(entry.getDN(),
                  ATTR_TIME_LIMIT_SECONDS, timeLimitStr),
             e);
      }
    }


    // Get the number of entries returned.
    final String entriesReturnedStr =
         entry.getAttributeValue(ATTR_ENTRIES_RETURNED);
    if (entriesReturnedStr == null)
    {
      entriesReturned = null;
    }
    else
    {
      try
      {
        entriesReturned = Integer.parseInt(entriesReturnedStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_SEARCH_INT_ERROR.get(entry.getDN(),
                  ATTR_ENTRIES_RETURNED, entriesReturnedStr),
             e);
      }
    }
  }



  /**
   * Retrieves the scope for the search request described by this search access
   * log entry.
   *
   * @return  The scope for the search request described by this search access
   *          log entry.
   */
  @NotNull()
  public SearchScope getScope()
  {
    return scope;
  }



  /**
   * Retrieves the alias dereference policy for the search request described by
   * this search access log entry.
   *
   * @return  The alias dereference policy for the search request described by
   *          this search access log entry.
   */
  @NotNull()
  public DereferencePolicy getDereferencePolicy()
  {
    return dereferencePolicy;
  }



  /**
   * Retrieves the value of the typesOnly flag for the search request described
   * by this search access log entry.
   *
   * @return  The value of the typesOnly flag for the search request described
   *          by this search access log entry.
   */
  public boolean typesOnly()
  {
    return typesOnly;
  }



  /**
   * Retrieves the filter for the search request described by this search access
   * log entry, if available.
   *
   * @return  The filter for the search request described by this search access
   *          log entry, or {@code null} if no filter was included in the access
   *          log entry.
   */
  @Nullable()
  public Filter getFilter()
  {
    return filter;
  }



  /**
   * Retrieves the requested size limit for the search request described by this
   * search access log entry, if available.
   *
   * @return  The requested size limit for the search request described by this
   *          search access log entry, or {@code null} if no size limit was
   *          included in the access log entry.
   */
  @Nullable()
  public Integer getRequestedSizeLimit()
  {
    return requestedSizeLimit;
  }



  /**
   * Retrieves the requested time limit (in seconds) for the search request
   * described by this search access log entry, if available.
   *
   * @return  The requested time limit (in seconds) for the search request
   *          described by this search access log entry, or {@code null} if no
   *          time limit was included in the access log entry.
   */
  @Nullable()
  public Integer getRequestedTimeLimitSeconds()
  {
    return requestedTimeLimitSeconds;
  }



  /**
   * Retrieves the requested attributes for the search request described by this
   * search access log entry, if available.
   *
   * @return  The requested attributes for the search request described by this
   *          search access log entry, or an empty list if no requested
   *          attributes were included in the access log entry.
   */
  @NotNull()
  public List<String> getRequestedAttributes()
  {
    return requestedAttributes;
  }



  /**
   * Retrieves the number of entries returned to the client in response to the
   * search request described by this search access log entry, if available.
   *
   * @return  The number of entries returned to the client in response to the
   *          search request described by this search access log entry, or
   *          {@code null} if the number of entries returned was not included in
   *          the access log entry.
   */
  @Nullable()
  public Integer getEntriesReturned()
  {
    return entriesReturned;
  }



  /**
   * Retrieves a {@code SearchRequest} created from this search access log
   * entry.  If the size limit or time limit was not present in the entry, a
   * default of zero will be used.  If the filter was not present in the entry,
   * a default of "(objectClass=*)" will be used.
   *
   * @return  The {@code SearchRequest} created from this search access log
   *          entry.
   */
  @NotNull()
  public SearchRequest toSearchRequest()
  {
    final int sizeLimit =
         ((requestedSizeLimit == null)
              ? 0
              : requestedSizeLimit);
    final int timeLimit =
         ((requestedTimeLimitSeconds == null)
              ? 0
              : requestedTimeLimitSeconds);
    final Filter f =
         ((filter == null)
              ? Filter.createPresenceFilter("objectClass")
              : filter);

    final String[] attrArray =
         requestedAttributes.toArray(StaticUtils.NO_STRINGS);

    final SearchRequest searchRequest = new SearchRequest(getTargetEntryDN(),
         scope, dereferencePolicy, sizeLimit, timeLimit, typesOnly, f,
         attrArray);
    searchRequest.setControls(getRequestControlArray());
    return searchRequest;
  }
}
