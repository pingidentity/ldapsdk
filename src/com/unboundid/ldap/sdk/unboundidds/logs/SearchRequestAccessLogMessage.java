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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a search
 * request received from a client.
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
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class SearchRequestAccessLogMessage
       extends OperationRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6751258649156129642L;



  // The typesOnly value for the search request.
  @Nullable private final Boolean typesOnly;

  // The alias dereferencing policy for the search request.
  @Nullable private final DereferencePolicy derefPolicy;

  // The size limit for the search request.
  @Nullable private final Integer sizeLimit;

  // The time limit for the search request.
  @Nullable private final Integer timeLimit;

  // The list of requested attributes for the search request.
  @Nullable private final List<String> requestedAttributes;

  // The scope for the search request.
  @Nullable private final SearchScope scope;

  // The base DN for the search request.
  @Nullable private final String baseDN;

  // The string representation of the filter for the search request.
  @Nullable private final String filter;



  /**
   * Creates a new search request access log message from the provided message
   * string.
   *
   * @param  s  The string to be parsed as a search request access log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public SearchRequestAccessLogMessage(@NotNull final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new search request access log message from the provided log
   * message.
   *
   * @param  m  The log message to be parsed as a search request access log
   *            message.
   */
  public SearchRequestAccessLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    baseDN    = getNamedValue("base");
    filter    = getNamedValue("filter");
    sizeLimit = getNamedValueAsInteger("sizeLimit");
    timeLimit = getNamedValueAsInteger("timeLimit");
    typesOnly = getNamedValueAsBoolean("typesOnly");

    SearchScope ss = null;
    try
    {
      ss = SearchScope.definedValueOf(getNamedValueAsInteger("scope"));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
    scope = ss;

    DereferencePolicy deref = null;
    final String derefStr = getNamedValue("deref");
    if (derefStr != null)
    {
      for (final DereferencePolicy p : DereferencePolicy.values())
      {
        if (p.getName().equalsIgnoreCase(derefStr))
        {
          deref = p;
          break;
        }
      }
    }
    derefPolicy = deref;

    final String attrStr = getNamedValue("attrs");
    if (attrStr == null)
    {
      requestedAttributes = null;
    }
    else if (attrStr.equals("ALL"))
    {
      requestedAttributes = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> attrs = new LinkedList<>();
      final StringTokenizer st = new StringTokenizer(attrStr, ",", false);
      while (st.hasMoreTokens())
      {
        attrs.add(st.nextToken());
      }
      requestedAttributes = Collections.unmodifiableList(attrs);
    }
  }



  /**
   * Retrieves the base DN for the search request.
   *
   * @return  The base DN for the search request, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  public final String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the scope for the search request.
   *
   * @return  The scope for the search request, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  public final SearchScope getScope()
  {
    return scope;
  }



  /**
   * Retrieves a string representation of the filter for the search request.
   *
   * @return  A string representation of the filter for the search request, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final String getFilter()
  {
    return filter;
  }



  /**
   * Retrieves a parsed representation of the filter for the search request.
   *
   * @return  A parsed representation of the filter for the search request, or
   *          {@code null} if it is not included in the log message or the
   *          filter string cannot be parsed as a filter.
   */
  @Nullable()
  public final Filter getParsedFilter()
  {
    try
    {
      if (filter == null)
      {
        return null;
      }
      else
      {
        return Filter.create(filter);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the dereference policy for the search request.
   *
   * @return  The dereference policy for the search request, or {@code null} if
   *          it is not included in the log message or the value cannot be
   *          parsed as a valid {@code DereferencePolicy} value.
   */
  @Nullable()
  public final DereferencePolicy getDereferencePolicy()
  {
    return derefPolicy;
  }



  /**
   * Retrieves the size limit for the search request.
   *
   * @return  The size limit for the search request, or {@code null} if it is
   *          not included in the log message or the value cannot be parsed as
   *          an integer.
   */
  @Nullable()
  public final Integer getSizeLimit()
  {
    return sizeLimit;
  }



  /**
   * Retrieves the time limit for the search request.
   *
   * @return  The time limit for the search request, or {@code null} if it is
   *          not included in the log message or the value cannot be parsed as
   *          an integer.
   */
  @Nullable()
  public final Integer getTimeLimit()
  {
    return timeLimit;
  }



  /**
   * Retrieves the typesOnly value for the search request.
   *
   * @return  {@code true} if only attribute type names should be included in
   *          entries that are returned, {@code false} if both attribute types
   *          and values should be returned, or {@code null} if is not included
   *          in the log message or cannot be parsed as a Boolean.
   */
  @Nullable()
  public final Boolean typesOnly()
  {
    return typesOnly;
  }



  /**
   * Retrieves the list of requested attributes for the search request.
   *
   * @return  The list of requested attributes for the search request, an empty
   *          list if the client did not explicitly request any attributes, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final List<String> getRequestedAttributes()
  {
    return requestedAttributes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final AccessLogOperationType getOperationType()
  {
    return AccessLogOperationType.SEARCH;
  }
}
