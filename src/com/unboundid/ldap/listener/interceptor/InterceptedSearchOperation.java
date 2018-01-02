/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import com.unboundid.ldap.listener.LDAPListenerClientConnection;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ReadOnlySearchRequest;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used in the course of
 * processing a search operation via the {@link InMemoryOperationInterceptor}
 * API.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
final class InterceptedSearchOperation
      extends InterceptedOperation
      implements InMemoryInterceptedSearchRequest,
                 InMemoryInterceptedSearchResult
{
  // The search request for this operation.
  private SearchRequest searchRequest;

  // The search result for this operation.
  private LDAPResult searchResult;



  /**
   * Creates a new instance of this search operation object with the provided
   * information.
   *
   * @param  clientConnection  The client connection with which this operation
   *                           is associated.
   * @param  messageID         The message ID for the associated operation.
   * @param  requestOp         The search request protocol op in the request
   *                           received from the client.
   * @param  requestControls   The controls in the request received from the
   *                           client.
   */
  InterceptedSearchOperation(
       final LDAPListenerClientConnection clientConnection, final int messageID,
       final SearchRequestProtocolOp requestOp,
       final Control... requestControls)
  {
    super(clientConnection, messageID);

    searchRequest = requestOp.toSearchRequest(requestControls);
    searchResult  = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ReadOnlySearchRequest getRequest()
  {
    return searchRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setRequest(final SearchRequest searchRequest)
  {
    this.searchRequest = searchRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult getResult()
  {
    return searchResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setResult(final LDAPResult searchResult)
  {
    this.searchResult = searchResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void sendSearchEntry(final Entry entry)
         throws LDAPException
  {
    final Control[] controls;
    if (entry instanceof SearchResultEntry)
    {
      controls = ((SearchResultEntry) entry).getControls();
    }
    else
    {
      controls = null;
    }

    getClientConnection().sendSearchResultEntry(getMessageID(),
         new SearchResultEntryProtocolOp(entry), controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void sendSearchReference(final SearchResultReference reference)
         throws LDAPException
  {
    getClientConnection().sendSearchResultReference(getMessageID(),
         new SearchResultReferenceProtocolOp(reference),
         reference.getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("InterceptedSearchOperation(");
    appendCommonToString(buffer);
    buffer.append(", request=");
    buffer.append(searchRequest);
    buffer.append(", result=");
    buffer.append(searchResult);
    buffer.append(')');
  }
}
