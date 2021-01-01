/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;



/**
 * This class provides an implementation of an LDAP connection logger that can
 * be used for testing purposes.
 */
public final class TestLDAPConnectionLogger
       extends LDAPConnectionLogger
{
  // Counters used to track each method call.
  private final AtomicInteger abandonRequestCount;
  private final AtomicInteger addRequestCount;
  private final AtomicInteger addResultCount;
  private final AtomicInteger bindResultCount;
  private final AtomicInteger compareRequestCount;
  private final AtomicInteger compareResultCount;
  private final AtomicInteger deleteRequestCount;
  private final AtomicInteger deleteResultCount;
  private final AtomicInteger disconnectCount;
  private final AtomicInteger extendedRequestCount;
  private final AtomicInteger extendedResultCount;
  private final AtomicInteger failedConnectCount;
  private final AtomicInteger intermediateResponseCount;
  private final AtomicInteger modifyDNRequestCount;
  private final AtomicInteger modifyDNResultCount;
  private final AtomicInteger modifyRequestCount;
  private final AtomicInteger modifyResultCount;
  private final AtomicInteger saslBindRequestCount;
  private final AtomicInteger searchRequestCount;
  private final AtomicInteger searchResultDoneCount;
  private final AtomicInteger searchResultEntryCount;
  private final AtomicInteger searchResultReferenceCount;
  private final AtomicInteger simpleBindRequestCount;
  private final AtomicInteger successfulConnectCount;
  private final AtomicInteger unbindRequestCount;



  /**
   * Creates a new instance of this logger.
   */
  public TestLDAPConnectionLogger()
  {
    abandonRequestCount = new AtomicInteger();
    addRequestCount = new AtomicInteger();
    addResultCount = new AtomicInteger();
    bindResultCount = new AtomicInteger();
    compareRequestCount = new AtomicInteger();
    compareResultCount = new AtomicInteger();
    deleteRequestCount = new AtomicInteger();
    deleteResultCount = new AtomicInteger();
    disconnectCount = new AtomicInteger();
    extendedRequestCount = new AtomicInteger();
    extendedResultCount = new AtomicInteger();
    failedConnectCount = new AtomicInteger();
    intermediateResponseCount = new AtomicInteger();
    modifyDNRequestCount = new AtomicInteger();
    modifyDNResultCount = new AtomicInteger();
    modifyRequestCount = new AtomicInteger();
    modifyResultCount = new AtomicInteger();
    saslBindRequestCount = new AtomicInteger();
    searchRequestCount = new AtomicInteger();
    searchResultDoneCount = new AtomicInteger();
    searchResultEntryCount = new AtomicInteger();
    searchResultReferenceCount = new AtomicInteger();
    simpleBindRequestCount = new AtomicInteger();
    successfulConnectCount = new AtomicInteger();
    unbindRequestCount = new AtomicInteger();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logConnect(final LDAPConnectionInfo connectionInfo,
                         final String host, final InetAddress inetAddress,
                         final int port)
  {
    super.logConnect(connectionInfo, host, inetAddress, port);
    successfulConnectCount.incrementAndGet();
  }



  /**
   * Retrieves the number of successful connect log messages.
   *
   * @return  The number of successful connect log messages.
   */
  public int getSuccessfulConnectCount()
  {
    return successfulConnectCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logConnectFailure(final LDAPConnectionInfo connectionInfo,
                                final String host, final int port,
                                final LDAPException connectException)
  {
    super.logConnectFailure(connectionInfo, host, port, connectException);
    failedConnectCount.incrementAndGet();
  }



  /**
   * Retrieves the number of failed connect log messages.
   *
   * @return  The number of failed connect log messages.
   */
  public int getFailedConnectCount()
  {
    return failedConnectCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logDisconnect(final LDAPConnectionInfo connectionInfo,
                            final String host, final int port,
                            final DisconnectType disconnectType,
                            final String disconnectMessage,
                            final Throwable disconnectCause)
  {
    super.logDisconnect(connectionInfo, host, port, disconnectType,
         disconnectMessage, disconnectCause);
    disconnectCount.incrementAndGet();
  }



  /**
   * Retrieves the number of disconnect log messages.
   *
   * @return  The number of disconnect log messages.
   */
  public int getDisconnectCount()
  {
    return disconnectCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logAbandonRequest(final LDAPConnectionInfo connectionInfo,
                                final int messageID,
                                final int messageIDToAbandon,
                                final List<Control> requestControls)
  {
    super.logAbandonRequest(connectionInfo, messageID, messageIDToAbandon,
         requestControls);
    abandonRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of abandon request log messages.
   *
   * @return  The number of abandon request log messages.
   */
  public int getAbandonRequestCount()
  {
    return abandonRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logAddRequest(final LDAPConnectionInfo connectionInfo,
                            final int messageID,
                            final ReadOnlyAddRequest addRequest)
  {
    super.logAddRequest(connectionInfo, messageID, addRequest);
    addRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of add request log messages.
   *
   * @return  The number of add request log messages.
   */
  public int getAddRequestCount()
  {
    return addRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logAddResult(final LDAPConnectionInfo connectionInfo,
                            final int requestMessageID,
                            final LDAPResult addResult)
  {
    super.logAddResult(connectionInfo, requestMessageID, addResult);
    addResultCount.incrementAndGet();
  }



  /**
   * Retrieves the number of add result log messages.
   *
   * @return  The number of add result log messages.
   */
  public int getAddResultCount()
  {
    return addResultCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logBindRequest(final LDAPConnectionInfo connectionInfo,
                             final int messageID,
                             final SimpleBindRequest bindRequest)
  {
    super.logBindRequest(connectionInfo, messageID, bindRequest);
    simpleBindRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of simple bind request log messages.
   *
   * @return  The number of simple bind request log messages.
   */
  public int getSimpleBindRequestCount()
  {
    return simpleBindRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logBindRequest(final LDAPConnectionInfo connectionInfo,
                             final int messageID,
                             final SASLBindRequest bindRequest)
  {
    super.logBindRequest(connectionInfo, messageID, bindRequest);
    saslBindRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of SASL bind request log messages.
   *
   * @return  The number of SASL bind request log messages.
   */
  public int getSASLBindRequestCount()
  {
    return saslBindRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logBindResult(final LDAPConnectionInfo connectionInfo,
                            final int requestMessageID,
                            final BindResult bindResult)
  {
    super.logBindResult(connectionInfo, requestMessageID, bindResult);
    bindResultCount.incrementAndGet();
  }



  /**
   * Retrieves the number of bind result log messages.
   *
   * @return  The number of bind result log messages.
   */
  public int getBindResultCount()
  {
    return bindResultCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompareRequest(final LDAPConnectionInfo connectionInfo,
                                final int messageID,
                                final ReadOnlyCompareRequest compareRequest)
  {
    super.logCompareRequest(connectionInfo, messageID, compareRequest);
    compareRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of compare request log messages.
   *
   * @return  The number of compare request log messages.
   */
  public int getCompareRequestCount()
  {
    return compareRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompareResult(final LDAPConnectionInfo connectionInfo,
                               final int requestMessageID,
                               final LDAPResult compareResult)
  {
    super.logCompareResult(connectionInfo, requestMessageID, compareResult);
    compareResultCount.incrementAndGet();
  }



  /**
   * Retrieves the number of compare result log messages.
   *
   * @return  The number of compare result log messages.
   */
  public int getCompareResultCount()
  {
    return compareResultCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logDeleteRequest(final LDAPConnectionInfo connectionInfo,
                               final int messageID,
                               final ReadOnlyDeleteRequest deleteRequest)
  {
    super.logDeleteRequest(connectionInfo, messageID, deleteRequest);
    deleteRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of delete request log messages.
   *
   * @return  The number of delete request log messages.
   */
  public int getDeleteRequestCount()
  {
    return deleteRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logDeleteResult(final LDAPConnectionInfo connectionInfo,
                              final int requestMessageID,
                              final LDAPResult deleteResult)
  {
    super.logDeleteResult(connectionInfo, requestMessageID, deleteResult);
    deleteResultCount.incrementAndGet();
  }



  /**
   * Retrieves the number of delete result log messages.
   *
   * @return  The number of delete result log messages.
   */
  public int getDeleteResultCount()
  {
    return deleteResultCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logExtendedRequest(final LDAPConnectionInfo connectionInfo,
                                 final int messageID,
                                 final ExtendedRequest extendedRequest)
  {
    super.logExtendedRequest(connectionInfo, messageID, extendedRequest);
    extendedRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of extended request log messages.
   *
   * @return  The number of extended request log messages.
   */
  public int getExtendedRequestCount()
  {
    return extendedRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logExtendedResult(final LDAPConnectionInfo connectionInfo,
                                final int requestMessageID,
                                final ExtendedResult extendedResult)
  {
    super.logExtendedResult(connectionInfo, requestMessageID, extendedResult);
    extendedResultCount.incrementAndGet();
  }



  /**
   * Retrieves the number of extended result log messages.
   *
   * @return  The number of extended result log messages.
   */
  public int getExtendedResultCount()
  {
    return extendedResultCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logModifyRequest(final LDAPConnectionInfo connectionInfo,
                               final int messageID,
                               final ReadOnlyModifyRequest modifyRequest)
  {
    super.logModifyRequest(connectionInfo, messageID, modifyRequest);
    modifyRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of modify request log messages.
   *
   * @return  The number of modify request log messages.
   */
  public int getModifyRequestCount()
  {
    return modifyRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logModifyResult(final LDAPConnectionInfo connectionInfo,
                              final int requestMessageID,
                              final LDAPResult modifyResult)
  {
    super.logModifyResult(connectionInfo, requestMessageID, modifyResult);
    modifyResultCount.incrementAndGet();
  }



  /**
   * Retrieves the number of modify result log messages.
   *
   * @return  The number of modify result log messages.
   */
  public int getModifyResultCount()
  {
    return modifyResultCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logModifyDNRequest(final LDAPConnectionInfo connectionInfo,
                                 final int messageID,
                                 final ReadOnlyModifyDNRequest modifyDNRequest)
  {
    super.logModifyDNRequest(connectionInfo, messageID, modifyDNRequest);
    modifyDNRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of modify DN request log messages.
   *
   * @return  The number of modify DN request log messages.
   */
  public int getModifyDNRequestCount()
  {
    return modifyDNRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logModifyDNResult(final LDAPConnectionInfo connectionInfo,
                                final int requestMessageID,
                                final LDAPResult modifyDNResult)
  {
    super.logModifyDNResult(connectionInfo, requestMessageID, modifyDNResult);
    modifyDNResultCount.incrementAndGet();
  }



  /**
   * Retrieves the number of modify DN result log messages.
   *
   * @return  The number of modify DN result log messages.
   */
  public int getModifyDNResultCount()
  {
    return modifyDNResultCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSearchRequest(final LDAPConnectionInfo connectionInfo,
                               final int messageID,
                               final ReadOnlySearchRequest searchRequest)
  {
    super.logSearchRequest(connectionInfo, messageID, searchRequest);
    searchRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of search request log messages.
   *
   * @return  The number of search request log messages.
   */
  public int getSearchRequestCount()
  {
    return searchRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSearchEntry(final LDAPConnectionInfo connectionInfo,
                             final int requestMessageID,
                             final SearchResultEntry searchEntry)
  {
    super.logSearchEntry(connectionInfo, requestMessageID, searchEntry);
    searchResultEntryCount.incrementAndGet();
  }



  /**
   * Retrieves the number of search result entry log messages.
   *
   * @return  The number of search result entry log messages.
   */
  public int getSearchResultEntryCount()
  {
    return searchResultEntryCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSearchReference(final LDAPConnectionInfo connectionInfo,
                                 final int requestMessageID,
                                 final SearchResultReference searchReference)
  {
    super.logSearchReference(connectionInfo, requestMessageID, searchReference);
    searchResultReferenceCount.incrementAndGet();
  }



  /**
   * Retrieves the number of search result reference log messages.
   *
   * @return  The number of search result reference log messages.
   */
  public int getSearchResultReferenceCount()
  {
    return searchResultReferenceCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSearchResult(final LDAPConnectionInfo connectionInfo,
                               final int requestMessageID,
                               final SearchResult searchResult)
  {
    super.logSearchResult(connectionInfo, requestMessageID, searchResult);
    searchResultDoneCount.incrementAndGet();
  }



  /**
   * Retrieves the number of search result done log messages.
   *
   * @return  The number of search result done log messages.
   */
  public int getSearchResultDoneCount()
  {
    return searchResultDoneCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logUnbindRequest(final LDAPConnectionInfo connectionInfo,
                               final int messageID,
                               final List<Control> requestControls)
  {
    super.logUnbindRequest(connectionInfo, messageID, requestControls);
    unbindRequestCount.incrementAndGet();
  }



  /**
   * Retrieves the number of unbind request log messages.
   *
   * @return  The number of unbind request log messages.
   */
  public int getUnbindRequestCount()
  {
    return unbindRequestCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logIntermediateResponse(final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   final IntermediateResponse intermediateResponse)
  {
    super.logIntermediateResponse(connectionInfo, messageID,
         intermediateResponse);
    intermediateResponseCount.incrementAndGet();
  }



  /**
   * Retrieves the number of intermediate response log messages.
   *
   * @return  The number of intermediate response log messages.
   */
  public int getIntermediateResponseCount()
  {
    return intermediateResponseCount.get();
  }
}
