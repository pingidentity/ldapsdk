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

import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be used to log operations processed on an
 * LDAP connection.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class LDAPConnectionLogger
{
  /**
   * Performs any appropriate log processing that may be needed when a
   * connection is established.
   *
   * @param  connectionInfo  Information about the connection that has been
   *                         established.  It will not be {@code null}.
   * @param  host            The string representation of the address to which
   *                         the connection was established.  It will not be
   *                         {@code null}.
   * @param  inetAddress     The {@code InetAddress} representation of the
   *                         address to which the connection was established.
   *                         It will not be {@code null}.
   * @param  port            The port to which the connection was established.
   */
  public void logConnect(@NotNull final LDAPConnectionInfo connectionInfo,
                         @NotNull final String host,
                         @NotNull final InetAddress inetAddress,
                         final int port)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when an attempt
   * to establish a connection fails.
   *
   * @param  connectionInfo    Information about the connection that has been
   *                           established.  It will not be {@code null}.
   * @param  host              The string representation of the address to which
   *                           the connection was established.  It will not be
   *                           {@code null}.
   * @param  port              The port to which the connection was established.
   * @param  connectException  An exception with information about the failed
   *                           connection attempt.  It will not be
   *                           {@code null}.
   */
  public void logConnectFailure(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   @NotNull final String host, final int port,
                   @NotNull final LDAPException connectException)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a
   * connection is disconnected, regardless of whether the disconnect was
   * initiated by the client or server.
   *
   * @param  connectionInfo     Information about the connection that has been
   *                            disconnected.  It will not be {@code null}.
   * @param  host               The string representation of the address to
   *                            which the connection was established.  It will
   *                            not be {@code null}.
   * @param  port               The port to which the connection was
   *                            established.
   * @param  disconnectType     The general reason for the disconnect.  It will
   *                            not be {@code null}.
   * @param  disconnectMessage  A human-readable message with additional
   *                            information about the disconnect.  It may be
   *                            {@code null} if no additional information is
   *                            available.
   * @param  disconnectCause    A {@code Throwable} that may have been
   *                            responsible for the disconnect.  It may be
   *                            {@code null} if the disconnect was not caused by
   *                            an exception or error.
   */
  public void logDisconnect(@NotNull final LDAPConnectionInfo connectionInfo,
                   @NotNull final String host, final int port,
                   @NotNull final DisconnectType disconnectType,
                   @Nullable final String disconnectMessage,
                   @Nullable final Throwable disconnectCause)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when an abandon
   * request is sent over a connection.
   *
   * @param  connectionInfo      Information about the connection that will be
   *                             used to send the abandon request.  It will not
   *                             be {@code null}.
   * @param  messageID           The LDAP message ID for the abandon request
   *                             that is to be sent.
   * @param  messageIDToAbandon  The LDAP message ID for the request that is to
   *                             be abandoned.
   * @param  requestControls     The list of controls included in the abandon
   *                             request.
   */
  public void logAbandonRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   final int messageIDToAbandon,
                    @NotNull final List<Control> requestControls)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when an add
   * request is sent over a connection.
   *
   * @param  connectionInfo  Information about the connection that will be used
   *                         to send the add request.  It will not be
   *                         {@code null}.
   * @param  messageID       The LDAP message ID for the add request that is to
   *                         be sent.
   * @param  addRequest      The add request that is to be sent.  This is
   *                         provided only for informational purposes, and it
   *                         must not be altered in any way.  It will not be
   *                         {@code null}.
   */
  public void logAddRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                            final int messageID,
                            @NotNull final ReadOnlyAddRequest addRequest)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when an add
   * response is received over a connection, or when an exception is caught
   * while waiting for or attempting to decode an add response.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           add request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated add
   *                           request.
   * @param  addResult         The add result that was received from the server,
   *                           or that was generated from an exception.  It will
   *                           not be {@code null}.
   */
  public void logAddResult(@NotNull final LDAPConnectionInfo connectionInfo,
                           final int requestMessageID,
                           @NotNull final LDAPResult addResult)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a simple
   * bind request is sent over a connection.
   *
   * @param  connectionInfo  Information about the connection that will be used
   *                         to send the bind request.  It will not be
   *                         {@code null}.
   * @param  messageID       The LDAP message ID for the add request that is to
   *                         be sent.
   * @param  bindRequest     The bind request that is to be sent.  This is
   *                         provided only for informational purposes, and it
   *                         must not be altered in any way.  It will not be
   *                         {@code null}.
   */
  public void logBindRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                             final int messageID,
                             @NotNull final SimpleBindRequest bindRequest)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a SASL
   * bind request is sent over a connection.
   *
   * @param  connectionInfo  Information about the connection that will be used
   *                         to send the bind request.  It will not be
   *                         {@code null}.
   * @param  messageID       The LDAP message ID for the add request that is to
   *                         be sent.
   * @param  bindRequest     The bind request that is to be sent.  This is
   *                         provided only for informational purposes, and it
   *                         must not be altered in any way.  It will not be
   *                         {@code null}.
   */
  public void logBindRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                             final int messageID,
                             @NotNull final SASLBindRequest bindRequest)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a bind
   * response is received over a connection, or when an exception is caught
   * while waiting for or attempting to decode a bind response.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           add request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated add
   *                           request.
   * @param  bindResult        The bind result that was received from the
   *                           server, or that was generated from an exception.
   *                           It will not be {@code null}.
   */
  public void logBindResult(@NotNull final LDAPConnectionInfo connectionInfo,
                            final int requestMessageID,
                            @NotNull final BindResult bindResult)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a compare
   * request is sent over a connection.
   *
   * @param  connectionInfo  Information about the connection that will be used
   *                         to send the compare request.  It will not be
   *                         {@code null}.
   * @param  messageID       The LDAP message ID for the compare request that is
   *                         to be sent.
   * @param  compareRequest  The compare request that is to be sent.  This is
   *                         provided only for informational purposes, and it
   *                         must not be altered in any way.  It will not be
   *                         {@code null}.
   */
  public void logCompareRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlyCompareRequest compareRequest)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a compare
   * response is received over a connection, or when an exception is caught
   * while waiting for or attempting to decode a compare response.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           compare request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated compare
   *                           request.
   * @param  compareResult     The compare result that was received from the
   *                           server, or that was generated from an exception.
   *                           It will not be {@code null}.
   */
  public void logCompareResult(@NotNull final LDAPConnectionInfo connectionInfo,
                               final int requestMessageID,
                               @NotNull final LDAPResult compareResult)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a delete
   * request is sent over a connection.
   *
   * @param  connectionInfo  Information about the connection that will be used
   *                         to send the delete request.  It will not be
   *                         {@code null}.
   * @param  messageID       The LDAP message ID for the delete request that is
   *                         to be sent.
   * @param  deleteRequest   The delete request that is to be sent.  This is
   *                         provided only for informational purposes, and it
   *                         must not be altered in any way.  It will not be
   *                         {@code null}.
   */
  public void logDeleteRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlyDeleteRequest deleteRequest)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a delete
   * response is received over a connection, or when an exception is caught
   * while waiting for or attempting to decode a delete response.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           delete request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated delete
   *                           request.
   * @param  deleteResult      The delete result that was received from the
   *                           server, or that was generated from an exception.
   *                           It will not be {@code null}.
   */
  public void logDeleteResult(
                    @NotNull final LDAPConnectionInfo connectionInfo,
                    final int requestMessageID,
                    @NotNull final LDAPResult deleteResult)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when an extended
   * request is sent over a connection.
   *
   * @param  connectionInfo   Information about the connection that will be used
   *                          to send the extended request.  It will not be
   *                          {@code null}.
   * @param  messageID        The LDAP message ID for the extended request that
   *                          is to be sent.
   * @param  extendedRequest  The extended request that is to be sent.  This is
   *                          provided only for informational purposes, and it
   *                          must not be altered in any way.  It will not be
   *                          {@code null}.
   */
  public void logExtendedRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ExtendedRequest extendedRequest)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when an extended
   * response is received over a connection, or when an exception is caught
   * while waiting for or attempting to decode an extended response.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           extended request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated extended
   *                           request.
   * @param  extendedResult    The extended result that was received from the
   *                           server, or that was generated from an exception.
   *                           It will not be {@code null}.
   */
  public void logExtendedResult(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int requestMessageID,
                   @NotNull final ExtendedResult extendedResult)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a modify
   * request is sent over a connection.
   *
   * @param  connectionInfo  Information about the connection that will be used
   *                         to send the modify request.  It will not be
   *                         {@code null}.
   * @param  messageID       The LDAP message ID for the modify request that is
   *                         to be sent.
   * @param  modifyRequest   The modify request that is to be sent.  This is
   *                         provided only for informational purposes, and it
   *                         must not be altered in any way.  It will not be
   *                         {@code null}.
   */
  public void logModifyRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlyModifyRequest modifyRequest)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a modify
   * response is received over a connection, or when an exception is caught
   * while waiting for or attempting to decode a modify response.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           modify request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated modify
   *                           request.
   * @param  modifyResult      The modify result that was received from the
   *                           server, or that was generated from an exception.
   *                           It will not be {@code null}.
   */
  public void logModifyResult(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int requestMessageID,
                   @NotNull final LDAPResult modifyResult)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a modify DN
   * request is sent over a connection.
   *
   * @param  connectionInfo   Information about the connection that will be used
   *                          to send the modify DN request.  It will not be
   *                          {@code null}.
   * @param  messageID        The LDAP message ID for the modify DN request that
   *                          is to be sent.
   * @param  modifyDNRequest  The modify DN request that is to be sent.  This is
   *                          provided only for informational purposes, and it
   *                          must not be altered in any way.  It will not be
   *                          {@code null}.
   */
  public void logModifyDNRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlyModifyDNRequest modifyDNRequest)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a modify DN
   * response is received over a connection, or when an exception is caught
   * while waiting for or attempting to decode a modify DN response.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           modify DN request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated modify DN
   *                           request.
   * @param  modifyDNResult    The modify DN result that was received from the
   *                           server, or that was generated from an exception.
   *                           It will not be {@code null}.
   */
  public void logModifyDNResult(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int requestMessageID,
                   @NotNull final LDAPResult modifyDNResult)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a search
   * request is sent over a connection.
   *
   * @param  connectionInfo  Information about the connection that will be used
   *                         to send the search request.  It will not be
   *                         {@code null}.
   * @param  messageID       The LDAP message ID for the search request that is
   *                         to be sent.
   * @param  searchRequest   The search request that is to be sent.  This is
   *                         provided only for informational purposes, and it
   *                         must not be altered in any way.  It will not be
   *                         {@code null}.
   */
  public void logSearchRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlySearchRequest searchRequest)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a search
   * result entry response is received over a connection.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           search request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated search
   *                           request.
   * @param  searchEntry       The search result entry that was received from
   *                           the server.  It will not be {@code null}.
   */
  public void logSearchEntry(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int requestMessageID,
                   @NotNull final SearchResultEntry searchEntry)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a search
   * result reference response is received over a connection.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           search request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated search
   *                           request.
   * @param  searchReference   The search result reference that was received
   *                           from the server.  It will not be {@code null}.
   */
  public void logSearchReference(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int requestMessageID,
                   @NotNull final SearchResultReference searchReference)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when a search
   * result done response is received over a connection, or when an exception is
   * caught while waiting for or attempting to decode a search result.
   *
   * @param  connectionInfo    Information about the connection used to send the
   *                           search request.  It will not be {@code null}.
   * @param  requestMessageID  The LDAP message ID for the associated search
   *                           request.
   * @param  searchResult      The search result that was received from the
   *                           server, or that was generated from an exception.
   *                           It will not be {@code null}.
   */
  public void logSearchResult(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int requestMessageID,
                   @NotNull final SearchResult searchResult)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when an unbind
   * request is sent over a connection.
   *
   * @param  connectionInfo      Information about the connection that will be
   *                             used to send the unbind request.  It will not
   *                             be {@code null}.
   * @param  messageID           The LDAP message ID for the unbind request
   *                             that is to be sent.
   * @param  requestControls     The list of controls included in the unbind
   *                             request.
   */
  public void logUnbindRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final List<Control> requestControls)
  {
    // No action will be taken by default.
  }



  /**
   * Performs any appropriate log processing that may be needed when an
   * intermediate response message is received over a connection.
   *
   * @param  connectionInfo        Information about the connection over which
   *                               the intermediate response was received.  It
   *                               will not be {@code null}.
   * @param  messageID             The LDAP message ID for the intermediate
   *                               response message.
   * @param  intermediateResponse  The intermediate response message that was
   *                               received.
   */
  public void logIntermediateResponse(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final IntermediateResponse intermediateResponse)
  {
    // No action will be taken by default.
  }
}
