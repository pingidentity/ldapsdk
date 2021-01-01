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
package com.unboundid.ldap.listener;



import java.util.Arrays;

import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;



/**
 * This class provides an implementation of a search result listener that will
 * be used by the {@link ProxyRequestHandler} class in the course of returning
 * entries to the client.
 */
final class ProxySearchResultListener
      implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1581507251328572490L;



  // The message ID for the associated search request.
  private final int messageID;

  // The client connection that will be used to return the results.
  @NotNull private final LDAPListenerClientConnection clientConnection;



  /**
   * Creates a new proxy search result listener with the provided information.
   *
   * @param  clientConnection  The client connection to which the results will
   *                           be sent.
   * @param  messageID         The message ID that will be used for any response
   *                           messages returned to the client.
   */
  ProxySearchResultListener(
       @NotNull final LDAPListenerClientConnection clientConnection,
       final int messageID)
  {
    this.clientConnection = clientConnection;
    this.messageID        = messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
    try
    {
      clientConnection.sendSearchResultEntry(messageID, searchEntry,
           searchEntry.getControls());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    try
    {
      final SearchResultReferenceProtocolOp searchResultReferenceProtocolOp =
           new SearchResultReferenceProtocolOp(Arrays.asList(
                searchReference.getReferralURLs()));

      clientConnection.sendSearchResultReference(messageID,
           searchResultReferenceProtocolOp, searchReference.getControls());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }
}
