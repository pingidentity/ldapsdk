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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a very simple LDAP listener request handler
 * implementation that simply returns a canned response to the client for each
 * type of operation.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CannedResponseRequestHandler
       extends LDAPListenerRequestHandler
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6199105854736880833L;



  // The protocol ops that will be used in responses.
  @NotNull private final AddResponseProtocolOp addResponseProtocolOp;
  @NotNull private final BindResponseProtocolOp bindResponseProtocolOp;
  @NotNull private final CompareResponseProtocolOp compareResponseProtocolOp;
  @NotNull private final DeleteResponseProtocolOp deleteResponseProtocolOp;
  @NotNull private final ExtendedResponseProtocolOp extendedResponseProtocolOp;
  @NotNull private final ModifyResponseProtocolOp modifyResponseProtocolOp;
  @NotNull private final ModifyDNResponseProtocolOp modifyDNResponseProtocolOp;
  @NotNull private final List<SearchResultEntryProtocolOp>
       searchEntryProtocolOps;
  @NotNull private final List<SearchResultReferenceProtocolOp>
       searchReferenceProtocolOps;
  @NotNull private final SearchResultDoneProtocolOp searchResultDoneProtocolOp;

  // The connection that will be used to communicate with the client.
  @Nullable private final LDAPListenerClientConnection clientConnection;



  /**
   * Creates a new instance of this canned response request handler that will
   * immediately return a "SUCCESS" response to any request that is received.
   */
  public CannedResponseRequestHandler()
  {
    this(ResultCode.SUCCESS, null, null, null);
  }



  /**
   * Creates a new instance of this canned response request handler that will
   * immediately return a response with the provided information to any request
   * that is received.
   *
   * @param  resultCode         The result code to use for the responses.  It
   *                            must not be {@code null}.
   * @param  matchedDN          The matched DN to use for the responses.  It may
   *                            be {@code null} if no matched DN should be
   *                            included.
   * @param  diagnosticMessage  The diagnostic message to use for the responses.
   *                            It may be {@code null} if no diagnostic message
   *                            should be included.
   * @param  referralURLs       The referral URLs to use for the responses.  It
   *                            may be empty or {@code null} if no referral URLs
   *                            should be included.
   */
  public CannedResponseRequestHandler(@NotNull final ResultCode resultCode,
                                      @Nullable final String matchedDN,
                                      @Nullable final String diagnosticMessage,
                                      @Nullable final List<String> referralURLs)
  {
    this(resultCode, matchedDN, diagnosticMessage, referralURLs, null, null);
  }



  /**
   * Creates a new instance of this canned response request handler that will
   * immediately return a response with the provided information to any request
   * that is received.
   *
   * @param  resultCode         The result code to use for the responses.  It
   *                            must not be {@code null}.
   * @param  matchedDN          The matched DN to use for the responses.  It may
   *                            be {@code null} if no matched DN should be
   *                            included.
   * @param  diagnosticMessage  The diagnostic message to use for the responses.
   *                            It may be {@code null} if no diagnostic message
   *                            should be included.
   * @param  referralURLs       The referral URLs to use for the responses.  It
   *                            may be empty or {@code null} if no referral URLs
   *                            should be included.
   * @param  searchEntries      The set of search result entries that should be
   *                            returned for every search.  It may be
   *                            {@code null} or empty if no entries are
   *                            required.
   * @param  searchReferences   The set of search result references that should
   *                            be returned for every search.  It may be
   *                            {@code null} or empty if no references are
   *                            required.
   */
  public CannedResponseRequestHandler(@NotNull final ResultCode resultCode,
       @Nullable final String matchedDN,
       @Nullable final String diagnosticMessage,
       @Nullable final List<String> referralURLs,
       @Nullable final Collection<? extends Entry> searchEntries,
       @Nullable final Collection<SearchResultReference> searchReferences)
  {
    Validator.ensureNotNull(resultCode);

    clientConnection = null;

    final int rc = resultCode.intValue();
    addResponseProtocolOp = new AddResponseProtocolOp(rc, matchedDN,
         diagnosticMessage, referralURLs);
    bindResponseProtocolOp = new BindResponseProtocolOp(rc, matchedDN,
         diagnosticMessage, referralURLs, null);
    compareResponseProtocolOp = new CompareResponseProtocolOp(rc, matchedDN,
         diagnosticMessage, referralURLs);
    deleteResponseProtocolOp = new DeleteResponseProtocolOp(rc, matchedDN,
         diagnosticMessage, referralURLs);
    extendedResponseProtocolOp = new ExtendedResponseProtocolOp(rc, matchedDN,
         diagnosticMessage, referralURLs, null, null);
    modifyResponseProtocolOp = new ModifyResponseProtocolOp(rc, matchedDN,
         diagnosticMessage, referralURLs);
    modifyDNResponseProtocolOp = new ModifyDNResponseProtocolOp(rc, matchedDN,
         diagnosticMessage, referralURLs);
    searchResultDoneProtocolOp = new SearchResultDoneProtocolOp(rc, matchedDN,
         diagnosticMessage, referralURLs);

    if ((searchEntries == null) || searchEntries.isEmpty())
    {
      searchEntryProtocolOps = Collections.emptyList();
    }
    else
    {
      final ArrayList<SearchResultEntryProtocolOp> l =
           new ArrayList<>(searchEntries.size());
      for (final Entry e : searchEntries)
      {
        l.add(new SearchResultEntryProtocolOp(e));
      }

      searchEntryProtocolOps = Collections.unmodifiableList(l);
    }

    if ((searchReferences == null) || searchReferences.isEmpty())
    {
      searchReferenceProtocolOps = Collections.emptyList();
    }
    else
    {
      final ArrayList<SearchResultReferenceProtocolOp> l =
           new ArrayList<>(searchReferences.size());
      for (final SearchResultReference r : searchReferences)
      {
        l.add(new SearchResultReferenceProtocolOp(r));
      }

      searchReferenceProtocolOps = Collections.unmodifiableList(l);
    }
  }



  /**
   * Creates a new instance of this canned response request handler using the
   * information of the provided handler and the given client connection.
   *
   * @param  h  The request handler from which to take the canned responses.
   * @param  c  The connection to use to communicate with the client.
   */
  private CannedResponseRequestHandler(
               @NotNull final CannedResponseRequestHandler h,
               @NotNull final LDAPListenerClientConnection c)
  {
    addResponseProtocolOp      = h.addResponseProtocolOp;
    bindResponseProtocolOp     = h.bindResponseProtocolOp;
    compareResponseProtocolOp  = h.compareResponseProtocolOp;
    deleteResponseProtocolOp   = h.deleteResponseProtocolOp;
    extendedResponseProtocolOp = h.extendedResponseProtocolOp;
    modifyResponseProtocolOp   = h.modifyResponseProtocolOp;
    modifyDNResponseProtocolOp = h.modifyDNResponseProtocolOp;
    searchEntryProtocolOps     = h.searchEntryProtocolOps;
    searchReferenceProtocolOps = h.searchReferenceProtocolOps;
    searchResultDoneProtocolOp = h.searchResultDoneProtocolOp;

    clientConnection = c;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public CannedResponseRequestHandler newInstance(
              @NotNull final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    return new CannedResponseRequestHandler(this, connection);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processAddRequest(final int messageID,
                          @NotNull final AddRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    return new LDAPMessage(messageID, addResponseProtocolOp,
         Collections.<Control>emptyList());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processBindRequest(final int messageID,
                          @NotNull final BindRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    return new LDAPMessage(messageID, bindResponseProtocolOp,
         Collections.<Control>emptyList());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processCompareRequest(final int messageID,
                          @NotNull final CompareRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    return new LDAPMessage(messageID, compareResponseProtocolOp,
         Collections.<Control>emptyList());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processDeleteRequest(final int messageID,
                          @NotNull final DeleteRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    return new LDAPMessage(messageID, deleteResponseProtocolOp,
         Collections.<Control>emptyList());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processExtendedRequest(final int messageID,
                          @NotNull final ExtendedRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    return new LDAPMessage(messageID, extendedResponseProtocolOp,
         Collections.<Control>emptyList());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyRequest(final int messageID,
                          @NotNull final ModifyRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    return new LDAPMessage(messageID, modifyResponseProtocolOp,
         Collections.<Control>emptyList());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyDNRequest(final int messageID,
                          @NotNull final ModifyDNRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    return new LDAPMessage(messageID, modifyDNResponseProtocolOp,
         Collections.<Control>emptyList());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processSearchRequest(final int messageID,
                          @NotNull final SearchRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    for (final SearchResultEntryProtocolOp e : searchEntryProtocolOps)
    {
      try
      {
        clientConnection.sendSearchResultEntry(messageID, e);
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
      }
    }

    for (final SearchResultReferenceProtocolOp r : searchReferenceProtocolOps)
    {
      try
      {
        clientConnection.sendSearchResultReference(messageID, r);
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
      }
    }

    return new LDAPMessage(messageID, searchResultDoneProtocolOp,
         Collections.<Control>emptyList());
  }
}
