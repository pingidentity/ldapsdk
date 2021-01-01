/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import java.util.Collection;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides an implementation of an {@link FullLDAPInterface} that
 * provides a basic means of mocking an {@link LDAPConnection} (which itself is
 * not easily mockable because it is final, as a commonly recognized best
 * practice for APIs).
 */
@Extensible()
@ThreadSafety(level= ThreadSafetyLevel.MOSTLY_THREADSAFE)
public class MockableLDAPConnection
       implements FullLDAPInterface
{
  // The wrapped connection.
  @NotNull private final LDAPConnection connection;



  /**
   * Creates a new mockable LDAP connection from the provided connection.  All
   * non-overridden methods will simply be delegated to the provided connection.
   *
   * @param  connection  The connection to which all non-overridden method calls
   *                     will be delegated.
   */
  public MockableLDAPConnection(@NotNull final LDAPConnection connection)
  {
    Validator.ensureNotNullWithMessage(connection,
         "MockableLDAPConnection.connection must not be null.");

    this.connection = connection;
  }



  /**
   * Retrieves the connection that has been wrapped by this mockable LDAP
   * connection, and to which all non-overridden method calls will be delegated.
   *
   * @return  The connection that has been wrapped by this mockable LDAP
   *          connection, and to which all non-overridden method calls will be
   *          delegated.
   */
  @NotNull()
  public final LDAPConnection getWrappedConnection()
  {
    return connection;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close()
  {
    connection.close();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public RootDSE getRootDSE()
         throws LDAPException
  {
    return connection.getRootDSE();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Schema getSchema()
         throws LDAPException
  {
    return connection.getSchema();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Schema getSchema(@Nullable final String entryDN)
         throws LDAPException
  {
    return connection.getSchema(entryDN);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public SearchResultEntry getEntry(@NotNull final String dn)
         throws LDAPException
  {
    return connection.getEntry(dn);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public SearchResultEntry getEntry(@NotNull final String dn,
                                    @Nullable final String... attributes)
         throws LDAPException
  {
    return connection.getEntry(dn, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final String dn,
                        @NotNull final Attribute... attributes)
         throws LDAPException
  {
    return connection.add(dn, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final String dn,
                        @NotNull final Collection<Attribute> attributes)
         throws LDAPException
  {
    return connection.add(dn, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final Entry entry)
         throws LDAPException
  {
    return connection.add(entry);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final String... ldifLines)
         throws LDIFException, LDAPException
  {
    return connection.add(ldifLines);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final AddRequest addRequest)
         throws LDAPException
  {
    return connection.add(addRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return connection.add(addRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public BindResult bind(@Nullable final String bindDN,
                         @Nullable final String password)
         throws LDAPException
  {
    return connection.bind(bindDN, password);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public BindResult bind(@NotNull final BindRequest bindRequest)
         throws LDAPException
  {
    return connection.bind(bindRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public CompareResult compare(@NotNull final String dn,
                               @NotNull final String attributeName,
                               @NotNull final String assertionValue)
         throws LDAPException
  {
    return connection.compare(dn, attributeName, assertionValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public CompareResult compare(@NotNull final CompareRequest compareRequest)
         throws LDAPException
  {
    return connection.compare(compareRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public CompareResult compare(
              @NotNull final ReadOnlyCompareRequest compareRequest)
         throws LDAPException
  {
    return connection.compare(compareRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult delete(@NotNull final String dn)
         throws LDAPException
  {
    return connection.delete(dn);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult delete(@NotNull final DeleteRequest deleteRequest)
         throws LDAPException
  {
    return connection.delete(deleteRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult delete(@NotNull final ReadOnlyDeleteRequest deleteRequest)
         throws LDAPException
  {
    return connection.delete(deleteRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ExtendedResult processExtendedOperation(
                             @NotNull final String requestOID)
         throws LDAPException
  {
    return connection.processExtendedOperation(requestOID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ExtendedResult processExtendedOperation(
                             @NotNull final String requestOID,
                             @Nullable final ASN1OctetString requestValue)
         throws LDAPException
  {
    return connection.processExtendedOperation(requestOID, requestValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ExtendedResult processExtendedOperation(
                             @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    return connection.processExtendedOperation(extendedRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String dn,
                           @NotNull final Modification mod)
         throws LDAPException
  {
    return connection.modify(dn, mod);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String dn,
                           @NotNull final Modification... mods)
         throws LDAPException
  {
    return connection.modify(dn, mods);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String dn,
                           @NotNull final List<Modification> mods)
         throws LDAPException
  {
    return connection.modify(dn, mods);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    return connection.modify(ldifModificationLines);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final ModifyRequest modifyRequest)
         throws LDAPException
  {
    return connection.modify(modifyRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final ReadOnlyModifyRequest modifyRequest)
         throws LDAPException
  {
    return connection.modify(modifyRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modifyDN(@NotNull final String dn,
                             @NotNull final String newRDN,
                             final boolean deleteOldRDN)
         throws LDAPException
  {
    return connection.modifyDN(dn, newRDN, deleteOldRDN);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modifyDN(@NotNull final String dn,
                             @NotNull final String newRDN,
                             final boolean deleteOldRDN,
                             @Nullable final String newSuperiorDN)
         throws LDAPException
  {
    return connection.modifyDN(dn, newRDN, deleteOldRDN, newSuperiorDN);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modifyDN(@NotNull final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return connection.modifyDN(modifyDNRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult modifyDN(
              @NotNull final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return connection.modifyDN(modifyDNRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final String filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(baseDN, scope, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final Filter filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(baseDN, scope, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(
              @Nullable final SearchResultListener searchResultListener,
              @NotNull final String baseDN,
              @NotNull final SearchScope scope,
              @NotNull final String filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(searchResultListener, baseDN, scope, filter,
         attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(
              @Nullable final SearchResultListener searchResultListener,
              @NotNull final String baseDN,
              @NotNull final SearchScope scope,
              @NotNull final Filter filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(searchResultListener, baseDN, scope, filter,
         attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly,
                             @NotNull final String filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(baseDN, scope, derefPolicy, sizeLimit, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly,
                             @NotNull final Filter filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(baseDN, scope, derefPolicy, sizeLimit, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(
              @Nullable final SearchResultListener searchResultListener,
              @NotNull final String baseDN, @NotNull final SearchScope scope,
              @NotNull final DereferencePolicy derefPolicy, final int sizeLimit,
              final int timeLimit, final boolean typesOnly,
              @NotNull final String filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(searchResultListener, baseDN, scope, derefPolicy,
         sizeLimit, timeLimit, typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(
              @Nullable final SearchResultListener searchResultListener,
              @NotNull final String baseDN, @NotNull final SearchScope scope,
              @NotNull final DereferencePolicy derefPolicy, final int sizeLimit,
              final int timeLimit, final boolean typesOnly,
              @NotNull final Filter filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(searchResultListener, baseDN, scope, derefPolicy,
         sizeLimit, timeLimit, typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    return connection.search(searchRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return connection.search(searchRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                          @NotNull final SearchScope scope,
                                          @NotNull final String filter,
                                          @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.searchForEntry(baseDN, scope, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                          @NotNull final SearchScope scope,
                                          @NotNull final Filter filter,
                                          @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.searchForEntry(baseDN, scope, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                @NotNull final SearchScope scope,
                                @NotNull final DereferencePolicy derefPolicy,
                                final int timeLimit, final boolean typesOnly,
                                @NotNull final String filter,
                                @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.searchForEntry(baseDN, scope, derefPolicy, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                @NotNull final SearchScope scope,
                                @NotNull final DereferencePolicy derefPolicy,
                                final int timeLimit, final boolean typesOnly,
                                @NotNull final Filter filter,
                                @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return connection.searchForEntry(baseDN, scope, derefPolicy, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(
                                @NotNull final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    return connection.searchForEntry(searchRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(
              @NotNull final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return connection.searchForEntry(searchRequest);
  }
}
