/*
 * Copyright 2019-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019-2020 Ping Identity Corporation
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
  private final LDAPConnection connection;



  /**
   * Creates a new mockable LDAP connection from the provided connection.  All
   * non-overridden methods will simply be delegated to the provided connection.
   *
   * @param  connection  The connection to which all non-overridden method calls
   *                     will be delegated.
   */
  public MockableLDAPConnection(final LDAPConnection connection)
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
  public RootDSE getRootDSE()
         throws LDAPException
  {
    return connection.getRootDSE();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Schema getSchema()
         throws LDAPException
  {
    return connection.getSchema();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Schema getSchema(final String entryDN)
         throws LDAPException
  {
    return connection.getSchema(entryDN);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResultEntry getEntry(final String dn)
         throws LDAPException
  {
    return connection.getEntry(dn);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResultEntry getEntry(final String dn, final String... attributes)
         throws LDAPException
  {
    return connection.getEntry(dn, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult add(final String dn, final Attribute... attributes)
         throws LDAPException
  {
    return connection.add(dn, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult add(final String dn, final Collection<Attribute> attributes)
         throws LDAPException
  {
    return connection.add(dn, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult add(final Entry entry)
         throws LDAPException
  {
    return connection.add(entry);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult add(final String... ldifLines)
         throws LDIFException, LDAPException
  {
    return connection.add(ldifLines);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult add(final AddRequest addRequest)
         throws LDAPException
  {
    return connection.add(addRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult add(final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return connection.add(addRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public BindResult bind(final String bindDN, final String password)
         throws LDAPException
  {
    return connection.bind(bindDN, password);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public BindResult bind(final BindRequest bindRequest)
         throws LDAPException
  {
    return connection.bind(bindRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public CompareResult compare(final String dn, final String attributeName,
                               final String assertionValue)
         throws LDAPException
  {
    return connection.compare(dn, attributeName, assertionValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public CompareResult compare(final CompareRequest compareRequest)
         throws LDAPException
  {
    return connection.compare(compareRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public CompareResult compare(final ReadOnlyCompareRequest compareRequest)
         throws LDAPException
  {
    return connection.compare(compareRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult delete(final String dn)
         throws LDAPException
  {
    return connection.delete(dn);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult delete(final DeleteRequest deleteRequest)
         throws LDAPException
  {
    return connection.delete(deleteRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult delete(final ReadOnlyDeleteRequest deleteRequest)
         throws LDAPException
  {
    return connection.delete(deleteRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult processExtendedOperation(final String requestOID)
         throws LDAPException
  {
    return connection.processExtendedOperation(requestOID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult processExtendedOperation(final String requestOID,
                             final ASN1OctetString requestValue)
         throws LDAPException
  {
    return connection.processExtendedOperation(requestOID, requestValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult processExtendedOperation(
                             final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    return connection.processExtendedOperation(extendedRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modify(final String dn, final Modification mod)
         throws LDAPException
  {
    return connection.modify(dn, mod);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modify(final String dn, final Modification... mods)
         throws LDAPException
  {
    return connection.modify(dn, mods);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modify(final String dn, final List<Modification> mods)
         throws LDAPException
  {
    return connection.modify(dn, mods);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modify(final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    return connection.modify(ldifModificationLines);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modify(final ModifyRequest modifyRequest)
         throws LDAPException
  {
    return connection.modify(modifyRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modify(final ReadOnlyModifyRequest modifyRequest)
         throws LDAPException
  {
    return connection.modify(modifyRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN)
         throws LDAPException
  {
    return connection.modifyDN(dn, newRDN, deleteOldRDN);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN,
                             final String newSuperiorDN)
         throws LDAPException
  {
    return connection.modifyDN(dn, newRDN, deleteOldRDN, newSuperiorDN);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modifyDN(final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return connection.modifyDN(modifyDNRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult modifyDN(final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return connection.modifyDN(modifyDNRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(baseDN, scope, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(baseDN, scope, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(searchResultListener, baseDN, scope, filter,
         attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(searchResultListener, baseDN, scope, filter,
         attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(baseDN, scope, derefPolicy, sizeLimit, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(baseDN, scope, derefPolicy, sizeLimit, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(searchResultListener, baseDN, scope, derefPolicy,
         sizeLimit, timeLimit, typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    return connection.search(searchResultListener, baseDN, scope, derefPolicy,
         sizeLimit, timeLimit, typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    return connection.search(searchRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResult search(final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return connection.search(searchRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final String filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    return connection.searchForEntry(baseDN, scope, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final Filter filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    return connection.searchForEntry(baseDN, scope, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final DereferencePolicy derefPolicy,
                                          final int timeLimit,
                                          final boolean typesOnly,
                                          final String filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    return connection.searchForEntry(baseDN, scope, derefPolicy, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final DereferencePolicy derefPolicy,
                                          final int timeLimit,
                                          final boolean typesOnly,
                                          final Filter filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    return connection.searchForEntry(baseDN, scope, derefPolicy, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResultEntry searchForEntry(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    return connection.searchForEntry(searchRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResultEntry searchForEntry(
                                final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return connection.searchForEntry(searchRequest);
  }
}
