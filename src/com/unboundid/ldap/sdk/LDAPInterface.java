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



import java.util.Collection;
import java.util.List;

import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that are available for objects that
 * may be used to communicate with an LDAP directory server.  This can be used
 * to facilitate development of methods which can be used for either a single
 * LDAP connection or an LDAP connection pool.  Note that this interface does
 * not include support for bind or extended operations, as they may alter the
 * state of the underlying connection (or connection-like object), and care must
 * be taken when invoking such operations.  The {@link FullLDAPInterface}
 * interface is a subclass of this interface that does include support for
 * bind and extended operations, but those methods should be used with care to
 * ensure that they do not inappropriately alter the state of the associated
 * object.
 * <BR><BR>
 * At present, all implementations provided by the LDAP SDK are at least mostly
 * threadsafe and can be used to process multiple requests concurrently.
 * However, this is not a hard requirement and it is conceivable that in the
 * future a new implementation could be added which is not inherently
 * threadsafe.  It is recommended that code which requires thread safety either
 * provide their own external synchronization or use one of the subclasses which
 * explicitly provides thread safety rather than relying on this generic
 * interface.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface LDAPInterface
{
  /**
   * Retrieves the directory server root DSE.
   *
   * @return  The directory server root DSE, or {@code null} if it is not
   *          available.
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the server root DSE.
   */
  @Nullable()
  RootDSE getRootDSE()
          throws LDAPException;



  /**
   * Retrieves the directory server schema definitions, using the subschema
   * subentry DN contained in the server's root DSE.  For directory servers
   * containing a single schema, this should be sufficient for all purposes.
   * For servers with multiple schemas, it may be necessary to specify the DN
   * of the target entry for which to obtain the associated schema.
   *
   * @return  The directory server schema definitions, or {@code null} if the
   *          schema information could not be retrieved (e.g, the client does
   *          not have permission to read the server schema).
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the server schema.
   */
  @Nullable()
  Schema getSchema()
         throws LDAPException;



  /**
   * Retrieves the directory server schema definitions that govern the specified
   * entry.  The subschemaSubentry attribute will be retrieved from the target
   * entry, and then the appropriate schema definitions will be loaded from the
   * entry referenced by that attribute.  This may be necessary to ensure
   * correct behavior in servers that support multiple schemas.
   *
   * @param  entryDN  The DN of the entry for which to retrieve the associated
   *                  schema definitions.  It may be {@code null} or an empty
   *                  string if the subschemaSubentry attribute should be
   *                  retrieved from the server's root DSE.
   *
   * @return  The directory server schema definitions, or {@code null} if the
   *          schema information could not be retrieved (e.g, the client does
   *          not have permission to read the server schema).
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the server schema.
   */
  @Nullable()
  Schema getSchema(@Nullable String entryDN)
       throws LDAPException;



  /**
   * Retrieves the entry with the specified DN.  All user attributes will be
   * requested in the entry to return.
   *
   * @param  dn  The DN of the entry to retrieve.  It must not be {@code null}.
   *
   * @return  The requested entry, or {@code null} if the target entry does not
   *          exist or no entry was returned (e.g., if the authenticated user
   *          does not have permission to read the target entry).
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Nullable()
  SearchResultEntry getEntry(@NotNull String dn)
       throws LDAPException;



  /**
   * Retrieves the entry with the specified DN.
   *
   * @param  dn          The DN of the entry to retrieve.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to request for the target entry.
   *                     If it is {@code null}, then all user attributes will be
   *                     requested.
   *
   * @return  The requested entry, or {@code null} if the target entry does not
   *          exist or no entry was returned (e.g., if the authenticated user
   *          does not have permission to read the target entry).
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Nullable()
  SearchResultEntry getEntry(@NotNull String dn, @Nullable String... attributes)
       throws LDAPException;



  /**
   * Processes an add operation with the provided information.
   *
   * @param  dn          The DN of the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult add(@NotNull String dn, @NotNull Attribute... attributes)
       throws LDAPException;



  /**
   * Processes an add operation with the provided information.
   *
   * @param  dn          The DN of the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult add(@NotNull String dn, @NotNull Collection<Attribute> attributes)
       throws LDAPException;



  /**
   * Processes an add operation with the provided information.
   *
   * @param  entry  The entry to add.  It must not be {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult add(@NotNull Entry entry)
       throws LDAPException;



  /**
   * Processes an add operation with the provided information.
   *
   * @param  ldifLines  The lines that comprise an LDIF representation of the
   *                    entry to add.  It must not be empty or {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDIFException  If the provided entry lines cannot be decoded as an
   *                         entry in LDIF form.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult add(@NotNull String... ldifLines)
       throws LDIFException, LDAPException;



  /**
   * Processes the provided add request.
   *
   * @param  addRequest  The add request to be processed.  It must not be
   *                     {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult add(@NotNull AddRequest addRequest)
       throws LDAPException;



  /**
   * Processes the provided add request.
   *
   * @param  addRequest  The add request to be processed.  It must not be
   *                     {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult add(@NotNull ReadOnlyAddRequest addRequest)
       throws LDAPException;



  /**
   * Processes a compare operation with the provided information.
   *
   * @param  dn              The DN of the entry in which to make the
   *                         comparison.  It must not be {@code null}.
   * @param  attributeName   The attribute name for which to make the
   *                         comparison.  It must not be {@code null}.
   * @param  assertionValue  The assertion value to verify in the target entry.
   *                         It must not be {@code null}.
   *
   * @return  The result of processing the compare operation.
   *
   * @throws  LDAPException  If the server rejects the compare request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  CompareResult compare(@NotNull String dn, @NotNull String attributeName,
                        @NotNull String assertionValue)
       throws LDAPException;



  /**
   * Processes the provided compare request.
   *
   * @param  compareRequest  The compare request to be processed.  It must not
   *                         be {@code null}.
   *
   * @return  The result of processing the compare operation.
   *
   * @throws  LDAPException  If the server rejects the compare request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  CompareResult compare(@NotNull CompareRequest compareRequest)
       throws LDAPException;



  /**
   * Processes the provided compare request.
   *
   * @param  compareRequest  The compare request to be processed.  It must not
   *                         be {@code null}.
   *
   * @return  The result of processing the compare operation.
   *
   * @throws  LDAPException  If the server rejects the compare request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  CompareResult compare(@NotNull ReadOnlyCompareRequest compareRequest)
       throws LDAPException;



  /**
   * Deletes the entry with the specified DN.
   *
   * @param  dn  The DN of the entry to delete.  It must not be {@code null}.
   *
   * @return  The result of processing the delete operation.
   *
   * @throws  LDAPException  If the server rejects the delete request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult delete(@NotNull String dn)
       throws LDAPException;



  /**
   * Processes the provided delete request.
   *
   * @param  deleteRequest  The delete request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the delete operation.
   *
   * @throws  LDAPException  If the server rejects the delete request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult delete(@NotNull DeleteRequest deleteRequest)
       throws LDAPException;



  /**
   * Processes the provided delete request.
   *
   * @param  deleteRequest  The delete request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the delete operation.
   *
   * @throws  LDAPException  If the server rejects the delete request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult delete(@NotNull ReadOnlyDeleteRequest deleteRequest)
       throws LDAPException;



  /**
   * Applies the provided modification to the specified entry.
   *
   * @param  dn   The DN of the entry to modify.  It must not be {@code null}.
   * @param  mod  The modification to apply to the target entry.  It must not
   *              be {@code null}.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult modify(@NotNull String dn, @NotNull Modification mod)
       throws LDAPException;



  /**
   * Applies the provided set of modifications to the specified entry.
   *
   * @param  dn    The DN of the entry to modify.  It must not be {@code null}.
   * @param  mods  The set of modifications to apply to the target entry.  It
   *               must not be {@code null} or empty.  *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult modify(@NotNull String dn, @NotNull Modification... mods)
       throws LDAPException;



  /**
   * Applies the provided set of modifications to the specified entry.
   *
   * @param  dn    The DN of the entry to modify.  It must not be {@code null}.
   * @param  mods  The set of modifications to apply to the target entry.  It
   *               must not be {@code null} or empty.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult modify(@NotNull String dn, @NotNull List<Modification> mods)
       throws LDAPException;



  /**
   * Processes a modify request from the provided LDIF representation of the
   * changes.
   *
   * @param  ldifModificationLines  The lines that comprise an LDIF
   *                                representation of a modify change record.
   *                                It must not be {@code null} or empty.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDIFException  If the provided set of lines cannot be parsed as an
   *                         LDIF modify change record.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   *
   */
  @NotNull()
  LDAPResult modify(@NotNull String... ldifModificationLines)
       throws LDIFException, LDAPException;



  /**
   * Processes the provided modify request.
   *
   * @param  modifyRequest  The modify request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult modify(@NotNull ModifyRequest modifyRequest)
       throws LDAPException;



  /**
   * Processes the provided modify request.
   *
   * @param  modifyRequest  The modify request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  LDAPResult modify(@NotNull ReadOnlyModifyRequest modifyRequest)
       throws LDAPException;



  /**
   * Performs a modify DN operation with the provided information.
   *
   * @param  dn            The current DN for the entry to rename.  It must not
   *                       be {@code null}.
   * @param  newRDN        The new RDN to use for the entry.  It must not be
   *                       {@code null}.
   * @param  deleteOldRDN  Indicates whether to delete the current RDN value
   *                       from the entry.
   *
   * @return  The result of processing the modify DN operation.
   *
   * @throws  LDAPException  If the server rejects the modify DN request, or if
   *                         a problem is encountered while sending the request
   *                         or reading the response.
   */
  @NotNull()
  LDAPResult modifyDN(@NotNull String dn, @NotNull String newRDN,
                      boolean deleteOldRDN)
       throws LDAPException;



  /**
   * Performs a modify DN operation with the provided information.
   *
   * @param  dn             The current DN for the entry to rename.  It must not
   *                        be {@code null}.
   * @param  newRDN         The new RDN to use for the entry.  It must not be
   *                        {@code null}.
   * @param  deleteOldRDN   Indicates whether to delete the current RDN value
   *                        from the entry.
   * @param  newSuperiorDN  The new superior DN for the entry.  It may be
   *                        {@code null} if the entry is not to be moved below a
   *                        new parent.
   *
   * @return  The result of processing the modify DN operation.
   *
   * @throws  LDAPException  If the server rejects the modify DN request, or if
   *                         a problem is encountered while sending the request
   *                         or reading the response.
   */
  @NotNull()
  LDAPResult modifyDN(@NotNull String dn, @NotNull String newRDN,
                      boolean deleteOldRDN, @Nullable String newSuperiorDN)
       throws LDAPException;



  /**
   * Processes the provided modify DN request.
   *
   * @param  modifyDNRequest  The modify DN request to be processed.  It must
   *                          not be {@code null}.
   *
   * @return  The result of processing the modify DN operation.
   *
   * @throws  LDAPException  If the server rejects the modify DN request, or if
   *                         a problem is encountered while sending the request
   *                         or reading the response.
   */
  @NotNull()
  LDAPResult modifyDN(@NotNull ModifyDNRequest modifyDNRequest)
       throws LDAPException;



  /**
   * Processes the provided modify DN request.
   *
   * @param  modifyDNRequest  The modify DN request to be processed.  It must
   *                          not be {@code null}.
   *
   * @return  The result of processing the modify DN operation.
   *
   * @throws  LDAPException  If the server rejects the modify DN request, or if
   *                         a problem is encountered while sending the request
   *                         or reading the response.
   */
  @NotNull()
  LDAPResult modifyDN(@NotNull ReadOnlyModifyDNRequest modifyDNRequest)
       throws LDAPException;



  /**
   * Processes a search operation with the provided information.  The search
   * result entries and references will be collected internally and included in
   * the {@code SearchResult} object that is returned.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN      The base DN for the search request.  It must not be
   *                     {@code null}.
   * @param  scope       The scope that specifies the range of entries that
   *                     should be examined for the search.
   * @param  filter      The string representation of the filter to use to
   *                     identify matching entries.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes that should be returned in
   *                     matching entries.  It may be {@code null} or empty if
   *                     the default attribute set (all user attributes) is to
   *                     be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, including the set of matching entries
   *          and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while parsing
   *                               the provided filter string, sending the
   *                               request, or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@NotNull String baseDN, @NotNull SearchScope scope,
                      @NotNull String filter, @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.  The search
   * result entries and references will be collected internally and included in
   * the {@code SearchResult} object that is returned.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN      The base DN for the search request.  It must not be
   *                     {@code null}.
   * @param  scope       The scope that specifies the range of entries that
   *                     should be examined for the search.
   * @param  filter      The filter to use to identify matching entries.  It
   *                     must not be {@code null}.
   * @param  attributes  The set of attributes that should be returned in
   *                     matching entries.  It may be {@code null} or empty if
   *                     the default attribute set (all user attributes) is to
   *                     be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, including the set of matching entries
   *          and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@NotNull String baseDN, @NotNull SearchScope scope,
                      @NotNull Filter filter, @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  filter                The string representation of the filter to
   *                               use to identify matching entries.  It must
   *                               not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while parsing
   *                               the provided filter string, sending the
   *                               request, or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@Nullable SearchResultListener searchResultListener,
                      @NotNull String baseDN, @NotNull SearchScope scope,
                      @NotNull String filter, @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  filter                The filter to use to identify matching
   *                               entries.  It must not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@Nullable SearchResultListener searchResultListener,
                      @NotNull String baseDN, @NotNull SearchScope scope,
                      @NotNull Filter filter, @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.  The search
   * result entries and references will be collected internally and included in
   * the {@code SearchResult} object that is returned.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN       The base DN for the search request.  It must not be
   *                      {@code null}.
   * @param  scope        The scope that specifies the range of entries that
   *                      should be examined for the search.
   * @param  derefPolicy  The dereference policy the server should use for any
   *                      aliases encountered while processing the search.
   * @param  sizeLimit    The maximum number of entries that the server should
   *                      return for the search.  A value of zero indicates that
   *                      there should be no limit.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing this search request.  A value
   *                      of zero indicates that there should be no limit.
   * @param  typesOnly    Indicates whether to return only attribute names in
   *                      matching entries, or both attribute names and values.
   * @param  filter       The string representation of the filter to use to
   *                      identify matching entries.  It must not be
   *                      {@code null}.
   * @param  attributes   The set of attributes that should be returned in
   *                      matching entries.  It may be {@code null} or empty if
   *                      the default attribute set (all user attributes) is to
   *                      be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, including the set of matching entries
   *          and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while parsing
   *                               the provided filter string, sending the
   *                               request, or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@NotNull String baseDN, @NotNull SearchScope scope,
                      @NotNull DereferencePolicy derefPolicy, int sizeLimit,
                      int timeLimit, boolean typesOnly,
                      @NotNull String filter, @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.  The search
   * result entries and references will be collected internally and included in
   * the {@code SearchResult} object that is returned.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN       The base DN for the search request.  It must not be
   *                      {@code null}.
   * @param  scope        The scope that specifies the range of entries that
   *                      should be examined for the search.
   * @param  derefPolicy  The dereference policy the server should use for any
   *                      aliases encountered while processing the search.
   * @param  sizeLimit    The maximum number of entries that the server should
   *                      return for the search.  A value of zero indicates that
   *                      there should be no limit.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing this search request.  A value
   *                      of zero indicates that there should be no limit.
   * @param  typesOnly    Indicates whether to return only attribute names in
   *                      matching entries, or both attribute names and values.
   * @param  filter       The filter to use to identify matching entries.  It
   *                      must not be {@code null}.
   * @param  attributes   The set of attributes that should be returned in
   *                      matching entries.  It may be {@code null} or empty if
   *                      the default attribute set (all user attributes) is to
   *                      be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, including the set of matching entries
   *          and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@NotNull String baseDN, @NotNull SearchScope scope,
                      @NotNull DereferencePolicy derefPolicy, int sizeLimit,
                      int timeLimit, boolean typesOnly, @NotNull Filter filter,
                      @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  derefPolicy           The dereference policy the server should use
   *                               for any aliases encountered while processing
   *                               the search.
   * @param  sizeLimit             The maximum number of entries that the server
   *                               should return for the search.  A value of
   *                               zero indicates that there should be no limit.
   * @param  timeLimit             The maximum length of time in seconds that
   *                               the server should spend processing this
   *                               search request.  A value of zero indicates
   *                               that there should be no limit.
   * @param  typesOnly             Indicates whether to return only attribute
   *                               names in matching entries, or both attribute
   *                               names and values.
   * @param  filter                The string representation of the filter to
   *                               use to identify matching entries.  It must
   *                               not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while parsing
   *                               the provided filter string, sending the
   *                               request, or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@Nullable SearchResultListener searchResultListener,
                      @NotNull String baseDN, @NotNull SearchScope scope,
                      @NotNull DereferencePolicy derefPolicy, int sizeLimit,
                      int timeLimit, boolean typesOnly,
                      @NotNull String filter, @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  derefPolicy           The dereference policy the server should use
   *                               for any aliases encountered while processing
   *                               the search.
   * @param  sizeLimit             The maximum number of entries that the server
   *                               should return for the search.  A value of
   *                               zero indicates that there should be no limit.
   * @param  timeLimit             The maximum length of time in seconds that
   *                               the server should spend processing this
   *                               search request.  A value of zero indicates
   *                               that there should be no limit.
   * @param  typesOnly             Indicates whether to return only attribute
   *                               names in matching entries, or both attribute
   *                               names and values.
   * @param  filter                The filter to use to identify matching
   *                               entries.  It must not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@Nullable SearchResultListener searchResultListener,
                      @NotNull String baseDN, @NotNull SearchScope scope,
                      @NotNull DereferencePolicy derefPolicy, int sizeLimit,
                      int timeLimit, boolean typesOnly,
                      @NotNull Filter filter, @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes the provided search request.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchRequest  The search request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@NotNull SearchRequest searchRequest)
       throws LDAPSearchException;



  /**
   * Processes the provided search request.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchRequest  The search request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @NotNull()
  SearchResult search(@NotNull ReadOnlySearchRequest searchRequest)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.  It is expected
   * that at most one entry will be returned from the search, and that no
   * additional content from the successful search result (e.g., diagnostic
   * message or response controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN      The base DN for the search request.  It must not be
   *                     {@code null}.
   * @param  scope       The scope that specifies the range of entries that
   *                     should be examined for the search.
   * @param  filter      The string representation of the filter to use to
   *                     identify matching entries.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes that should be returned in
   *                     matching entries.  It may be {@code null} or empty if
   *                     the default attribute set (all user attributes) is to
   *                     be requested.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @Nullable()
  SearchResultEntry searchForEntry(@NotNull String baseDN,
                                   @NotNull SearchScope scope,
                                   @NotNull String filter,
                                   @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.  It is expected
   * that at most one entry will be returned from the search, and that no
   * additional content from the successful search result (e.g., diagnostic
   * message or response controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN      The base DN for the search request.  It must not be
   *                     {@code null}.
   * @param  scope       The scope that specifies the range of entries that
   *                     should be examined for the search.
   * @param  filter      The string representation of the filter to use to
   *                     identify matching entries.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes that should be returned in
   *                     matching entries.  It may be {@code null} or empty if
   *                     the default attribute set (all user attributes) is to
   *                     be requested.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @Nullable()
  SearchResultEntry searchForEntry(@NotNull String baseDN,
                                   @NotNull SearchScope scope,
                                   @NotNull Filter filter,
                                   @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.  It is expected
   * that at most one entry will be returned from the search, and that no
   * additional content from the successful search result (e.g., diagnostic
   * message or response controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN       The base DN for the search request.  It must not be
   *                      {@code null}.
   * @param  scope        The scope that specifies the range of entries that
   *                      should be examined for the search.
   * @param  derefPolicy  The dereference policy the server should use for any
   *                      aliases encountered while processing the search.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing this search request.  A value
   *                      of zero indicates that there should be no limit.
   * @param  typesOnly    Indicates whether to return only attribute names in
   *                      matching entries, or both attribute names and values.
   * @param  filter       The string representation of the filter to use to
   *                      identify matching entries.  It must not be
   *                      {@code null}.
   * @param  attributes   The set of attributes that should be returned in
   *                      matching entries.  It may be {@code null} or empty if
   *                      the default attribute set (all user attributes) is to
   *                      be requested.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @Nullable()
  SearchResultEntry searchForEntry(@NotNull String baseDN,
                                   @NotNull SearchScope scope,
                                   @NotNull DereferencePolicy derefPolicy,
                                   int timeLimit, boolean typesOnly,
                                   @NotNull String filter,
                                   @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes a search operation with the provided information.  It is expected
   * that at most one entry will be returned from the search, and that no
   * additional content from the successful search result (e.g., diagnostic
   * message or response controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN       The base DN for the search request.  It must not be
   *                      {@code null}.
   * @param  scope        The scope that specifies the range of entries that
   *                      should be examined for the search.
   * @param  derefPolicy  The dereference policy the server should use for any
   *                      aliases encountered while processing the search.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing this search request.  A value
   *                      of zero indicates that there should be no limit.
   * @param  typesOnly    Indicates whether to return only attribute names in
   *                      matching entries, or both attribute names and values.
   * @param  filter       The filter to use to identify matching entries.  It
   *                      must not be {@code null}.
   * @param  attributes   The set of attributes that should be returned in
   *                      matching entries.  It may be {@code null} or empty if
   *                      the default attribute set (all user attributes) is to
   *                      be requested.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @Nullable()
  SearchResultEntry searchForEntry(@NotNull String baseDN,
                                   @NotNull SearchScope scope,
                                   @NotNull DereferencePolicy derefPolicy,
                                   int timeLimit, boolean typesOnly,
                                   @NotNull Filter filter,
                                   @Nullable String... attributes)
       throws LDAPSearchException;



  /**
   * Processes the provided search request.  It is expected that at most one
   * entry will be returned from the search, and that no additional content from
   * the successful search result (e.g., diagnostic message or response
   * controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  searchRequest  The search request to be processed.  If it is
   *                        configured with a search result listener or a size
   *                        limit other than one, then the provided request will
   *                        be duplicated with the appropriate settings.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @Nullable()
  SearchResultEntry searchForEntry(@NotNull SearchRequest searchRequest)
       throws LDAPSearchException;



  /**
   * Processes the provided search request.  It is expected that at most one
   * entry will be returned from the search, and that no additional content from
   * the successful search result (e.g., diagnostic message or response
   * controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  searchRequest  The search request to be processed.  If it is
   *                        configured with a search result listener or a size
   *                        limit other than one, then the provided request will
   *                        be duplicated with the appropriate settings.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @Nullable()
  SearchResultEntry searchForEntry(@NotNull ReadOnlySearchRequest searchRequest)
       throws LDAPSearchException;
}
