/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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
package com.unboundid.ldap.sdk.persist;



import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPEntrySource;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides an interface that can be used to store and update
 * representations of Java objects in an LDAP directory server, and to find and
 * retrieve Java objects from the directory server.  The objects to store,
 * update, and retrieve must be marked with the {@link LDAPObject} annotation.
 * Fields and methods within the class should be marked with the
 * {@link LDAPField}, {@link LDAPFieldGetter}, or {@link LDAPFieldSetter}
 * annotations as appropriate to indicate how to convert between the LDAP and
 * the Java representations of the content.
 *
 * @param  <T>  The type of object handled by this class.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPPersister<T>
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4001743482496453961L;



  // The LDAP object handler that will be used for this class.
  private final LDAPObjectHandler<T> handler;



  /**
   * Creates a new instance of this LDAP persister that will be used to interact
   * with objects of the specified type.
   *
   * @param  type  The type of object managed by this LDAP persister.  It must
   *               not be {@code null}, and it must be marked with the
   *               {@link LDAPObject} annotation.
   *
   * @throws  LDAPPersistException  If the provided class is not suitable for
   *                                persisting in an LDAP directory server.
   */
  public LDAPPersister(final Class<T> type)
         throws LDAPPersistException
  {
    ensureNotNull(type);
    handler = new LDAPObjectHandler<T>(type);
  }



  /**
   * Retrieves the {@link LDAPObject} annotation of the class used for objects
   * of the associated type.
   *
   * @return  The {@code LDAPObject} annotation of the class used for objects of
   *          the associated type.
   */
  public LDAPObject getLDAPObjectAnnotation()
  {
    return handler.getLDAPObjectAnnotation();
  }



  /**
   * Constructs a list of LDAP attribute type definitions which may be added to
   * the directory server schema to allow it to hold objects of this type.  Note
   * that the object identifiers used for the constructed attribute type
   * definitions are not required to be valid or unique.
   *
   * @return  A list of attribute type definitions that may be used to represent
   *          objects of the associated type in an LDAP directory.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                generate the list of attribute type
   *                                definitions.
   */
  public List<AttributeTypeDefinition> constructAttributeTypes()
         throws LDAPPersistException
  {
    return constructAttributeTypes(DefaultOIDAllocator.getInstance());
  }



  /**
   * Constructs a list of LDAP attribute type definitions which may be added to
   * the directory server schema to allow it to hold objects of this type.  Note
   * that the object identifiers used for the constructed attribute type
   * definitions are not required to be valid or unique.
   *
   * @param  a  The OID allocator to use to generate the object identifiers for
   *            the constructed attribute types.  It must not be {@code null}.
   *
   * @return  A list of attribute type definitions that may be used to represent
   *          objects of the associated type in an LDAP directory.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                generate the list of attribute type
   *                                definitions.
   */
  public List<AttributeTypeDefinition> constructAttributeTypes(
                                            final OIDAllocator a)
         throws LDAPPersistException
  {
    final LinkedList<AttributeTypeDefinition> attrList =
         new LinkedList<AttributeTypeDefinition>();

    for (final FieldInfo i : handler.getFields().values())
    {
      attrList.add(i.constructAttributeType(a));
    }

    for (final GetterInfo i : handler.getGetters().values())
    {
      attrList.add(i.constructAttributeType(a));
    }

    return Collections.unmodifiableList(attrList);
  }



  /**
   * Constructs a list of LDAP object class definitions which may be added to
   * the directory server schema to allow it to hold objects of this type.  Note
   * that the object identifiers used for the constructed object class
   * definitions are not required to be valid or unique.
   *
   * @return  A list of object class definitions that may be used to represent
   *          objects of the associated type in an LDAP directory.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                generate the list of object class
   *                                definitions.
   */
  public List<ObjectClassDefinition> constructObjectClasses()
         throws LDAPPersistException
  {
    return constructObjectClasses(DefaultOIDAllocator.getInstance());
  }



  /**
   * Constructs a list of LDAP object class definitions which may be added to
   * the directory server schema to allow it to hold objects of this type.  Note
   * that the object identifiers used for the constructed object class
   * definitions are not required to be valid or unique.
   *
   * @param  a  The OID allocator to use to generate the object identifiers for
   *            the constructed attribute types.  It must not be {@code null}.
   *
   * @return  A list of object class definitions that may be used to represent
   *          objects of the associated type in an LDAP directory.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                generate the list of object class
   *                                definitions.
   */
  public List<ObjectClassDefinition> constructObjectClasses(
                                          final OIDAllocator a)
         throws LDAPPersistException
  {
    return handler.constructObjectClasses(a);
  }



  /**
   * Encodes the provided object to an entry that is suitable for storing it in
   * an LDAP directory server.
   *
   * @param  o         The object to be encoded.  It must not be {@code null}.
   * @param  parentDN  The parent DN to use for the resulting entry.  If the
   *                   provided object was previously read from a directory
   *                   server and includes a field marked with the
   *                   {@link LDAPDNField} or {@link LDAPEntryField} annotation,
   *                   then that field may be used to retrieve the actual DN of
   *                   the associated entry.  If the actual DN of the associated
   *                   entry is not available, then a DN will be constructed
   *                   from the RDN fields and/or getter methods declared in the
   *                   class.  If the provided parent DN is {@code null}, then
   *                   the default parent DN defined in the {@link LDAPObject}
   *                   annotation will be used.
   *
   * @return  An entry containing the encoded representation of the provided
   *          object.  It may be altered by the caller if necessary.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                encode the provided object.
   */
  public Entry encode(final T o, final String parentDN)
         throws LDAPPersistException
  {
    ensureNotNull(o);
    return handler.encode(o, parentDN);
  }



  /**
   * Creates an object and initializes it with the contents of the provided
   * entry.
   *
   * @param  entry  The entry to use to create the object.  It must not be
   *                {@code null}.
   *
   * @return  The object created from the provided entry.
   *
   * @throws  LDAPPersistException  If an error occurs while attempting to
   *                                create or initialize the object from the
   *                                provided entry.
   */
  public T decode(final Entry entry)
         throws LDAPPersistException
  {
    ensureNotNull(entry);
    return handler.decode(entry);
  }



  /**
   * Initializes the provided object from the information contained in the
   * given entry.
   *
   * @param  o      The object to initialize with the contents of the provided
   *                entry.  It must not be {@code null}.
   * @param  entry  The entry to use to create the object.  It must not be
   *                {@code null}.
   *
   * @throws  LDAPPersistException  If an error occurs while attempting to
   *                                initialize the object from the provided
   *                                entry.  If an exception is thrown, then the
   *                                provided object may or may not have been
   *                                altered.
   */
  public void decode(final T o, final Entry entry)
         throws LDAPPersistException
  {
    ensureNotNull(o, entry);
    handler.decode(o, entry);
  }



  /**
   * Adds the provided object to the directory server using the provided
   * connection.
   *
   * @param  o         The object to be added.  It must not be {@code null}.
   * @param  i         The interface to use to communicate with the directory
   *                   server.  It must not be {@code null}.
   * @param  parentDN  The parent DN to use for the resulting entry.  If the
   *                   provided object was previously read from a directory
   *                   server and includes a field marked with the
   *                   {@link LDAPDNField} or {@link LDAPEntryField} annotation,
   *                   then that field may be used to retrieve the actual DN of
   *                   the associated entry.  If the actual DN of the associated
   *                   entry is not available, then a DN will be constructed
   *                   from the RDN fields and/or getter methods declared in the
   *                   class.  If the provided parent DN is {@code null}, then
   *                   the default parent DN defined in the {@link LDAPObject}
   *                   annotation will be used.
   *
   * @return  A read-only representation of the entry that was added.
   *
   * @throws  LDAPPersistException  If a problem occurs while encoding or adding
   *                                the entry.
   */
  public ReadOnlyEntry add(final T o, final LDAPInterface i,
                           final String parentDN)
         throws LDAPPersistException
  {
    ensureNotNull(o, i);
    final Entry e = encode(o, parentDN);

    try
    {
      i.add(e);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    return new ReadOnlyEntry(e);
  }



  /**
   * Deletes the provided object from the directory.
   *
   * @param  o  The object to be deleted.  It must not be {@code null}, and it
   *            must have been retrieved from the directory and have a field
   *            with either the {@link LDAPDNField} or {@link LDAPEntryField}
   *            annotations.
   * @param  i  The interface to use to communicate with the directory server.
   *            It must not be {@code null}.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                delete the entry.
   */
  public void delete(final T o, final LDAPInterface i)
         throws LDAPPersistException
  {
    ensureNotNull(o, i);
    final String dn = handler.getEntryDN(o);
    if (dn == null)
    {
      throw new LDAPPersistException(ERR_PERSISTER_DELETE_NO_DN.get());
    }

    try
    {
      i.delete(dn);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }
  }



  /**
   * Retrieves a list of modifications that can be used to update the stored
   * representation of the provided object in the directory.  If the provided
   * object was retrieved from the directory using the persistence framework and
   * includes a field with the {@link LDAPEntryField} annotation, then that
   * entry will be used to make the returned set of modifications as efficient
   * as possible.  Otherwise, the resulting modifications will include attempts
   * to replace every attribute which are associated with fields or getters
   * that should be used in modify operations.
   *
   * @param  o                 The object for which to generate the list of
   *                           modifications.  It must not be {@code null}.
   * @param  deleteNullValues  Indicates whether to include modifications that
   *                           may completely remove an attribute from the
   *                           entry if the corresponding field or getter method
   *                           has a value of {@code null}.
   * @param  attributes        The set of LDAP attributes for which to include
   *                           modifications.  If this is empty or {@code null},
   *                           then all attributes marked for inclusion in the
   *                           modification will be examined.
   *
   * @return  An unmodifiable list of modifications that can be used to update
   *          the stored representation of the provided object in the directory.
   *          It may be empty if there are no differences identified in the
   *          attributes to be evaluated.
   *
   * @throws  LDAPPersistException  If a problem occurs while computing the set
   *                                of modifications.
   */
  public List<Modification> getModifications(final T o,
                                             final boolean deleteNullValues,
                                             final String... attributes)
         throws LDAPPersistException
  {
    ensureNotNull(o);
    return handler.getModifications(o, deleteNullValues, attributes);
  }



  /**
   * Updates the stored representation of the provided object in the directory.
   * If the provided object was retrieved from the directory using the
   * persistence framework and includes a field with the {@link LDAPEntryField}
   * annotation, then that entry will be used to make the returned set of
   * modifications as efficient as possible.  Otherwise, the resulting
   * modifications will include attempts to replace every attribute which are
   * associated with fields or getters that should be used in modify operations.
   *
   * @param  o                 The object for which to generate the list of
   *                           modifications.  It must not be {@code null}.
   * @param  i                 The interface to use to communicate with the
   *                           directory server.  It must not be {@code null}.
   * @param  dn                The DN to use for the entry.  It must not be
   *                           {@code null} if the object was not retrieved from
   *                           the directory using the persistence framework or
   *                           does not have a field marked with the
   *                           {@link LDAPDNField} or {@link LDAPEntryField}
   *                           annotation.
   * @param  deleteNullValues  Indicates whether to include modifications that
   *                           may completely remove an attribute from the
   *                           entry if the corresponding field or getter method
   *                           has a value of {@code null}.
   * @param  attributes        The set of LDAP attributes for which to include
   *                           modifications.  If this is empty or {@code null},
   *                           then all attributes marked for inclusion in the
   *                           modification will be examined.
   *
   * @return  An unmodifiable list of the modifications applied to the entry.
   *
   * @throws  LDAPPersistException  If a problem occurs while computing the set
   *                                of modifications.
   */
  public List<Modification> modify(final T o, final LDAPInterface i,
                                   final String dn,
                                   final boolean deleteNullValues,
                                   final String... attributes)
         throws LDAPPersistException
  {
    ensureNotNull(o, i);
    final List<Modification> mods =
         handler.getModifications(o, deleteNullValues, attributes);

    final String targetDN;
    if (dn == null)
    {
      targetDN = handler.getEntryDN(o);
      if (targetDN == null)
      {
        throw new LDAPPersistException(ERR_PERSISTER_MODIFY_NO_DN.get());
      }
    }
    else
    {
      targetDN = dn;
    }

    try
    {
      i.modify(targetDN, mods);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    return mods;
  }



  /**
   * Constructs the DN of the associated entry from the provided object and
   * parent DN and retrieves the contents of that entry as a new instance of
   * that object.
   *
   * @param  o         An object instance to use to construct the DN of the
   *                   entry to retrieve.  It must not be {@code null}, and all
   *                   fields and/or getter methods marked for inclusion in the
   *                   entry RDN must have non-{@code null} values.
   * @param  i         The interface to use to communicate with the directory
   *                   server. It must not be {@code null}.
   * @param  parentDN  The parent DN to use for the entry to retrieve.  If the
   *                   provided object was previously read from a directory
   *                   server and includes a field marked with the
   *                   {@link LDAPDNField} or {@link LDAPEntryField} annotation,
   *                   then that field may be used to retrieve the actual DN of
   *                   the associated entry.  If the actual DN of the target
   *                   entry is not available, then a DN will be constructed
   *                   from the RDN fields and/or getter methods declared in the
   *                   class and this parent DN.  If the provided parent DN is
   *                   {@code null}, then the default parent DN defined in the
   *                   {@link LDAPObject} annotation will be used.
   *
   * @return  The object read from the entry with the provided DN, or
   *          {@code null} if no entry exists with the constructed DN.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                construct the entry DN, retrieve the
   *                                corresponding entry or decode it as an
   *                                object.
   */
  public T get(final T o, final LDAPInterface i, final String parentDN)
         throws LDAPPersistException
  {
    final String dn = handler.constructDN(o, parentDN);

    final Entry entry;
    try
    {
      entry = i.getEntry(dn, "*", "+");
      if (entry == null)
      {
        return null;
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    return decode(entry);
  }



  /**
   * Retrieves the object from the directory entry with the provided DN.
   *
   * @param  dn  The DN of the entry to retrieve and decode.  It must not be
   *             {@code null}.
   * @param  i   The interface to use to communicate with the directory server.
   *             It must not be {@code null}.
   *
   * @return  The object read from the entry with the provided DN, or
   *          {@code null} if no entry exists with the provided DN.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                retrieve the specified entry or decode it
   *                                as an object.
   */
  public T get(final String dn, final LDAPInterface i)
         throws LDAPPersistException
  {
    final Entry entry;
    try
    {
      entry = i.getEntry(dn, "*", "+");
      if (entry == null)
      {
        return null;
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    return decode(entry);
  }



  /**
   * Performs a search in the directory for objects matching the contents of the
   * provided object.  A search filter will be generated from the provided
   * object containing all non-{@code null} values from fields and getter
   * methods whose {@link LDAPField} or {@link LDAPFieldGetter} annotation has
   * the {@code inFilter} element set to {@code true}.
   * <BR><BR>
   * The search performed will be a subtree search using a base DN equal to the
   * {@link LDAPObject#defaultParentDN} element in the {@code LDAPObject}
   * annotation.  It will not enforce a client-side time limit or size limit.
   * <BR><BR>
   * Note that this method requires an {@link LDAPConnection} argument rather
   * than using the more generic {@link LDAPInterface} type because the search
   * is invoked as an asynchronous operation, which is not supported by the
   * generic {@code LDAPInterface} interface.  It also means that the provided
   * connection must not be configured to operate in synchronous mode (via the
   * {@link com.unboundid.ldap.sdk.LDAPConnectionOptions#setUseSynchronousMode}
   * option).
   *
   * @param  o  The object to use to construct the search filter.  It must not
   *            be {@code null}.
   * @param  c  The connection to use to communicate with the directory server.
   *            It must not be {@code null}.
   *
   * @return  A results object that may be used to iterate through the objects
   *          returned from the search.
   *
   * @throws  LDAPPersistException  If an error occurs while preparing or
   *                                sending the search request.
   */
  public PersistedObjects<T> search(final T o, final LDAPConnection c)
         throws LDAPPersistException
  {
    return search(o, c, null, SearchScope.SUB, DereferencePolicy.NEVER, 0, 0);
  }



  /**
   * Performs a search in the directory for objects matching the contents of the
   * provided object.  A search filter will be generated from the provided
   * object containing all non-{@code null} values from fields and getter
   * methods whose {@link LDAPField} or {@link LDAPFieldGetter} annotation has
   * the {@code inFilter} element set to {@code true}.
   * <BR><BR>
   * The search performed will be a subtree search using a base DN equal to the
   * {@link LDAPObject#defaultParentDN} element in the {@code LDAPObject}
   * annotation.  It will not enforce a client-side time limit or size limit.
   * <BR><BR>
   * Note that this method requires an {@link LDAPConnection} argument rather
   * than using the more generic {@link LDAPInterface} type because the search
   * is invoked as an asynchronous operation, which is not supported by the
   * generic {@code LDAPInterface} interface.  It also means that the provided
   * connection must not be configured to operate in synchronous mode (via the
   * {@link com.unboundid.ldap.sdk.LDAPConnectionOptions#setUseSynchronousMode}
   * option).
   *
   * @param  o       The object to use to construct the search filter.  It must
   *                 not be {@code null}.
   * @param  c       The connection to use to communicate with the directory
   *                 server. It must not be {@code null}.
   * @param  baseDN  The base DN to use for the search.  It may be {@code null}
   *                 if the {@link LDAPObject#defaultParentDN} element in the
   *                 {@code LDAPObject}
   * @param  scope   The scope to use for the search operation.  It must not be
   *                 {@code null}.
   *
   * @return  A results object that may be used to iterate through the objects
   *          returned from the search.
   *
   * @throws  LDAPPersistException  If an error occurs while preparing or
   *                                sending the search request.
   */
  public PersistedObjects<T> search(final T o, final LDAPConnection c,
                                    final String baseDN,
                                    final SearchScope scope)
         throws LDAPPersistException
  {
    return search(o, c, baseDN, scope, DereferencePolicy.NEVER, 0, 0);
  }



  /**
   * Performs a search in the directory for objects matching the contents of
   * the provided object.  A search filter will be generated from the provided
   * object containing all non-{@code null} values from fields and getter
   * methods whose {@link LDAPField} or {@link LDAPFieldGetter} annotation has
   * the {@code inFilter} element set to {@code true}.
   * <BR><BR>
   * Note that this method requires an {@link LDAPConnection} argument rather
   * than using the more generic {@link LDAPInterface} type because the search
   * is invoked as an asynchronous operation, which is not supported by the
   * generic {@code LDAPInterface} interface.  It also means that the provided
   * connection must not be configured to operate in synchronous mode (via the
   * {@link com.unboundid.ldap.sdk.LDAPConnectionOptions#setUseSynchronousMode}
   * option).
   *
   * @param  o            The object to use to construct the search filter.  It
   *                      must not be {@code null}.
   * @param  c            The connection to use to communicate with the
   *                      directory server.  It must not be {@code null}.
   * @param  baseDN       The base DN to use for the search.  It may be
   *                      {@code null} if the {@link LDAPObject#defaultParentDN}
   *                      element in the {@code LDAPObject}
   * @param  scope        The scope to use for the search operation.  It must
   *                      not be {@code null}.
   * @param  derefPolicy  The dereference policy to use for the search
   *                      operation.  It must not be {@code null}.
   * @param  sizeLimit    The maximum number of entries to retrieve from the
   *                      directory.  A value of zero indicates that no
   *                      client-requested size limit should be enforced.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing the search.  A value of zero
   *                      indicates that no client-requested time limit should
   *                      be enforced.
   *
   * @return  A results object that may be used to iterate through the objects
   *          returned from the search.
   *
   * @throws  LDAPPersistException  If an error occurs while preparing or
   *                                sending the search request.
   */
  public PersistedObjects<T> search(final T o, final LDAPConnection c,
                                    final String baseDN,
                                    final SearchScope scope,
                                    final DereferencePolicy derefPolicy,
                                    final int sizeLimit, final int timeLimit)
         throws LDAPPersistException
  {
    ensureNotNull(o, c, scope, derefPolicy);

    final String base;
    if (baseDN == null)
    {
      base = handler.getDefaultParentDN().toString();
    }
    else
    {
      base = baseDN;
    }

    final Filter filter = handler.createFilter(o);

    final SearchRequest searchRequest = new SearchRequest(base, scope,
         derefPolicy, sizeLimit, timeLimit, false, filter, "*", "+");

    final LDAPEntrySource entrySource;
    try
    {
      entrySource = new LDAPEntrySource(c, searchRequest, false);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPPersistException(le);
    }

    return new PersistedObjects<T>(this, entrySource);
  }



  /**
   * Performs a search in the directory for objects matching the contents of the
   * provided object.  A search filter will be generated from the provided
   * object containing all non-{@code null} values from fields and getter
   * methods whose {@link LDAPField} or {@link LDAPFieldGetter} annotation has
   * the {@code inFilter} element set to {@code true}.
   * <BR><BR>
   * The search performed will be a subtree search using a base DN equal to the
   * {@link LDAPObject#defaultParentDN} element in the {@code LDAPObject}
   * annotation.  It will not enforce a client-side time limit or size limit.
   *
   * @param  o  The object to use to construct the search filter.  It must not
   *            be {@code null}.
   * @param  i  The interface to use to communicate with the directory server.
   *            It must not be {@code null}.
   * @param  l  The persist search result listener that will be used to receive
   *            objects decoded from entries returned for the search.  It must
   *            not be {@code null}.
   *
   * @return  The result of the search operation that was processed.
   *
   * @throws  LDAPPersistException  If an error occurs while preparing or
   *                                sending the search request.
   */
  public SearchResult search(final T o, final LDAPInterface i,
                             final PersistSearchListener<T> l)
         throws LDAPPersistException
  {
    return search(o, i, null, SearchScope.SUB, DereferencePolicy.NEVER, 0, 0,
         l);
  }



  /**
   * Performs a search in the directory for objects matching the contents of the
   * provided object.  A search filter will be generated from the provided
   * object containing all non-{@code null} values from fields and getter
   * methods whose {@link LDAPField} or {@link LDAPFieldGetter} annotation has
   * the {@code inFilter} element set to {@code true}.
   * <BR><BR>
   * The search performed will be a subtree search using a base DN equal to the
   * {@link LDAPObject#defaultParentDN} element in the {@code LDAPObject}
   * annotation.  It will not enforce a client-side time limit or size limit.
   *
   * @param  o       The object to use to construct the search filter.  It must
   *                 not be {@code null}.
   * @param  i       The interface to use to communicate with the directory
   *                 server. It must not be {@code null}.
   * @param  baseDN  The base DN to use for the search.  It may be {@code null}
   *                 if the {@link LDAPObject#defaultParentDN} element in the
   *                 {@code LDAPObject}
   * @param  scope   The scope to use for the search operation.  It must not be
   *                 {@code null}.
   * @param  l       The persist search result listener that will be used to
   *                 receive objects decoded from entries returned for the
   *                 search.  It must not be {@code null}.
   *
   * @return  A results object that may be used to iterate through the objects
   *          returned from the search.
   *
   * @throws  LDAPPersistException  If an error occurs while preparing or
   *                                sending the search request.
   */
  public SearchResult search(final T o, final LDAPInterface i,
                             final String baseDN, final SearchScope scope,
                             final PersistSearchListener<T> l)
         throws LDAPPersistException
  {
    return search(o, i, baseDN, scope, DereferencePolicy.NEVER, 0, 0, l);
  }



  /**
   * Performs a search in the directory for objects matching the contents of
   * the provided object.  A search filter will be generated from the provided
   * object containing all non-{@code null} values from fields and getter
   * methods whose {@link LDAPField} or {@link LDAPFieldGetter} annotation has
   * the {@code inFilter} element set to {@code true}.
   *
   * @param  o            The object to use to construct the search filter.  It
   *                      must not be {@code null}.
   * @param  i            The connection to use to communicate with the
   *                      directory server.  It must not be {@code null}.
   * @param  baseDN       The base DN to use for the search.  It may be
   *                      {@code null} if the {@link LDAPObject#defaultParentDN}
   *                      element in the {@code LDAPObject}
   * @param  scope        The scope to use for the search operation.  It must
   *                      not be {@code null}.
   * @param  derefPolicy  The dereference policy to use for the search
   *                      operation.  It must not be {@code null}.
   * @param  sizeLimit    The maximum number of entries to retrieve from the
   *                      directory.  A value of zero indicates that no
   *                      client-requested size limit should be enforced.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing the search.  A value of zero
   *                      indicates that no client-requested time limit should
   *                      be enforced.
   * @param  l            The persist search result listener that will be used
   *                      to receive objects decoded from entries returned for
   *                      the search.  It must not be {@code null}.
   *
   * @return  A results object that may be used to iterate through the objects
   *          returned from the search.
   *
   * @throws  LDAPPersistException  If an error occurs while preparing or
   *                                sending the search request.
   */
  public SearchResult search(final T o, final LDAPInterface i,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final PersistSearchListener<T> l)
         throws LDAPPersistException
  {
    ensureNotNull(o, i, scope, derefPolicy, l);

    final String base;
    if (baseDN == null)
    {
      base = handler.getDefaultParentDN().toString();
    }
    else
    {
      base = baseDN;
    }

    final Filter filter = handler.createFilter(o);

    final SearchListenerBridge<T> bridge = new SearchListenerBridge<T>(this, l);

    final SearchRequest searchRequest = new SearchRequest(bridge, base, scope,
         derefPolicy, sizeLimit, timeLimit, false, filter, "*", "+");

    try
    {
      return i.search(searchRequest);
    }
    catch (LDAPException le)
    {
      throw new LDAPPersistException(le);
    }
  }
}
