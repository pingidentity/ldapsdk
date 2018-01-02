/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that provide access to objects
 * returned by the {@link LDAPPersister} class in the course of performing a
 * search.
 *
 * @param  <T>  The type of object handled by this class.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ObjectSearchListener<T>
{
  /**
   * Indicates that the provided object was created from an entry retrieved from
   * the directory server in the course of processing the search operation.
   *
   * @param  o  The object that has been decoded from the entry that was
   *            returned.  It will never be {@code null}.
   */
  void objectReturned(T o);



  /**
   * Indicates that the provided entry was retrieved from the director server
   * in the course of processing the search operation, but an error occurred
   * while attempting to instantiate an object from it.
   *
   * @param  entry      The entry that was retrieved from the directory server
   *                    but could not be decoded as an object.
   * @param  exception  The exception that was encountered while trying to
   *                    create and initialize an object from the provided entry.
   */
  void unparsableEntryReturned(SearchResultEntry entry,
                               LDAPPersistException exception);



  /**
   * Indicates that the provided search result reference was retrieved from the
   * directory server in the course of processing the search operation.
   *
   * @param  searchReference  The search result reference that has been
   *                          retrieved from the server.
   */
  void searchReferenceReturned(SearchResultReference searchReference);
}
