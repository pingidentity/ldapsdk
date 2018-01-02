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
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;



/**
 * This class provides a bridge between the {@link SearchResultListener}
 * interface used to receive entries returned by a search operation and the
 * {@link ObjectSearchListener} interface used to provide those entries as
 * decoded objects.
 *
 * @param  <T>  The type of object accessed by this class.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class SearchListenerBridge<T>
      implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1939354785788059032L;



  // The persister that will be used to decode any entries that are returned.
  private final LDAPPersister<T> persister;

  // The listener to which decoded objects will be provided.
  private final ObjectSearchListener<T> listener;



  /**
   * Creates a new instance of this search listener bridge that will use the
   * given persister to decode search result entries and forward them to the
   * provided object search listener.
   *
   * @param  persister  The persister that will be used to decode entries that
   *                    are returned during search processing.
   * @param  listener   The listener to which decoded objects should be
   *                    forwarded.
   */
  SearchListenerBridge(final LDAPPersister<T> persister,
                       final ObjectSearchListener<T> listener)
  {
    this.persister = persister;
    this.listener  = listener;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    try
    {
      listener.objectReturned(persister.decode(searchEntry));
    }
    catch (final LDAPPersistException lpe)
    {
      debugException(lpe);
      listener.unparsableEntryReturned(searchEntry, lpe);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    listener.searchReferenceReturned(searchReference);
  }
}
