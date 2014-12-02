/*
 * Copyright 2010-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2014 UnboundID Corp.
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



import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ObjectPair;



/**
 * This interface may be implemented by a class which wishes to intercept and
 * alter search result references in some way before they are returned to the
 * client, and/or to prevent them from being returned altogether.  Search
 * reference transformers may be enabled or disabled by adding them to or
 * removing them from an {@link LDAPListenerClientConnection}.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface SearchReferenceTransformer
{
  /**
   * Transforms the provided search result reference and/or set of controls to
   * alter what will be returned to the client.
   *
   * @param  messageID  The message ID for the associated search operation.
   * @param  reference  The search result reference to be processed.  It will
   *                    not be {@code null}.
   * @param  controls   The set of controls to be processed.  It will not be
   *                    {@code null} but may be empty if there are no controls.
   *
   * @return  An {@link ObjectPair} containing a possibly updated reference and
   *          set of controls, or {@code null} to indicate that the reference
   *          should not be returned to the client.
   */
  ObjectPair<SearchResultReferenceProtocolOp,Control[]> transformReference(
       final int messageID, final SearchResultReferenceProtocolOp reference,
       final Control[] controls);
}
