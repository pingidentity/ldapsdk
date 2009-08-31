/*
 * Copyright 2007-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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



import java.util.List;

import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that may be safely called in an LDAP
 * add request without altering its contents.  This interface must not be
 * implemented by any class other than {@link AddRequest}.
 * <BR><BR>
 * This interface does not inherently provide the assurance of thread safety for
 * the methods that it exposes, because it is still possible for a thread
 * referencing the object which implements this interface to alter the request
 * using methods not included in this interface.  However, if it can be
 * guaranteed that no thread will alter the underlying object, then the methods
 * exposed by this interface can be safely invoked concurrently by any number of
 * threads.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlyAddRequest
       extends ReadOnlyLDAPRequest
{
  /**
   * Retrieves the DN for this add request.
   *
   * @return  The DN for this add request.
   */
  String getDN();



  /**
   * Retrieves the set of attributes for this add request.
   *
   * @return  The set of attributes for this add request.
   */
  List<Attribute> getAttributes();



  /**
   * {@inheritDoc}
   */
  AddRequest duplicate();



  /**
   * {@inheritDoc}
   */
  AddRequest duplicate(final Control[] controls);



  /**
   * Retrieves an LDIF add change record with the contents of this add request.
   *
   * @return  An LDIF add change record with the contents of this add request.
   */
  LDIFAddChangeRecord toLDIFChangeRecord();



  /**
   * Retrieves a string array whose lines contain an LDIF representation of the
   * corresponding add change record.
   *
   * @return  A string array whose lines contain an LDIF representation of the
   *          corresponding add change record.
   */
  String[] toLDIF();



  /**
   * Retrieves an LDIF string representation of this add request.
   *
   * @return  An LDIF string representation of this add request.
   */
  String toLDIFString();
}
