/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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



import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that may be safely called in an LDAP
 * modify DN request without altering its contents.  This interface must not be
 * implemented by any class other than {@link ModifyDNRequest}.
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
public interface ReadOnlyModifyDNRequest
       extends ReadOnlyLDAPRequest
{
  /**
   * Retrieves the current DN of the entry to move/rename.
   *
   * @return  The current DN of the entry to move/rename.
   */
  String getDN();



  /**
   * Retrieves the new RDN for the entry.
   *
   * @return  The new RDN for the entry.
   */
  String getNewRDN();



  /**
   * Indicates whether the current RDN value should be removed from the entry.
   *
   * @return  {@code true} if the current RDN value should be removed from the
   *          entry, or {@code false} if not.
   */
  boolean deleteOldRDN();



  /**
   * Retrieves the new superior DN for the entry.
   *
   * @return  The new superior DN for the entry, or {@code null} if the entry is
   *          not to be moved below a new parent.
   */
  String getNewSuperiorDN();



  /**
   * {@inheritDoc}
   */
  @Override()
  ModifyDNRequest duplicate();



  /**
   * {@inheritDoc}
   */
  @Override()
  ModifyDNRequest duplicate(Control[] controls);



  /**
   * Retrieves an LDIF modify DN change record with the contents of this modify
   * DN request.
   *
   * @return  An LDIF modify DN change record with the contents of this modify
   *          DN request.
   */
  LDIFModifyDNChangeRecord toLDIFChangeRecord();



  /**
   * Retrieves a string array whose lines contain an LDIF representation of the
   * corresponding modify DN change record.
   *
   * @return  A string array whose lines contain an LDIF representation of the
   *          corresponding modify DN change record.
   */
  String[] toLDIF();



  /**
   * Retrieves an LDIF string representation of this modify DN request.
   *
   * @return  An LDIF string representation of this modify DN request.
   */
  String toLDIFString();
}
