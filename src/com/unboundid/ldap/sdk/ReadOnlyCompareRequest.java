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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that may be safely called in an LDAP
 * compare request without altering its contents.  This interface must not be
 * implemented by any class other than {@link CompareRequest}.
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
public interface ReadOnlyCompareRequest
       extends ReadOnlyLDAPRequest
{
  /**
   * Retrieves the DN of the entry in which the comparison is to be performed.
   *
   * @return  The DN of the entry in which the comparison is to be performed.
   */
  String getDN();



  /**
   * Retrieves the name of the attribute for which the comparison is to be
   * performed.
   *
   * @return  The name of the attribute for which the comparison is to be
   *          performed.
   */
  String getAttributeName();



  /**
   * Retrieves the assertion value to verify within the target entry.
   *
   * @return  The assertion value to verify within the target entry.
   */
  String getAssertionValue();



  /**
   * Retrieves the assertion value to verify within the target entry, formatted
   * as a byte array.
   *
   * @return  The assertion value to verify within the target entry, formatted
   *          as a byte array.
   */
  byte[] getAssertionValueBytes();



  /**
   * Retrieves the assertion value to verify within the target entry.
   *
   * @return  The assertion value to verify within the target entry.
   */
  ASN1OctetString getRawAssertionValue();



  /**
   * {@inheritDoc}
   */
  @Override()
  CompareRequest duplicate();



  /**
   * {@inheritDoc}
   */
  @Override()
  CompareRequest duplicate(Control[] controls);
}
