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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
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
  @NotNull()
  String getDN();



  /**
   * Retrieves the name of the attribute for which the comparison is to be
   * performed.
   *
   * @return  The name of the attribute for which the comparison is to be
   *          performed.
   */
  @NotNull()
  String getAttributeName();



  /**
   * Retrieves the assertion value to verify within the target entry.
   *
   * @return  The assertion value to verify within the target entry.
   */
  @NotNull()
  String getAssertionValue();



  /**
   * Retrieves the assertion value to verify within the target entry, formatted
   * as a byte array.
   *
   * @return  The assertion value to verify within the target entry, formatted
   *          as a byte array.
   */
  @NotNull()
  byte[] getAssertionValueBytes();



  /**
   * Retrieves the assertion value to verify within the target entry.
   *
   * @return  The assertion value to verify within the target entry.
   */
  @NotNull()
  ASN1OctetString getRawAssertionValue();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  CompareRequest duplicate();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  CompareRequest duplicate(@Nullable Control[] controls);
}
