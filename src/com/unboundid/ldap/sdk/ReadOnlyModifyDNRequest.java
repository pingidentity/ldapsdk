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



import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
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
  @NotNull()
  String getDN();



  /**
   * Retrieves the new RDN for the entry.
   *
   * @return  The new RDN for the entry.
   */
  @NotNull()
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
  @Nullable()
  String getNewSuperiorDN();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  ModifyDNRequest duplicate();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  ModifyDNRequest duplicate(@Nullable Control[] controls);



  /**
   * Retrieves an LDIF modify DN change record with the contents of this modify
   * DN request.
   *
   * @return  An LDIF modify DN change record with the contents of this modify
   *          DN request.
   */
  @NotNull()
  LDIFModifyDNChangeRecord toLDIFChangeRecord();



  /**
   * Retrieves a string array whose lines contain an LDIF representation of the
   * corresponding modify DN change record.
   *
   * @return  A string array whose lines contain an LDIF representation of the
   *          corresponding modify DN change record.
   */
  @NotNull()
  String[] toLDIF();



  /**
   * Retrieves an LDIF string representation of this modify DN request.
   *
   * @return  An LDIF string representation of this modify DN request.
   */
  @NotNull()
  String toLDIFString();
}
