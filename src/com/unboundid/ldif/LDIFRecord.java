/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldif;



import java.io.Serializable;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a common API for LDIF records, which are objects that
 * can be represented using LDIF.  This includes both
 * {@link com.unboundid.ldap.sdk.Entry} and {@link LDIFChangeRecord} objects.
 * It is possible to obtain the DN of an LDIF record, as well as to obtain the
 * LDIF representation of that object.  They can be read using the
 * {@link LDIFReader#readLDIFRecord} method and written using the
 * {@link LDIFWriter#writeLDIFRecord} method.
 * <BR><BR>
 * This interface defines a data type that is intended to be implemented only
 * by classes within the LDAP SDK.  Third-party code may reference objects using
 * this data type, but external classes should not create additional
 * implementations of this interface.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDIFRecord
       extends Serializable
{
  /**
   * Retrieves the string representation of the DN for this LDIF record.
   *
   * @return  The string representation of the DN for this LDIF record.
   */
  @NotNull()
  String getDN();



  /**
   * Retrieves the parsed DN for this LDIF record as a {@link DN} object.
   *
   * @return  The parsed DN for this LDIF record as a {@link DN} object.
   *
   * @throws  LDAPException  If a problem occurs while trying to parse the DN.
   */
  @NotNull()
  DN getParsedDN()
     throws LDAPException;



  /**
   * Retrieves an LDIF representation of this LDIF record, with each line of
   * the LDIF representation in a separate element of the returned array.  Long
   * lines will not be wrapped.
   *
   * @return  An LDIF representation of this LDIF record.
   */
  @NotNull()
  String[] toLDIF();



  /**
   * Retrieves an LDIF representation of this LDIF record, with each line of
   * the LDIF representation in a separate element of the returned array.
   *
   * @param  wrapColumn  The column at which to wrap long lines.  A value that
   *                     is less than or equal to two indicates that no
   *                     wrapping should be performed.
   *
   * @return  An LDIF representation of this LDIF record.
   */
  @NotNull()
  String[] toLDIF(int wrapColumn);



  /**
   * Appends an LDIF-formatted string representation of this LDIF record to the
   * provided buffer.  No wrapping will be performed, and no extra blank lines
   * will be added.
   *
   * @param  buffer  The buffer to which to append the LDIF representation of
   *                 this LDIF record.
   */
  void toLDIF(@NotNull ByteStringBuffer buffer);



  /**
   * Appends an LDIF-formatted string representation of this LDIF record to the
   * provided buffer.  No extra blank lines will be added.
   *
   * @param  buffer      The buffer to which to append the LDIF representation
   *                     of this LDIF record.
   * @param  wrapColumn  The column at which to wrap long lines.  A value that
   *                     is less than or equal to two indicates that no
   *                     wrapping should be performed.
   */
  void toLDIF(@NotNull ByteStringBuffer buffer, int wrapColumn);



  /**
   * Retrieves an LDIF-formatted string representation of this LDIF record.  No
   * wrapping will be performed, and no extra blank lines will be added.
   *
   * @return  An LDIF-formatted string representation of this entry.
   */
  @NotNull()
  String toLDIFString();



  /**
   * Retrieves an LDIF-formatted string representation of this LDIF record.  No
   * extra blank lines will be added.
   *
   * @param  wrapColumn  The column at which to wrap long lines.  A value that
   *                     is less than or equal to two indicates that no
   *                     wrapping should be performed.
   *
   * @return  An LDIF-formatted string representation of this entry.
   */
  @NotNull()
  String toLDIFString(int wrapColumn);



  /**
   * Appends an LDIF-formatted string representation of this LDIF record to the
   * provided buffer.  No wrapping will be performed, and no extra blank lines
   * will be added.
   *
   * @param  buffer  The buffer to which to append the LDIF representation of
   *                 this LDIF record.
   */
  void toLDIFString(@NotNull StringBuilder buffer);



  /**
   * Appends an LDIF-formatted string representation of this LDIF record to the
   * provided buffer.  No extra blank lines will be added.
   *
   * @param  buffer      The buffer to which to append the LDIF representation
   *                     of this LDIF record.
   * @param  wrapColumn  The column at which to wrap long lines.  A value that
   *                     is less than or equal to two indicates that no
   *                     wrapping should be performed.
   */
  void toLDIFString(@NotNull StringBuilder buffer, int wrapColumn);



  /**
   * Retrieves a string representation of this LDIF record.  Note that it will
   * be a single-line string representation and will therefore not be an LDIF
   * representation.
   *
   * @return  A string representation of this LDIF record.
   */
  @Override()
  @NotNull()
  String toString();



  /**
   * Appends a string representation of this LDIF record to the provided buffer.
   * Note that it will be a single-line string representation and will
   * therefore not be an LDIF representation.
   *
   * @param  buffer  The buffer to which the string representation of this LDIF
   *                 record should be appended.
   */
  void toString(@NotNull StringBuilder buffer);
}
