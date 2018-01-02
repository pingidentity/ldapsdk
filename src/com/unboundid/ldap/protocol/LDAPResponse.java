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
package com.unboundid.ldap.protocol;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface serves as a marker for classes in the
 * {@code com.unboundid.ldap.sdk} package that are responses which may be
 * received from a directory server.
 *
 */
@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface LDAPResponse
{
  /**
   * An empty set of controls.
   */
  Control[] NO_CONTROLS = new Control[0];



  /**
   * Retrieves the message ID for the LDAP message containing this response.
   *
   * @return  The message ID for the LDAP message containing this response.
   */
  int getMessageID();



  /**
   * Appends a string representation of this LDAP response to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  void toString(StringBuilder buffer);
}
