/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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



import java.io.Serializable;

import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be used to obtain a clear-text password
 * that may be used for authentication or other purposes.  Passwords must be
 * returned in the form of a byte array, and the contents of that array will be
 * zeroed out as soon as the password is no longer required in order to minimize
 * the length of time that the password will remain in memory.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class PasswordProvider
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1582416755360005908L;



  /**
   * Retrieves a password in a newly-created byte array.  Once the password is
   * no longer required, the contents of the array will be overwritten so that
   * the password is no longer contained in memory.
   *
   * @return  A byte array containing the password that should be used.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         obtain the password.
   */
  public abstract byte[] getPasswordBytes()
         throws LDAPException;
}
