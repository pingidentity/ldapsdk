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



import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface provides the ability to perform custom processing immediately
 * after creating an LDAP connection for use in a connection pool.  It may be
 * used, for example, to perform StartTLS negotiation on the connection before
 * it is made available for use in the pool.
 * <BR><BR>
 * Implementations of this interface must be threadsafe to allow for the
 * possibility of performing post-connect processing on different connections
 * at the same time in separate threads.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface PostConnectProcessor
{
  /**
   * Performs any appropriate processing on the provided connection before
   * making it available for use in a connection pool.  This method will be
   * invoked immediately after the connection has been established but before
   * any attempt has been made to perform any authentication.
   *
   * @param  connection  The connection for which the processing is to be
   *                     performed.
   *
   * @throws  LDAPException  If a problem occurs during processing.  If an
   *                         exception is thrown, then the connection will be
   *                         terminated and not used in the pool.
   */
  void processPreAuthenticatedConnection(@NotNull LDAPConnection connection)
       throws LDAPException;



  /**
   * Performs any appropriate processing on the provided connection before
   * making it available for use in a connection pool.  This method will be
   * invoked immediately after any appropriate authentication has been performed
   * on the connection.
   *
   * @param  connection  The connection for which the processing is to be
   *                     performed.
   *
   * @throws  LDAPException  If a problem occurs during processing.  If an
   *                         exception is thrown, then the connection will be
   *                         terminated and not used in the pool.
   */
  void processPostAuthenticatedConnection(@NotNull LDAPConnection connection)
       throws LDAPException;
}
