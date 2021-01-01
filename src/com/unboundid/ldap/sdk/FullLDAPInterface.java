/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import java.io.Closeable;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that are available for objects that
 * may be used to communicate with an LDAP directory server (or something that
 * simulates an LDAP directory server).  This can be used to facilitate
 * development of methods which can be used for either a single LDAP connection
 * or an LDAP  pool.  This interface extends the basic
 * {@link LDAPInterface} interface to also include support for bind and extended
 * operations, although those operations should be used with care because they
 * may alter the state of the associated connection (or connection-like object),
 * and in some cases (like a connection pool with multiple connections, where it
 * may not be possible to guarantee that successive operations are processed on
 * the same underlying connection), this may result in unexpected behavior.
 * <BR><BR>
 * This interface also extends the {@code Closeable} interface so that the
 * underlying connection (or connection-like object) may be closed.  After it
 * has been closed, no attempt should be made to re-use the object to perform
 * LDAP (or LDAP-like) communication.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface FullLDAPInterface
       extends LDAPInterface, Closeable
{
  /**
   * Closes the associated interface and frees any resources associated with it.
   * This method may be safely called multiple times, but the associated
   * interface should not be used after it has been closed.
   */
  @Override()
  void close();



  /**
   * Processes a simple bind request with the provided DN and password.
   *
   * @param  bindDN    The bind DN for the bind operation.
   * @param  password  The password for the simple bind operation.
   *
   * @return  The result of processing the bind operation.
   *
   * @throws  LDAPException  If the server rejects the bind request, or if a
   *                         problem occurs while sending the request or reading
   *                         the response.
   */
  @NotNull()
  BindResult bind(@Nullable String bindDN, @Nullable String password)
       throws LDAPException;



  /**
   * Processes the provided bind request.
   *
   * @param  bindRequest  The bind request to be processed.  It must not be
   *                      {@code null}.
   *
   * @return  The result of processing the bind operation.
   *
   * @throws  LDAPException  If the server rejects the bind request, or if a
   *                         problem occurs while sending the request or reading
   *                         the response.
   */
  @NotNull()
  BindResult bind(@NotNull BindRequest bindRequest)
       throws LDAPException;



  /**
   * Processes an extended operation with the provided request OID and no value.
   *
   * @param  requestOID  The OID for the extended request to process.  It must
   *                     not be {@code null}.
   *
   * @return  The extended result object that provides information about the
   *          result of the request processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  ExtendedResult processExtendedOperation(@NotNull String requestOID)
       throws LDAPException;



  /**
   * Processes an extended operation with the provided request OID and value.
   *
   * @param  requestOID    The OID for the extended request to process.  It must
   *                       not be {@code null}.
   * @param  requestValue  The encoded value for the extended request to
   *                       process.  It may be {@code null} if there does not
   *                       need to be a value for the requested operation.
   *
   * @return  The extended result object that provides information about the
   *          result of the request processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  ExtendedResult processExtendedOperation(@NotNull String requestOID,
                      @Nullable ASN1OctetString requestValue)
       throws LDAPException;



  /**
   * Processes the provided extended request.
   *
   * @param  extendedRequest  The extended request to be processed.  It must not
   *                          be {@code null}.
   *
   * @return  The extended result object that provides information about the
   *          result of the request processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  ExtendedResult processExtendedOperation(
                      @NotNull ExtendedRequest extendedRequest)
       throws LDAPException;
}
