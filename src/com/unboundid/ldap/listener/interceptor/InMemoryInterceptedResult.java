/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an API that can be used in the course of processing a
 * result via the {@link InMemoryOperationInterceptor} API.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface InMemoryInterceptedResult
{
  /**
   * Retrieves the connection ID for the associated client connection.
   *
   * @return  The connection ID for the associated client connection.
   */
  long getConnectionID();



  /**
   * Retrieves the server address to which the client is connected, if
   * available.
   *
   * @return  The server address to which the client is connected, or
   *          {@code null} if this is not available for some reason.
   */
  String getConnectedAddress();



  /**
   * Retrieves the server port to which the client is connected, if available.
   *
   * @return  The server port to which the client is connected, or -1 if this is
   *          not available for some reason.
   */
  int getConnectedPort();



  /**
   * Retrieves the LDAP message ID for this operation.
   *
   * @return  The LDAP message ID for this operation.
   */
  int getMessageID();



  /**
   * Sends an unsolicited notification message to the client.
   *
   * @param  unsolicitedNotification  The unsolicited notification to send to
   *                                  the client.  It must not be {@code null}.
   *
   * @throws  LDAPException  If a problem is encountered while trying to send
   *                         the unsolicited notification.
   */
  void sendUnsolicitedNotification(ExtendedResult unsolicitedNotification)
         throws LDAPException;



  /**
   * Retrieves the value for a property that has previously been set for this
   * operation.  This can be used to help maintain state information across the
   * request and response for an operation.
   *
   * @param  name  The name of the property for which to retrieve the
   *               corresponding value.  It must not be {@code null}.
   *
   * @return  The value for the requested property, or {@code null} if there is
   *          no value for the specified property.
   */
  Object getProperty(String name);
}
