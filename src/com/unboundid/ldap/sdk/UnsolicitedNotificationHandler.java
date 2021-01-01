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
 * This interface defines a method that may be invoked if an unsolicited
 * notification is received from the directory server.  An unsolicited
 * notification handler should be defined in the {@link LDAPConnectionOptions}
 * for an {@link LDAPConnection} to be called whenever an unsolicited
 * notification is received for that connection.
 * <BR><BR>
 * An unsolicited notification is a type of extended response that is sent from
 * the server to the client without a corresponding request, and it may be used
 * to alert the client of a significant server-side event.  For example,
 * section 4.4.1 of <A HREF="http://www.ietf.org/rfc/rfc4511.txt">RFC 4511</A>
 * defines a notice of disconnection unsolicited notification that can be used
 *  by the server to inform the client that it is about to close the connection.
 * <BR><BR>
 * Implementations of this interface should be threadsafe to ensure that
 * multiple connections will be able to safely use the same
 * {@code UnsolicitedNotificationHandler} instance.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface UnsolicitedNotificationHandler
{
  /**
   * Performs any processing that may be necessary in response to the provided
   * unsolicited notification that has been received from the server.
   *
   * @param  connection    The connection on which the unsolicited notification
   *                       was received.
   * @param  notification  The unsolicited notification that has been received
   *                       from the server.
   */
  void handleUnsolicitedNotification(@NotNull LDAPConnection connection,
                                     @NotNull ExtendedResult notification);
}
