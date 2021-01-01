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
 * This interface defines an API that may be used to establish a connection
 * (and perform authentication if appropriate) to a remote server when following
 * a referral.
 * <BR><BR>
 * Implementations of this interface should be threadsafe to ensure that
 * multiple connections will be able to safely use the same
 * {@code ReferralConnector} instance.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface ReferralConnector
{
  /**
   * Retrieves an (optionally authenticated) LDAP connection for use in
   * following a referral as defined in the provided LDAP URL.  The connection
   * will automatically be closed after the referral has been followed.
   *
   * @param  referralURL  The LDAP URL representing the referral being followed.
   * @param  connection   The connection on which the referral was received.
   *
   * @return  An LDAP connection established and optionally authenticated to the
   *          target system that may be used to attempt to follow a referral.
   *
   * @throws  LDAPException  If a problem occurs while establishing the
   *                         connection or performing authentication on it.  If
   *                         an exception is thrown, then any underlying
   *                         connection should be terminated before the
   *                         exception is thrown.
   */
  @NotNull()
  LDAPConnection getReferralConnection(@NotNull LDAPURL referralURL,
                                       @NotNull LDAPConnection connection)
                 throws LDAPException;
}
