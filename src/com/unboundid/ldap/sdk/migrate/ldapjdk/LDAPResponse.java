/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that represents a response that may be
 * received from a directory server.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the {@link LDAPResult} class
 * should be used instead.
 */
@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPResponse
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8401666939604882177L;



  // The LDAP result for this LDAP response.
  @NotNull private final LDAPResult ldapResult;



  /**
   * Creates a new LDAP response from the provided {@link LDAPResult}.
   *
   * @param  ldapResult  The {@code LDAPResult} object to use to create this
   *                     LDAP response.
   */
  public LDAPResponse(@NotNull final LDAPResult ldapResult)
  {
    this.ldapResult = ldapResult;
  }



  /**
   * Retrieves the LDAP message ID for this LDAP response.
   *
   * @return  The LDAP message ID for this LDAP response.
   */
  public int getMessageID()
  {
    return ldapResult.getMessageID();
  }



  /**
   * Retrieves the result code for this LDAP response.
   *
   * @return  The result code for this LDAP response.
   */
  public int getResultCode()
  {
    return ldapResult.getResultCode().intValue();
  }



  /**
   * Retrieves the error message for this LDAP response, if available.
   *
   * @return  The error message for this LDAP response, or {@code null} if there
   *          is none.
   */
  @Nullable()
  public String getErrorMessage()
  {
    return ldapResult.getDiagnosticMessage();
  }



  /**
   * Retrieves the matched DN for this LDAP response, if available.
   *
   * @return  The matched DN for this LDAP response, or {@code null} if there
   *          is none.
   */
  @Nullable()
  public String getMatchedDN()
  {
    return ldapResult.getMatchedDN();
  }



  /**
   * Retrieves the set of referrals for this LDAP response, if any.
   *
   * @return  The set of referrals for this LDAP response, or {@code null} if
   *          there are none.
   */
  @Nullable()
  public String[] getReferrals()
  {
    final String[] referrals = ldapResult.getReferralURLs();
    if (referrals.length == 0)
    {
      return null;
    }
    else
    {
      return referrals;
    }
  }



  /**
   * Retrieves the list of controls for this LDAP response, if any.
   *
   * @return  The list of controls for this LDAP response, or {@code null} if
   *          there are none.
   */
  @Nullable()
  public LDAPControl[] getControls()
  {
    final Control[] controls = ldapResult.getResponseControls();
    if (controls.length == 0)
    {
      return null;
    }

    return LDAPControl.toLDAPControls(controls);
  }



  /**
   * Retrieves an {@link LDAPResult} object that is the equivalent of this LDAP
   * response.
   *
   * @return  An {@code LDAPResult} object that is the equivalent of this LDAP
   *          response.
   */
  @NotNull()
  public final LDAPResult toLDAPResult()
  {
    return ldapResult;
  }



  /**
   * Retrieves a string representation of this LDAP response.
   *
   * @return  A string representation of this LDAP response.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return ldapResult.toString();
  }
}
