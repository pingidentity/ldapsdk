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



import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an exception that may be returned if a referral is
 * returned in response for an operation.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the
 * {@link com.unboundid.ldap.sdk.LDAPException} class should be used instead.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPReferralException
       extends LDAPException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7867903105944011998L;



  // The referral URLs for this exception.
  @NotNull private final String[] referralURLs;



  /**
   * Creates a new LDAP referral exception with no information.
   */
  public LDAPReferralException()
  {
    super(null, REFERRAL);

    referralURLs = new String[0];
  }



  /**
   * Creates a new LDAP referral exception with the provided information.
   *
   * @param  message             The message for this LDAP referral exception.
   * @param  resultCode          The result code for this LDAP referral
   *                             exception.
   * @param  serverErrorMessage  The error message returned from the server.
   */
  public LDAPReferralException(@Nullable final String message,
                               final int resultCode,
                               @Nullable final String serverErrorMessage)
  {
    super(message, resultCode, serverErrorMessage, null);

    referralURLs = new String[0];
  }



  /**
   * Creates a new LDAP referral exception with the provided information.
   *
   * @param  message     The message for this LDAP referral exception.
   * @param  resultCode  The result code for this LDAP referral exception.
   * @param  referrals   The set of referrals for this exception.
   */
  public LDAPReferralException(@Nullable final String message,
                               final int resultCode,
                               @NotNull final String[] referrals)
  {
    super(message, resultCode, null, null);

    referralURLs = referrals;
  }



  /**
   * Creates a new LDAP referral exception from the provided
   * {@link com.unboundid.ldap.sdk.LDAPException} object.
   *
   * @param  ldapException  The {@code LDAPException} object to use for this
   *                        LDAP interrupted exception.
   */
  public LDAPReferralException(
              @NotNull final com.unboundid.ldap.sdk.LDAPException ldapException)
  {
    super(ldapException);

    referralURLs = ldapException.getReferralURLs();
  }



  /**
   * Creates a new LDAP referral exception from the provided
   * {@link SearchResultReference} object.
   *
   * @param  reference  The {@code SearchResultReference} object to use to
   *                    create this exception.
   */
  public LDAPReferralException(@NotNull final SearchResultReference reference)
  {
    super(null, REFERRAL);

    referralURLs = reference.getReferralURLs();
  }



  /**
   * Retrieves the set of referral URLs for this exception.
   *
   * @return  The set of referral URLs for this exception.
   */
  @NotNull()
  public String[] getURLs()
  {
    return referralURLs;
  }
}
