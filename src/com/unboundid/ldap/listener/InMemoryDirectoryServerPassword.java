/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.OctetStringMatchingRule;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that encapsulates a password used by the
 * in-memory directory server.  It may be optionally associated with an
 * {@link InMemoryPasswordEncoder}.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InMemoryDirectoryServerPassword
{
  // The password as it is (or has the potential to be) stored in the in-memory
  // directory server.
  @NotNull private final ASN1OctetString storedPassword;

  // The password encoder that should be used when interacting with the stored
  // password.
  @Nullable private final InMemoryPasswordEncoder passwordEncoder;

  // The user entry with which the stored password is associated.
  @NotNull private final ReadOnlyEntry userEntry;

  // The name of the attribute with which the stored password is associated.
  @NotNull private final String attributeName;



  /**
   * Creates a new in-memory directory server password with the provided
   * information.
   *
   * @param  storedPassword    The password as it is (or has the potential to
   *                           be) stored in the in-memory directory server.  It
   *                           must not be {@code null}.
   * @param  userEntry         The user entry with which the stored password is
   *                           associated.  It must not be {@code nulL}.
   * @param  attributeName     The name of the attribute with which the stored
   *                           password is associated.  It must not be
   *                           {@code null}.
   * @param  passwordEncoders  The set of password encoders configured for the
   *                           in-memory directory server.  It must not be
   *                           {@code null} but may be empty.
   */
  InMemoryDirectoryServerPassword(@NotNull final ASN1OctetString storedPassword,
       @NotNull final ReadOnlyEntry userEntry,
       @NotNull final String attributeName,
       @NotNull final List<InMemoryPasswordEncoder> passwordEncoders)
  {
    this.storedPassword = storedPassword;
    this.userEntry = userEntry;
    this.attributeName = attributeName;

    InMemoryPasswordEncoder encoder = null;
    for (final InMemoryPasswordEncoder e : passwordEncoders)
    {
      if (e.passwordStartsWithPrefix(storedPassword))
      {
        encoder = e;
        break;
      }
    }

    passwordEncoder = encoder;
  }



  /**
   * Retrieves the password as it is (or has the potential to be) stored in the
   * in-memory directory server.  If the {@link #isEncoded()} method returns
   * {@code true}, then the stored password will be treated as an encoded
   * password.  Otherwise, it will be treated as a clear-text password with
   * no encoding or output formatting.
   *
   * @return  The password as it is (or has the potential to be) stored in the
   *          in-memory directory server.
   */
  @NotNull()
  public ASN1OctetString getStoredPassword()
  {
    return storedPassword;
  }



  /**
   * Retrieves the name of the attribute with which the stored password is
   * associated.
   *
   * @return  The name of the attribute with which the stored password is
   *          associated.
   */
  @NotNull()
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Indicates whether the stored password is encoded or in the clear.
   *
   * @return  {@code true} if the stored password is encoded, or {@code false}
   *          if it is the clear.
   */
  public boolean isEncoded()
  {
    return (passwordEncoder != null);
  }



  /**
   * Retrieves the password encoder that should be used to interact with the
   * stored password.
   *
   * @return  The password encoder that should be used to interact with the
   *          stored password, or {@code null} if the password is not encoded.
   */
  @Nullable()
  public InMemoryPasswordEncoder getPasswordEncoder()
  {
    return passwordEncoder;
  }



  /**
   * Retrieves the clear-text representation of the stored password, if it
   * is possible to obtain it.  If the password is not encoded, then the stored
   * password will be returned as-is.  If the stored password is encoded, then
   * the {@link InMemoryPasswordEncoder#extractClearPasswordFromEncodedPassword}
   * method will be used in an attempt to
   *
   * @return  The clear-text representation of the stored password.
   *
   * @throws  LDAPException  If the stored password is encoded using a mechanism
   *                         that does not permit extracting the clear-text
   *                         password.
   */
  @NotNull()
  public ASN1OctetString getClearPassword()
         throws LDAPException
  {
    if (passwordEncoder == null)
    {
      return storedPassword;
    }
    else
    {
      return passwordEncoder.extractClearPasswordFromEncodedPassword(
           storedPassword, userEntry);
    }
  }



  /**
   * Indicates whether this password matches the provided clear-text password.
   *
   * @param  clearPassword  The clear-text password for which to make the
   *                        determination.
   *
   * @return  {@code true} if this password matches the provided clear-text
   *          password, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to make
   *                         the determination.
   */
  public boolean matchesClearPassword(
                      @NotNull final ASN1OctetString clearPassword)
         throws LDAPException
  {
    if (passwordEncoder == null)
    {
      return OctetStringMatchingRule.getInstance().valuesMatch(clearPassword,
           storedPassword);
    }
    else
    {
      return passwordEncoder.clearPasswordMatchesEncodedPassword(clearPassword,
           storedPassword, userEntry);
    }
  }
}
