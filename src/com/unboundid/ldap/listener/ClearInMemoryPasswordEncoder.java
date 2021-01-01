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



import java.util.Arrays;
import java.util.List;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an in-memory directory server
 * password encoder that leaves the password in the clear.  This doesn't provide
 * any more protection than leaving passwords unencoded, but it does make it
 * possible to store these passwords with a prefix, and to use an optional
 * output format (e.g., to format the clear-text value in base64 or
 * hexadecimal).
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ClearInMemoryPasswordEncoder
       extends InMemoryPasswordEncoder
{
  /**
   * Creates a new instance of this in-memory directory server password encoder
   * with the provided information.
   *
   * @param  prefix           The string that will appear at the beginning of
   *                          encoded passwords.  It must not be {@code null} or
   *                          empty.
   * @param  outputFormatter  The output formatter that will be used to format
   *                          the encoded representation of clear-text
   *                          passwords.  It may be {@code null} if no
   *                          special formatting should be applied to the raw
   *                          bytes.
   */
  public ClearInMemoryPasswordEncoder(@NotNull final String prefix,
              @Nullable final PasswordEncoderOutputFormatter outputFormatter)
  {
    super(prefix, outputFormatter);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected byte[] encodePassword(@NotNull final byte[] clearPassword,
                        @NotNull final ReadOnlyEntry userEntry,
                        @NotNull final List<Modification> modifications)
            throws LDAPException
  {
    return clearPassword;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void ensurePreEncodedPasswordAppearsValid(
       @NotNull final byte[] unPrefixedUnFormattedEncodedPasswordBytes,
       @NotNull final ReadOnlyEntry userEntry,
       @NotNull final List<Modification> modifications)
            throws LDAPException
  {
    // No validation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean passwordMatches(@NotNull final byte[] clearPasswordBytes,
       @NotNull final byte[] unPrefixedUnFormattedEncodedPasswordBytes,
       @NotNull final ReadOnlyEntry userEntry)
            throws LDAPException
  {
    return Arrays.equals(clearPasswordBytes,
         unPrefixedUnFormattedEncodedPasswordBytes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected byte[] extractClearPassword(
       @NotNull final byte[] unPrefixedUnFormattedEncodedPasswordBytes,
       @NotNull final ReadOnlyEntry userEntry)
            throws LDAPException
  {
    return unPrefixedUnFormattedEncodedPasswordBytes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ClearInMemoryPasswordEncoder(prefix='");
    buffer.append(getPrefix());
    buffer.append("', outputFormatter=");

    final PasswordEncoderOutputFormatter outputFormatter =
         getOutputFormatter();
    if (outputFormatter == null)
    {
      buffer.append("null");
    }
    else
    {
      outputFormatter.toString(buffer);
    }

    buffer.append(')');
  }
}
