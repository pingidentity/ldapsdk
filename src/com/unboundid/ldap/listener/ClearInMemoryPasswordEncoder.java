/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
  public ClearInMemoryPasswordEncoder(final String prefix,
              final PasswordEncoderOutputFormatter outputFormatter)
  {
    super(prefix, outputFormatter);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected byte[] encodePassword(final byte[] clearPassword,
                                  final ReadOnlyEntry userEntry,
                                  final List<Modification> modifications)
            throws LDAPException
  {
    return clearPassword;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void ensurePreEncodedPasswordAppearsValid(
                      final byte[] unPrefixedUnFormattedEncodedPasswordBytes,
                      final ReadOnlyEntry userEntry,
                      final List<Modification> modifications)
            throws LDAPException
  {
    // No validation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean passwordMatches(final byte[] clearPasswordBytes,
                         final byte[] unPrefixedUnFormattedEncodedPasswordBytes,
                         final ReadOnlyEntry userEntry)
            throws LDAPException
  {
    return Arrays.equals(clearPasswordBytes,
         unPrefixedUnFormattedEncodedPasswordBytes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected byte[] extractClearPassword(
                 final byte[] unPrefixedUnFormattedEncodedPasswordBytes,
                 final ReadOnlyEntry userEntry)
            throws LDAPException
  {
    return unPrefixedUnFormattedEncodedPasswordBytes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
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
