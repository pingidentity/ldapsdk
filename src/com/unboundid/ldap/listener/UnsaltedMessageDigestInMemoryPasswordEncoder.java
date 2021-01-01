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



import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an implementation of an in-memory directory server
 * password encoder that uses a message digest to encode passwords.  No salt
 * will be used when generating the digest, so the same clear-text password will
 * always result in the same encoded representation.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class UnsaltedMessageDigestInMemoryPasswordEncoder
       extends InMemoryPasswordEncoder
{
  // The length of the generated message digest, in bytes.
  private final int digestLengthBytes;

  // The message digest instance tha will be used to actually perform the
  // encoding.
  @NotNull private final MessageDigest messageDigest;



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
   * @param  messageDigest    The message digest that will be used to actually
   *                          perform the encoding.  It must not be
   *                          {@code null}, it must have a fixed length, and it
   *                          must properly report that length via the
   *                          {@code MessageDigest.getDigestLength} method.
   */
  public UnsaltedMessageDigestInMemoryPasswordEncoder(
              @NotNull final String prefix,
              @Nullable final PasswordEncoderOutputFormatter outputFormatter,
              @NotNull final MessageDigest messageDigest)
  {
    super(prefix, outputFormatter);

    Validator.ensureNotNull(messageDigest);
    this.messageDigest = messageDigest;

    digestLengthBytes = messageDigest.getDigestLength();
    Validator.ensureTrue((digestLengthBytes > 0),
         "The message digest use a fixed digest length, and that " +
              "length must be greater than zero.");
  }



  /**
   * Retrieves the digest algorithm that will be used when encoding passwords.
   *
   * @return  The message digest
   */
  @NotNull()
  public String getDigestAlgorithm()
  {
    return messageDigest.getAlgorithm();
  }



  /**
   * Retrieves the digest length, in bytes.
   *
   * @return  The digest length, in bytes.
   */
  public int getDigestLengthBytes()
  {
    return digestLengthBytes;
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
    return messageDigest.digest(clearPassword);
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
    // Make sure that the length of the array containing the encoded password
    // matches the digest length.
    if (unPrefixedUnFormattedEncodedPasswordBytes.length != digestLengthBytes)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_UNSALTED_DIGEST_PW_ENCODER_PRE_ENCODED_LENGTH_MISMATCH.get(
                messageDigest.getAlgorithm(),
                unPrefixedUnFormattedEncodedPasswordBytes.length,
                digestLengthBytes));
    }
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
    final byte[] expectedEncodedPassword =
         messageDigest.digest(clearPasswordBytes);
    return Arrays.equals(unPrefixedUnFormattedEncodedPasswordBytes,
         expectedEncodedPassword);
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
    throw new LDAPException(ResultCode.NOT_SUPPORTED,
         ERR_UNSALTED_DIGEST_PW_ENCODER_NOT_REVERSIBLE.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SaltedMessageDigestInMemoryPasswordEncoder(prefix='");
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

    buffer.append(", digestAlgorithm='");
    buffer.append(messageDigest.getAlgorithm());
    buffer.append("', digestLengthBytes=");
    buffer.append(messageDigest.getDigestLength());
    buffer.append(')');
  }
}
