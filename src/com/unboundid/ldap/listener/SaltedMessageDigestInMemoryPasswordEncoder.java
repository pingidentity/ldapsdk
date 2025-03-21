/*
 * Copyright 2017-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2025 Ping Identity Corporation
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
 * Copyright (C) 2017-2025 Ping Identity Corporation
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
import com.unboundid.util.ThreadLocalSecureRandom;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an implementation of an in-memory directory server
 * password encoder that uses a message digest to encode passwords.  Encoded
 * passwords will also include some number of randomly generated bytes, called a
 * salt, to ensure that encoding the same password multiple times will yield
 * multiple different encoded representations.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class SaltedMessageDigestInMemoryPasswordEncoder
       extends InMemoryPasswordEncoder
{
  // Indicates whether the salt should go after or before the clear-text
  // password when generating the message digest.
  private final boolean saltAfterClearPassword;

  // Indicates whether the salt should go after or before the digest bytes
  // when generating the final encoded representation.
  private final boolean saltAfterMessageDigest;

  // The length of the generated message digest, in bytes.
  private final int digestLengthBytes;

  // The number of salt bytes to generate.
  private final int numSaltBytes;

  // The message digest instance tha will be used to actually perform the
  // encoding.
  @NotNull private final MessageDigest messageDigest;



  /**
   * Creates a new instance of this in-memory directory server password encoder
   * with the provided information.
   *
   * @param  prefix                  The string that will appear at the
   *                                 beginning of encoded passwords.  It must
   *                                 not be {@code null} or empty.
   * @param  outputFormatter         The output formatter that will be used to
   *                                 format the encoded representation of
   *                                 clear-text passwords.  It may be
   *                                 {@code null} if no special formatting
   *                                 should be applied to the raw bytes.
   * @param  messageDigest           The message digest that will be used to
   *                                 actually perform the encoding.  It must not
   *                                 be {@code null}.
   * @param  numSaltBytes            The number of salt bytes to generate when
   *                                 encoding passwords.  It must be greater
   *                                 than zero.
   * @param  saltAfterClearPassword  Indicates whether the salt should be placed
   *                                 after or before the clear-text password
   *                                 when computing the message digest.  If this
   *                                 is {@code true}, then the digest will be
   *                                 computed from the concatenation of the
   *                                 clear-text password and the salt, in that
   *                                 order.  If this is {@code false}, then the
   *                                 digest will be computed from the
   *                                 concatenation of the salt and the
   *                                 clear-text password.
   * @param  saltAfterMessageDigest  Indicates whether the salt should be placed
   *                                 after or before the computed digest when
   *                                 creating the encoded representation.  If
   *                                 this is {@code true}, then the encoded
   *                                 password will consist of the concatenation
   *                                 of the computed message digest and the
   *                                 salt, in that order.  If this is
   *                                 {@code false}, then the encoded password
   *                                 will consist of the concatenation of the
   *                                 salt and the message digest.
   */
  public SaltedMessageDigestInMemoryPasswordEncoder(
              @NotNull final String prefix,
              @Nullable final PasswordEncoderOutputFormatter outputFormatter,
              @NotNull final MessageDigest messageDigest,
              final int numSaltBytes, final boolean saltAfterClearPassword,
              final boolean saltAfterMessageDigest)
  {
    super(prefix, outputFormatter);

    Validator.ensureNotNull(messageDigest);
    this.messageDigest = messageDigest;

    digestLengthBytes = messageDigest.getDigestLength();
    Validator.ensureTrue((digestLengthBytes > 0),
         "The message digest use a fixed digest length, and that " +
              "length must be greater than zero.");

    this.numSaltBytes = numSaltBytes;
    Validator.ensureTrue((numSaltBytes > 0),
         "numSaltBytes must be greater than zero.");

    this.saltAfterClearPassword = saltAfterClearPassword;
    this.saltAfterMessageDigest = saltAfterMessageDigest;
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
   * Retrieves the number of bytes of salt that will be generated when encoding
   * a password.  Note that this is used only when encoding new clear-text
   * passwords.  When comparing a clear-text password against an existing
   * encoded representation, the number of salt bytes from the existing encoded
   * password will be used.
   *
   * @return  The number of bytes of salt that will be generated when encoding a
   *          password.
   */
  public int getNumSaltBytes()
  {
    return numSaltBytes;
  }



  /**
   * Indicates whether the salt should be appended or prepended to the
   * clear-text password when computing the message digest.
   *
   * @return  {@code true} if the salt should be appended to the clear-text
   *          password when computing the message digest, or {@code false} if
   *          the salt should be prepended to the clear-text password.
   */
  public boolean isSaltAfterClearPassword()
  {
    return saltAfterClearPassword;
  }



  /**
   * Indicates whether the salt should be appended or prepended to the digest
   * when generating the encoded representation for the password.
   *
   * @return  {@code true} if the salt should be appended to the digest when
   *          generating the encoded representation for the password, or
   *          {@code false} if the salt should be prepended to the digest.
   */
  public boolean isSaltAfterMessageDigest()
  {
    return saltAfterMessageDigest;
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
    final byte[] salt = new byte[numSaltBytes];
    ThreadLocalSecureRandom.get().nextBytes(salt);

    final byte[] saltedPassword;
    if (saltAfterClearPassword)
    {
      saltedPassword = concatenate(clearPassword, salt);
    }
    else
    {
      saltedPassword = concatenate(salt, clearPassword);
    }

    final byte[] digest = messageDigest.digest(saltedPassword);

    if (saltAfterMessageDigest)
    {
      return concatenate(digest, salt);
    }
    else
    {
      return concatenate(salt, digest);
    }
  }



  /**
   * Creates a new byte array that is a concatenation of the provided byte
   * arrays.
   *
   * @param  b1  The byte array to appear first in the concatenation.
   * @param  b2  The byte array to appear second in the concatenation.
   *
   * @return  A byte array containing the concatenation.
   */
  @NotNull()
  private static byte[] concatenate(@NotNull final byte[] b1,
                                    @NotNull final byte[] b2)
  {
    final byte[] combined = new byte[b1.length + b2.length];
    System.arraycopy(b1, 0, combined, 0, b1.length);
    System.arraycopy(b2, 0, combined, b1.length, b2.length);
    return combined;
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
    // Make sure that the encoded password is longer than the digest length
    // so that there is room for some amount of salt.
    if (unPrefixedUnFormattedEncodedPasswordBytes.length <= digestLengthBytes)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SALTED_DIGEST_PW_ENCODER_PRE_ENCODED_LENGTH_MISMATCH.get(
                messageDigest.getAlgorithm(),
                unPrefixedUnFormattedEncodedPasswordBytes.length,
                (digestLengthBytes + 1)));
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
    // Subtract the digest length from the encoded password to get the number
    // of salt bytes.  If the number of salt bytes is less than or equal to
    // zero, then the password will not match.
    final int numComputedSaltBytes =
         unPrefixedUnFormattedEncodedPasswordBytes.length - digestLengthBytes;
    if (numComputedSaltBytes <= 0)
    {
      return false;
    }


    // Separate the salt and the digest.
    final byte[] salt = new byte[numComputedSaltBytes];
    final byte[] digest = new byte[digestLengthBytes];
    if (saltAfterMessageDigest)
    {
      System.arraycopy(unPrefixedUnFormattedEncodedPasswordBytes, 0, digest, 0,
           digestLengthBytes);
      System.arraycopy(unPrefixedUnFormattedEncodedPasswordBytes,
           digestLengthBytes, salt, 0, salt.length);
    }
    else
    {
      System.arraycopy(unPrefixedUnFormattedEncodedPasswordBytes, 0, salt, 0,
           salt.length);
      System.arraycopy(unPrefixedUnFormattedEncodedPasswordBytes, salt.length,
           digest, 0, digestLengthBytes);
    }


    // Now that we have the salt, combine it with the clear-text password in the
    // proper order.
    // Combine the clear-text password and the salt in the proper order.
    final byte[] saltedPassword;
    if (saltAfterClearPassword)
    {
      saltedPassword = concatenate(clearPasswordBytes, salt);
    }
    else
    {
      saltedPassword = concatenate(salt, clearPasswordBytes);
    }


    // Compute a digest of the salted password and see whether it matches the
    // digest we extracted earlier.  If so, then the clear-text password
    // matches.  If not, then it doesn't.
    final byte[] computedDigest = messageDigest.digest(saltedPassword);
    return Arrays.equals(computedDigest, digest);
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
         ERR_SALTED_DIGEST_PW_ENCODER_NOT_REVERSIBLE.get());
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
    buffer.append(", numSaltBytes=");
    buffer.append(numSaltBytes);
    buffer.append(", saltAfterClearPassword=");
    buffer.append(saltAfterClearPassword);
    buffer.append(", saltAfterMessageDigest=");
    buffer.append(saltAfterMessageDigest);
    buffer.append(')');
  }
}
