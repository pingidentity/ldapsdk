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
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class defines an API that may be used to interact with clear-text
 * passwords provided to the in-memory directory server.  It can be used to
 * ensure that clear-text passwords are encoded when storing them in the server,
 * and to determine whether a provided clear-text password matches an encoded
 * value.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class InMemoryPasswordEncoder
{
  // The bytes that comprise the prefix.
  @NotNull private final byte[] prefixBytes;

  // The output formatter that will be used to format the encoded representation
  // of clear-text passwords.
  @Nullable private final PasswordEncoderOutputFormatter outputFormatter;

  // The string that will appear at the beginning of encoded passwords.
  @NotNull private final String prefix;



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
  protected InMemoryPasswordEncoder(@NotNull final String prefix,
                 @Nullable final PasswordEncoderOutputFormatter outputFormatter)
  {
    Validator.ensureNotNullOrEmpty(prefix,
         "The password encoder prefix must not be null or empty.");

    this.prefix = prefix;
    this.outputFormatter = outputFormatter;

    prefixBytes = StaticUtils.getBytes(prefix);
  }



  /**
   * Retrieves the string that will appear at the beginning of encoded
   * passwords.
   *
   * @return  The string that will appear at the beginning of encoded passwords.
   */
  @NotNull()
  public final String getPrefix()
  {
    return prefix;
  }



  /**
   * Retrieves the output formatter that will be used when generating the
   * encoded representation of a password.
   *
   * @return  The output formatter that will be used when generating the encoded
   *          representation of a password, or {@code nulL} if no output
   *          formatting will be applied.
   */
  @Nullable()
  public final PasswordEncoderOutputFormatter getOutputFormatter()
  {
    return outputFormatter;
  }



  /**
   * Encodes the provided clear-text password for storage in the in-memory
   * directory server.  The encoded password that is returned will include the
   * prefix, and any appropriate output formatting will have been applied.
   * <BR><BR>
   * This method will be invoked when adding data into the server, including
   * through LDAP add operations or LDIF imports, and when modifying existing
   * entries through LDAP modify operations.
   *
   * @param  clearPassword  The clear-text password to be encoded.  It must not
   *                        be {@code null} or empty, and it must not be
   *                        pre-encoded.
   * @param  userEntry      The entry in which the encoded password will appear.
   *                        It must not be {@code null}.  If the entry is in the
   *                        process of being modified, then this will be a
   *                        representation of the entry as it appeared before
   *                        any changes have been applied.
   * @param  modifications  A set of modifications to be applied to the user
   *                        entry.  It must not be [@code null}.  It will be an
   *                        empty list for entries created via LDAP add and LDIF
   *                        import operations.  It will be a non-empty list for
   *                        LDAP modifications.
   *
   * @return  The encoded representation of the provided clear-text password.
   *          It will include the prefix, and any appropriate output formatting
   *          will have been applied.
   *
   * @throws  LDAPException  If a problem is encountered while trying to encode
   *                         the provided clear-text password.
   */
  @NotNull()
  public final ASN1OctetString encodePassword(
                    @NotNull final ASN1OctetString clearPassword,
                    @NotNull final ReadOnlyEntry userEntry,
                    @NotNull final List<Modification> modifications)
         throws LDAPException
  {
    if (clearPassword.getValueLength() == 0)
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           ERR_PW_ENCODER_ENCODE_PASSWORD_EMPTY.get());
    }

    final byte[] clearPasswordBytes = clearPassword.getValue();
    final byte[] encodedPasswordBytes =
         encodePassword(clearPasswordBytes, userEntry, modifications);

    final byte[] formattedEncodedPasswordBytes;
    if (outputFormatter == null)
    {
      formattedEncodedPasswordBytes = encodedPasswordBytes;
    }
    else
    {
      formattedEncodedPasswordBytes =
           outputFormatter.format(encodedPasswordBytes);
    }

    final byte[] formattedPasswordBytesWithPrefix =
         new byte[formattedEncodedPasswordBytes.length + prefixBytes.length];
    System.arraycopy(prefixBytes, 0, formattedPasswordBytesWithPrefix, 0,
         prefixBytes.length);
    System.arraycopy(formattedEncodedPasswordBytes, 0,
         formattedPasswordBytesWithPrefix, prefixBytes.length,
         formattedEncodedPasswordBytes.length);

    return new ASN1OctetString(formattedPasswordBytesWithPrefix);
  }



  /**
   * Encodes the provided clear-text password for storage in the in-memory
   * directory server.  The encoded password that is returned must not include
   * the prefix, and no output formatting should have been applied.
   * <BR><BR>
   * This method will be invoked when adding data into the server, including
   * through LDAP add operations or LDIF imports, and when modifying existing
   * entries through LDAP modify operations.
   *
   * @param  clearPassword  The bytes that comprise the clear-text password to
   *                        be encoded.  It must not be {@code null} or empty.
   * @param  userEntry      The entry in which the encoded password will appear.
   *                        It must not be {@code null}.  If the entry is in the
   *                        process of being modified, then this will be a
   *                        representation of the entry as it appeared before
   *                        any changes have been applied.
   * @param  modifications  A set of modifications to be applied to the user
   *                        entry.  It must not be [@code null}.  It will be an
   *                        empty list for entries created via LDAP add and LDIF
   *                        import operations.  It will be a non-empty list for
   *                        LDAP modifications.
   *
   * @return  The bytes that comprise encoded representation of the provided
   *          clear-text password, without the prefix, and without any output
   *          formatting applied.
   *
   * @throws  LDAPException  If a problem is encountered while trying to encode
   *                         the provided clear-text password.
   */
  @NotNull()
  protected abstract byte[] encodePassword(@NotNull byte[] clearPassword,
                                 @NotNull ReadOnlyEntry userEntry,
                                 @NotNull List<Modification> modifications)
            throws LDAPException;



  /**
   * Verifies that the provided pre-encoded password (including the prefix, and
   * with any appropriate output formatting applied) is compatible with the
   * validation performed by this password encoder.
   * <BR><BR>
   * This method will be invoked when adding data into the server, including
   * through LDAP add operations or LDIF imports, and when modifying existing
   * entries through LDAP modify operations.  Any password included in any of
   * these entries that starts with a prefix registered with the in-memory
   * directory server will be validated with the encoder that corresponds to
   * that password's prefix.
   *
   * @param  prefixedFormattedEncodedPassword
   *              The pre-encoded password to validate.  It must not be
   *              {@code null}, and it should include the prefix and any
   *              applicable output formatting.
   * @param  userEntry
   *              The entry in which the password will appear.  It must not be
   *              {@code null}.  If the entry is in the process of being
   *              modified, then this will be a representation of the entry
   *              as it appeared before any changes have been applied.
   * @param  modifications
   *              A set of modifications to be applied to the user entry.  It
   *              must not be [@code null}.  It will be an empty list for
   *              entries created via LDAP add and LDIF import operations.  It
   *              will be a non-empty list for LDAP modifications.
   *
   * @throws  LDAPException  If the provided encoded password is not compatible
   *                         with the validation performed by this password
   *                         encoder, or if a problem is encountered while
   *                         making the determination.
   */
  public final void ensurePreEncodedPasswordAppearsValid(
              @NotNull final ASN1OctetString prefixedFormattedEncodedPassword,
              @NotNull final ReadOnlyEntry userEntry,
              @NotNull final List<Modification> modifications)
         throws LDAPException
  {
    // Strip the prefix off the encoded password.
    final byte[] prefixedFormattedEncodedPasswordBytes =
         prefixedFormattedEncodedPassword.getValue();
    if (! passwordStartsWithPrefix(prefixedFormattedEncodedPasswordBytes))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           ERR_PW_ENCODER_VALIDATE_ENCODED_PW_MISSING_PREFIX.get(
                getClass().getName(), prefix));
    }

    final byte[] unPrefixedFormattedEncodedPasswordBytes =
         new byte[prefixedFormattedEncodedPasswordBytes.length -
              prefixBytes.length];
    System.arraycopy(prefixedFormattedEncodedPasswordBytes, prefixBytes.length,
         unPrefixedFormattedEncodedPasswordBytes, 0,
         unPrefixedFormattedEncodedPasswordBytes.length);


    // If an output formatter is configured, then revert the output formatting.
    final byte[] unPrefixedUnFormattedEncodedPasswordBytes;
    if (outputFormatter == null)
    {
      unPrefixedUnFormattedEncodedPasswordBytes =
           unPrefixedFormattedEncodedPasswordBytes;
    }
    else
    {
      unPrefixedUnFormattedEncodedPasswordBytes =
           outputFormatter.unFormat(unPrefixedFormattedEncodedPasswordBytes);
    }


    // Validate the un-prefixed, un-formatted password.
    ensurePreEncodedPasswordAppearsValid(
         unPrefixedUnFormattedEncodedPasswordBytes, userEntry, modifications);
  }



  /**
   * Verifies that the provided pre-encoded password (with the prefix removed
   * and any output formatting reverted) is compatible with the validation
   * performed by this password encoder.
   * <BR><BR>
   * Note that this method should return {@code true} if the provided
   * {@code unPrefixedUnFormattedEncodedPasswordBytes} value could be used in
   * conjunction with the {@link #passwordMatches} method, even if it does not
   * exactly match the format of the output that would have been generated by
   * the {@link #encodePassword} method.  For example, if this password encoder
   * uses a salt, then it may be desirable to accept passwords encoded with a
   * salt that has a different length than the {@code encodePassword} method
   * would use when encoding a clear-test password.  This may allow the
   * in-memory directory server to support pre-encoded passwords generated from
   * other types of directory servers that may use different settings when
   * encoding passwords, but still generates encoded passwords that are
   * compatible with this password encoder.
   *
   * @param  unPrefixedUnFormattedEncodedPasswordBytes
   *              The bytes that comprise the pre-encoded password to validate,
   *              with the prefix stripped off and the output formatting
   *              reverted.
   * @param  userEntry
   *              The entry in which the password will appear.  It must not be
   *              {@code null}.  If the entry is in the process of being
   *              modified, then this will be a representation of the entry
   *              as it appeared before any changes have been applied.
   * @param  modifications
   *              A set of modifications to be applied to the user entry.  It
   *              must not be [@code null}.  It will be an empty list for
   *              entries created via LDAP add and LDIF import operations.  It
   *              will be a non-empty list for LDAP modifications.
   *
   * @throws  LDAPException  If the provided encoded password is not compatible
   *                         with the validation performed by this password
   *                         encoder, or if a problem is encountered while
   *                         making the determination.
   */
  protected abstract void ensurePreEncodedPasswordAppearsValid(
                 @NotNull byte[] unPrefixedUnFormattedEncodedPasswordBytes,
                 @NotNull ReadOnlyEntry userEntry,
                 @NotNull List<Modification> modifications)
            throws LDAPException;



  /**
   * Indicates whether the provided clear-text password could have been used to
   * generate the given encoded password.  This method will be invoked when
   * verifying a provided clear-text password during bind processing, or when
   * removing an existing password in a modify operation.
   *
   * @param  clearPassword
   *               The clear-text password to be compared against the encoded
   *               password.  It must not be {@code null} or empty.
   * @param  prefixedFormattedEncodedPassword
   *              The encoded password to compare against the clear-text
   *              password.  It must not be {@code null}, it must include the
   *              prefix, and any appropriate output formatting must have been
   *              applied.
   * @param  userEntry
   *              The entry in which the encoded password appears.  It must not
   *              be {@code null}.
   *
   * @return  {@code true} if the provided clear-text password could be used to
   *          generate the given encoded password, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while making the
   *                         determination.
   */
  public final boolean clearPasswordMatchesEncodedPassword(
              @NotNull final ASN1OctetString clearPassword,
              @NotNull final ASN1OctetString prefixedFormattedEncodedPassword,
              @NotNull final ReadOnlyEntry userEntry)
         throws LDAPException
  {
    // Make sure that the provided clear-text password is not null or empty.
    final byte[] clearPasswordBytes = clearPassword.getValue();
    if (clearPasswordBytes.length == 0)
    {
      return false;
    }


    // If the password doesn't start with the right prefix, then it's not
    // considered a match.  If it does start with the right prefix, then strip
    // it off.
    final byte[] prefixedFormattedEncodedPasswordBytes =
         prefixedFormattedEncodedPassword.getValue();
    if (! passwordStartsWithPrefix(prefixedFormattedEncodedPasswordBytes))
    {
      return false;
    }

    final byte[] unPrefixedFormattedEncodedPasswordBytes =
         new byte[prefixedFormattedEncodedPasswordBytes.length -
              prefixBytes.length];
    System.arraycopy(prefixedFormattedEncodedPasswordBytes, prefixBytes.length,
         unPrefixedFormattedEncodedPasswordBytes, 0,
         unPrefixedFormattedEncodedPasswordBytes.length);


    // If an output formatter is configured, then revert the output formatting.
    final byte[] unPrefixedUnFormattedEncodedPasswordBytes;
    if (outputFormatter == null)
    {
      unPrefixedUnFormattedEncodedPasswordBytes =
           unPrefixedFormattedEncodedPasswordBytes;
    }
    else
    {
      unPrefixedUnFormattedEncodedPasswordBytes =
           outputFormatter.unFormat(unPrefixedFormattedEncodedPasswordBytes);
    }


    // Make sure that the resulting un-prefixed, un-formatted password is not
    // empty.
    if (unPrefixedUnFormattedEncodedPasswordBytes.length == 0)
    {
      return false;
    }


    // Determine whether the provided clear-text password could have been used
    // to generate the encoded representation.
    return passwordMatches(clearPasswordBytes,
         unPrefixedUnFormattedEncodedPasswordBytes, userEntry);
  }



  /**
   * Indicates whether the provided clear-text password could have been used to
   * generate the given encoded password.  This method will be invoked when
   * verifying a provided clear-text password during bind processing, or when
   * removing an existing password in a modify operation.
   *
   * @param  clearPasswordBytes
   *               The bytes that comprise the clear-text password to be
   *               compared against the encoded password.  It must not be
   *               {@code null} or empty.
   * @param  unPrefixedUnFormattedEncodedPasswordBytes
   *              The bytes that comprise the encoded password, with the prefix
   *              stripped off and the output formatting reverted.
   * @param  userEntry
   *              The entry in which the encoded password appears.  It must not
   *              be {@code null}.
   *
   * @return  {@code true} if the provided clear-text password could have been
   *          used to generate the given encoded password, or {@code false} if
   *          not.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         make the determination.
   */
  protected abstract boolean passwordMatches(
                 @NotNull byte[] clearPasswordBytes,
                 @NotNull byte[] unPrefixedUnFormattedEncodedPasswordBytes,
                 @NotNull ReadOnlyEntry userEntry)
            throws LDAPException;



  /**
   * Attempts to extract the clear-text password used to generate the provided
   * encoded representation, if possible.  Many password encoder implementations
   * may use one-way encoding mechanisms, so it will often not be possible to
   * obtain the original clear-text password from its encoded representation.
   *
   * @param  prefixedFormattedEncodedPassword
   *              The encoded password from which to extract the clear-text
   *              password.  It must not be {@code null}, it must include the
   *              prefix, and any appropriate output formatting must have been
   *              applied.
   * @param  userEntry
   *              The entry in which the encoded password appears.  It must not
   *              be {@code null}.
   *
   * @return  The clear-text password used to generate the provided encoded
   *          representation.
   *
   * @throws  LDAPException  If this password encoder is not reversible, or if a
   *                         problem occurs while trying to extract the
   *                         clear-text representation from the provided encoded
   *                         password.
   */
  @NotNull()
  public final ASN1OctetString extractClearPasswordFromEncodedPassword(
              @NotNull final ASN1OctetString prefixedFormattedEncodedPassword,
              @NotNull final ReadOnlyEntry userEntry)
         throws LDAPException
  {
    // Strip the prefix off the encoded password.
    final byte[] prefixedFormattedEncodedPasswordBytes =
         prefixedFormattedEncodedPassword.getValue();
    if (! passwordStartsWithPrefix(prefixedFormattedEncodedPasswordBytes))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           ERR_PW_ENCODER_PW_MATCHES_ENCODED_PW_MISSING_PREFIX.get(
                getClass().getName(), prefix));
    }

    final byte[] unPrefixedFormattedEncodedPasswordBytes =
         new byte[prefixedFormattedEncodedPasswordBytes.length -
              prefixBytes.length];
    System.arraycopy(prefixedFormattedEncodedPasswordBytes, prefixBytes.length,
         unPrefixedFormattedEncodedPasswordBytes, 0,
         unPrefixedFormattedEncodedPasswordBytes.length);


    // If an output formatter is configured, then revert the output formatting.
    final byte[] unPrefixedUnFormattedEncodedPasswordBytes;
    if (outputFormatter == null)
    {
      unPrefixedUnFormattedEncodedPasswordBytes =
           unPrefixedFormattedEncodedPasswordBytes;
    }
    else
    {
      unPrefixedUnFormattedEncodedPasswordBytes =
           outputFormatter.unFormat(unPrefixedFormattedEncodedPasswordBytes);
    }


    // Try to extract the clear-text password.
    final byte[] clearPasswordBytes = extractClearPassword(
         unPrefixedUnFormattedEncodedPasswordBytes, userEntry);
    return new ASN1OctetString(clearPasswordBytes);
  }



  /**
   * Attempts to extract the clear-text password used to generate the provided
   * encoded representation, if possible.  Many password encoder implementations
   * may use one-way encoding mechanisms, so it will often not be possible to
   * obtain the original clear-text password from its encoded representation.
   *
   * @param  unPrefixedUnFormattedEncodedPasswordBytes
   *              The bytes that comprise the encoded password, with the prefix
   *              stripped off and the output formatting reverted.
   * @param  userEntry
   *              The entry in which the encoded password appears.  It must not
   *              be {@code null}.
   *
   * @return  The clear-text password used to generate the provided encoded
   *          representation.
   *
   * @throws  LDAPException  If this password encoder is not reversible, or if a
   *                         problem occurs while trying to extract the
   *                         clear-text representation from the provided encoded
   *                         password.
   */
  @NotNull()
  protected abstract byte[] extractClearPassword(
                 @NotNull byte[] unPrefixedUnFormattedEncodedPasswordBytes,
                 @NotNull ReadOnlyEntry userEntry)
            throws LDAPException;



  /**
   * Indicates whether the provided password starts with the encoded password
   * prefix.
   *
   * @param  password  The password for which to make the determination.
   *
   * @return  {@code true} if the provided password starts with the encoded
   *          password prefix, or {@code false} if not.
   */
  public final boolean passwordStartsWithPrefix(
                            @NotNull final ASN1OctetString password)
  {
    return passwordStartsWithPrefix(password.getValue());
  }



  /**
   * Indicates whether the provided byte array starts with the encoded password
   * prefix.
   *
   * @param  b  The byte array for which to make the determination.
   *
   * @return  {@code true} if the provided byte array starts with the encoded
   *          password prefix, or {@code false} if not.
   */
  private boolean passwordStartsWithPrefix(@NotNull final byte[] b)
  {
    if (b.length < prefixBytes.length)
    {
      return false;
    }

    for (int i=0; i < prefixBytes.length; i++)
    {
      if (b[i] != prefixBytes[i])
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Retrieves a string representation of this password encoder.
   *
   * @return  A string representation of this password encoder.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this password encoder to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public abstract void toString(@NotNull StringBuilder buffer);
}
