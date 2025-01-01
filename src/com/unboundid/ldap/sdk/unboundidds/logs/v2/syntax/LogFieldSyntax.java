/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax;



import java.security.MessageDigest;
import java.util.LinkedList;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBuffer;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.
                   LogSyntaxMessages.*;



/**
 * This class defines the base class for syntaxes that may be used for field
 * values in log messages.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 *
 * @param  <T>  The type of value represented by this syntax.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class LogFieldSyntax<T>
{
  /**
   * The code point that represents the ASCII carriage return character.
   */
  protected static final int CARRIAGE_RETURN_CODE_POINT = 0x0D;



  /**
   * The code point that represents the ASCII double quote character.
   */
  protected static final int DOUBLE_QUOTE_CODE_POINT = 0x22;



  /**
   * The code point that represents the ASCII newline character.
   */
  protected static final int NEWLINE_CODE_POINT = 0x0A;



  /**
   * The code point that represents the ASCII octothorpe character.
   */
  protected static final int OCTOTHORPE_CODE_POINT = 0x23;



  /**
   * The code point that represents the ASCII tab character.
   */
  protected static final int TAB_CODE_POINT = 0x09;



  /**
   * A string that will be used to indicate that the value has been redacted.
   */
  @NotNull public static final String REDACTED_STRING = "{REDACTED}";



  /**
   * A prefix that will be used before a token in a tokenized value.
   */
  @NotNull public static final String TOKEN_PREFIX_STRING = "{TOKENIZED:";



  /**
   * A suffix that will be used after a token in a tokenized value.
   */
  @NotNull public static final String TOKEN_SUFFIX_STRING = "}";



  /**
   * The digest algorithm used in the course of generating value tokens.
   */
  @NotNull private static final String TOKEN_DIGEST_ALGORITHM = "SHA-256";



  /**
   * The number of digest bytes to use when generating token values.
   */
  private static final int TOKEN_DIGEST_BYTES_LENGTH = 12;



  // The maximum length (in characters) to use for strings within values.
  private final int maxStringLengthCharacters;

  // A set of thread-local buffers that may be used in processing.
  @NotNull private final ThreadLocal<LinkedList<ByteStringBuffer>>
       threadLocalBuffers;

  // A set of thread-local message digests that may be used in processing.
  @NotNull private final ThreadLocal<MessageDigest> threadLocalDigests;




  /**
   * Creates a new instance of this log field syntax implementation.
   *
   * @param  maxStringLengthCharacters  The maximum length (in characters) to
   *                                    use for strings within values.  Strings
   *                                    that are longer than this should be
   *                                    truncated before inclusion in the log.
   *                                    This value must be greater than or equal
   *                                    to zero.
   */
  protected LogFieldSyntax(final int maxStringLengthCharacters)
  {
    this.maxStringLengthCharacters = maxStringLengthCharacters;

    threadLocalBuffers = new ThreadLocal<>();
    threadLocalDigests = new ThreadLocal<>();
  }



  /**
   * Retrieves the maximum length (in characters) to use for strings within
   * values.  Strings that are longer than this should be truncated before
   * inclusion in the log.
   *
   * @return  The maximum length (in characters) to use for strings within
   *          values.
   */
  protected int getMaxStringLengthCharacters()
  {
    return maxStringLengthCharacters;
  }



  /**
   * Retrieves the name for this syntax.
   *
   * @return  The name for this syntax.
   */
  @NotNull()
  public abstract String getSyntaxName();



  /**
   * Encodes the provided value to a sanitized string representation suitable
   * for inclusion in a log message.  The sanitized string should at least be
   * cleaned of control characters and other non-printable characters, but
   * depending on the syntax, it may clean other characters as well.
   *
   * @param  value  The value to be encoded.  It must not be {@code null}.
   *
   * @return  The encoded representation of the value.  It must not be
   *          {@code null}, but may be empty.
   */
  @NotNull()
  public String valueToSanitizedString(@NotNull final T value)
  {
    final ByteStringBuffer buffer = getTemporaryBuffer();
    try
    {
      valueToSanitizedString(value, buffer);
      return buffer.toString();
    }
    finally
    {
      releaseTemporaryBuffer(buffer);
    }
  }



  /**
   * Encodes the provided value to a sanitized string representation suitable
   * for inclusion in a log message.  The sanitized string should at least be
   * cleaned of control characters and other non-printable characters, but
   * depending on the syntax, it may clean other characters as well.
   *
   * @param  value   The value to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.  It must not be {@code null}.
   */
  public abstract void valueToSanitizedString(
              @NotNull final T value,
              @NotNull final ByteStringBuffer buffer);



  /**
   * Appends a sanitized representation of the specified field (both field name
   * and value) for a text-formatted log message to the given buffer.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logSanitizedFieldToTextFormattedLog(
              @NotNull final String fieldName,
              @NotNull final T fieldValue,
              @NotNull final ByteStringBuffer buffer);



  /**
   * Appends a sanitized representation of the specified field (both field name
   * and value) for a JSON-formatted log message to the given buffer.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logSanitizedFieldToJSONFormattedLog(
              @NotNull final String fieldName,
              @NotNull final T fieldValue,
              @NotNull final JSONBuffer buffer);



  /**
   * Appends a sanitized representation of the provided value (without a field
   * name, as might be suitable for a value included in a JSON array) for a
   * JSON-formatted log message to the given buffer.
   *
   * @param  value   The value to be appended to the buffer.  It must not be
   *                 {@code null}.
   * @param  buffer  The buffer to which the sanitized value should be appended.
   *                 It must not be {@code null}.
   */
  public abstract void logSanitizedValueToJSONFormattedLog(
              @NotNull final T value,
              @NotNull final JSONBuffer buffer);



  /**
   * Retrieves a sanitized version of the provided string.
   *
   * @param  string  The string to be sanitized.  It must not be {@code null}.
   *
   * @return  The sanitized version of the provided string.
   */
  @NotNull()
  protected final String sanitize(@NotNull final String string)
  {
    final ByteStringBuffer buffer = getTemporaryBuffer();
    try
    {
      sanitize(string, buffer);
      return buffer.toString();
    }
    finally
    {
      releaseTemporaryBuffer(buffer);
    }
  }



  /**
   * Appends an appropriately sanitized version of the provided string to the
   * given buffer.
   *
   * @param  string  The string to be sanitized.  It must not be {@code null}.
   * @param  buffer  The buffer to which the sanitized representation should be
   *                 appended.  It must not be {@code null}.
   */
  protected final void sanitize(@NotNull final String string,
                                @NotNull final ByteStringBuffer buffer)
  {
    final int numCharsToExamine;
    final int numCharsToTruncate;
    final int stringLength = string.length();
    if (stringLength > maxStringLengthCharacters)
    {
      numCharsToExamine = maxStringLengthCharacters;
      numCharsToTruncate = stringLength - maxStringLengthCharacters;
    }
    else
    {
      numCharsToExamine = stringLength;
      numCharsToTruncate = 0;
    }

    int pos = 0;
    while (pos < numCharsToExamine)
    {
      final int codePoint = string.codePointAt(pos);
      switch (codePoint)
      {
        case DOUBLE_QUOTE_CODE_POINT:
          buffer.append((byte) '\'');
          break;
        case NEWLINE_CODE_POINT:
          buffer.append("\\n");
          break;
        case CARRIAGE_RETURN_CODE_POINT:
          buffer.append("\\r");
          break;
        case TAB_CODE_POINT:
          buffer.append("\\t");
          break;
        case OCTOTHORPE_CODE_POINT:
          buffer.append("#23");
          break;
        default:
          if (StaticUtils.isLikelyDisplayableCharacter(codePoint))
          {
            buffer.appendCodePoint(codePoint);
          }
          else
          {
            for (final byte b : StaticUtils.getBytesForCodePoint(codePoint))
            {
              buffer.append('#');
              StaticUtils.toHex(b, buffer);
            }
          }
          break;
      }

      pos += Character.charCount(codePoint);
    }

    if (numCharsToTruncate > 0)
    {
      if (numCharsToTruncate == 1)
      {
        buffer.append(
             INFO_LOG_SYNTAX_TRUNCATED_1_CHAR.get());
      }
      else
      {
        buffer.append(
             INFO_LOG_SYNTAX_TRUNCATED_CHARS.get(numCharsToTruncate));
      }
    }
  }



  /**
   * Attempts to parse the provided string as a value in accordance with this
   * syntax.
   *
   * @param  valueString  The string to be parsed.
   *
   * @return  The value that was parsed.
   *
   * @throws  RedactedValueException  If the provided value has been redacted
   *                                  (either the complete value or one or more
   *                                  of its components), and the redacted form
   *                                  cannot be represented in this syntax.
   *
   * @throws  TokenizedValueException  If the provided value has been tokenized
   *                                   (either the complete value or one or more
   *                                   of its components), and the redacted form
   *                                   cannot be represented in this syntax.
   *
   * @throws  LogSyntaxException  If the provided value cannot be parsed in
   *                              accordance with this syntax.
   */
  @NotNull()
  public abstract T parseValue(@NotNull final String valueString)
         throws RedactedValueException, TokenizedValueException,
                LogSyntaxException;



  /**
   * Determines whether the provided value string represents a value that has
   * been completely redacted.
   *
   * @param  valueString  The value for which to make the determination.  It
   *                      must not be {@code null}.
   *
   * @return  {@code true} if the provided value string represents a value that
   *          has been completely redacted, or {@code false} if not.
   */
  public boolean valueStringIsCompletelyRedacted(
                      @NotNull final String valueString)
  {
    return valueString.equals(REDACTED_STRING);
  }



  /**
   * Indicates whether values that have been completely redacted still conform
   * to this syntax.
   *
   * @return  {@code true} if values that have been completely redacted still
   *          conform to this syntax, or {@code false} if not.
   */
  public abstract boolean completelyRedactedValueConformsToSyntax();



  /**
   * Retrieves a string that may be included in a log message to indicate that
   * the entire value for a field with this syntax has been redacted.
   *
   * @return  A string that may be included in a log message to
   *          indicate that the entire value for a field with this syntax has
   *          been redacted.
   */
  @NotNull()
  public String redactEntireValue()
  {
    final ByteStringBuffer buffer = getTemporaryBuffer();
    try
    {
      redactEntireValue(buffer);
      return buffer.toString();
    }
    finally
    {
      releaseTemporaryBuffer(buffer);
    }
  }



  /**
   * Appends a string representation of a redacted entire value to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the redacted string representation
   *                 should be appended.  It must not be {@code null}.
   */
  public void redactEntireValue(@NotNull final ByteStringBuffer buffer)
  {
    buffer.append(REDACTED_STRING);
  }



  /**
   * Appends a completely redacted representation of the specified field (both
   * field name and value) for a text-formatted log message to the given buffer.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logCompletelyRedactedFieldToTextFormattedLog(
              @NotNull final String fieldName,
              @NotNull final ByteStringBuffer buffer);



  /**
   * Appends a completely redacted representation of the specified field (both
   * field name and value) for a JSON-formatted log message to the given buffer.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logCompletelyRedactedFieldToJSONFormattedLog(
              @NotNull final String fieldName,
              @NotNull final JSONBuffer buffer);



  /**
   * Appends a completely redacted representation of a value (without a field
   * name, as might be suitable for a value included in a JSON array) for a
   * JSON-formatted log message to the given buffer.
   *
   * @param  buffer  The buffer to which the redacted value should be appended.
   *                 It must not be {@code null}.
   */
  public abstract void logCompletelyRedactedValueToJSONFormattedLog(
              @NotNull final JSONBuffer buffer);



  /**
   * Indicates whether this syntax supports redacting individual components of
   * the entire value.
   *
   * @return  {@code true} if this syntax supports redacting individual
   *          components of the entire value, or {@code false} if not.
   */
  public abstract boolean supportsRedactedComponents();



  /**
   * Determines whether the provided value string represents a value that has
   * had one or more components redacted.
   *
   * @param  valueString  The value for which to make the determination.  It
   *                      must not be {@code null}.
   *
   * @return  {@code true} if the provided value string represents a value that
   *          has had one or more components redacted, or {@code false} if not.
   */
  public boolean valueStringIncludesRedactedComponent(
                      @NotNull final String valueString)
  {
    return valueString.contains(REDACTED_STRING);
  }



  /**
   * Indicates whether values with one or more redacted components still conform
   * to this syntax.
   *
   * @return  {@code true} if values with one or more redacted components still
   *          conform to this syntax.
   */
  public abstract boolean valueWithRedactedComponentsConformsToSyntax();



  /**
   * Retrieves a string that provides a representation of the given value with
   * zero or more of its components redacted.  If this syntax does not support
   * redacted components, then the entire value should be redacted.
   *
   * @param  value  The value for which to obtain the redacted representation.
   *                It must not be {@code null}.
   *
   * @return  A string representation of the given value with zero or more of
   *          its components redacted.
   */
  @NotNull()
  public String redactComponents(@NotNull final T value)
  {
    final ByteStringBuffer buffer = getTemporaryBuffer();
    try
    {
      redactComponents(value, buffer);
      return buffer.toString();
    }
    finally
    {
      releaseTemporaryBuffer(buffer);
    }
  }



  /**
   * Appends a string representation of the given value with redacted components
   * to the provided buffer.
   *
   * @param  value   The value for which to obtain the redacted representation.
   *                 It must not be {@code null}.
   * @param  buffer  The buffer to which the redacted string representation
   *                 should be appended.  It must not be {@code null}.
   */
  public void redactComponents(@NotNull final T value,
                               @NotNull final ByteStringBuffer buffer)
  {
    redactEntireValue(buffer);
  }



  /**
   * Appends a representation of the specified field (both field name and value)
   * with redacted value components for a text-formatted log message to the
   * given buffer.  If this syntax does not support redacting components within
   * a value, then it should redact the entire value.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logRedactedComponentsFieldToTextFormattedLog(
              @NotNull final String fieldName,
              @NotNull final T fieldValue,
              @NotNull final ByteStringBuffer buffer);



  /**
   * Appends a representation of the specified field (both field name and value)
   * with redacted value components for a JSON-formatted log message to the
   * given buffer.  If this syntax does not support redacting components within
   * a value, then it should redact the entire value.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logRedactedComponentsFieldToJSONFormattedLog(
              @NotNull final String fieldName,
              @NotNull final T fieldValue,
              @NotNull final JSONBuffer buffer);



  /**
   * Appends a representation of the provided value (without a field name, as
   * might be suitable for a value included in a JSON array) with redacted
   * components for a JSON-formatted log message to the given buffer.  If this
   * syntax does not support redacting components within a value, then it should
   * redact the entire value.
   *
   * @param  value   The value to be appended to the buffer in redacted form.
   *                 It must not be {@code null}.
   * @param  buffer  The buffer to which the redacted value should be appended.
   *                 It must not be {@code null}.
   */
  public abstract void logRedactedComponentsValueToJSONFormattedLog(
              @NotNull final T value,
              @NotNull final JSONBuffer buffer);



  /**
   * Determines whether the provided value string represents a value that has
   * been completely tokenized.
   *
   * @param  valueString  The value for which to make the determination.  It
   *                      must not be {@code null}.
   *
   * @return  {@code true} if the provided value string represents a value that
   *          has been completely tokenized, or {@code false} if not.
   */
  public boolean valueStringIsCompletelyTokenized(
                      @NotNull final String valueString)
  {
    return (valueString.startsWith(TOKEN_PREFIX_STRING) &&
         valueString.endsWith(TOKEN_SUFFIX_STRING) &&
         (valueString.indexOf(TOKEN_PREFIX_STRING,
              TOKEN_PREFIX_STRING.length()) < 0));
  }



  /**
   * Indicates whether values that have been completely tokenized still conform
   * to this syntax.
   *
   * @return  {@code true} if values that have been completely tokenized still
   *          conform to this syntax, or {@code false} if not.
   */
  public abstract boolean completelyTokenizedValueConformsToSyntax();



  /**
   * Retrieves a string that represents a tokenized representation of the
   * provided value.
   * <BR><BR>
   * The resulting token will protect the provided value by representing it in a
   * way that makes it at infeasible to determine what the original value was.
   * However, tokenizing the same value with the same pepper should consistently
   * yield the same token value, so that it will be possible to identify the
   * same value across multiple log messages.
   *
   * @param  value   The value for which to generate the token.  It must not be
   *                 {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   *
   * @return  A string that represents a tokenized representation of the
   *          provided value.
   */
  @NotNull()
  public String tokenizeEntireValue(@NotNull final T value,
                                    @NotNull final byte[] pepper)
  {
    final ByteStringBuffer buffer = getTemporaryBuffer();
    try
    {
      tokenizeEntireValue(value, pepper, buffer);
      return buffer.toString();
    }
    finally
    {
      releaseTemporaryBuffer(buffer);
    }
  }



  /**
   * Appends a tokenized representation of the provided value to the given
   * buffer.
   * <BR><BR>
   * The resulting token will protect the provided value by representing it in a
   * way that makes it at infeasible to determine what the original value was.
   * However, tokenizing the same value with the same pepper should consistently
   * yield the same token value, so that it will be possible to identify the
   * same value across multiple log messages.
   *
   * @param  value   The value for which to generate the token.  It must not be
   *                 {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   * @param  buffer  The buffer to which the tokenized representation should be
   *                 appended.  It must not be {@code null}.
   */
  public abstract void tokenizeEntireValue(@NotNull final T value,
                                  @NotNull final byte[] pepper,
                                  @NotNull final ByteStringBuffer buffer);



  /**
   * Appends a completely tokenized representation of the specified field (both
   * field name and value) for a text-formatted log message to the given buffer.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   * @param  pepper      A pepper used to provide brute-force protection for the
   *                     resulting token.  The pepper value should be kept
   *                     secret so that it is not available to unauthorized
   *                     users who might be able to view log information,
   *                     although the same pepper value should be consistently
   *                     provided when tokenizing values so that the same value
   *                     will consistently yield the same token.  It must not be
   *                     {@code null} and should not be empty.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logCompletelyTokenizedFieldToTextFormattedLog(
              @NotNull final String fieldName,
              @NotNull final T fieldValue,
              @NotNull final byte[] pepper,
              @NotNull final ByteStringBuffer buffer);



  /**
   * Appends a completely tokenized representation of the specified field (both
   * field name and value) for a JSON-formatted log message to the given buffer.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   * @param  pepper      A pepper used to provide brute-force protection for the
   *                     resulting token.  The pepper value should be kept
   *                     secret so that it is not available to unauthorized
   *                     users who might be able to view log information,
   *                     although the same pepper value should be consistently
   *                     provided when tokenizing values so that the same value
   *                     will consistently yield the same token.  It must not be
   *                     {@code null} and should not be empty.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logCompletelyTokenizedFieldToJSONFormattedLog(
              @NotNull final String fieldName,
              @NotNull final T fieldValue,
              @NotNull final byte[] pepper,
              @NotNull final JSONBuffer buffer);



  /**
   * Appends a completely tokenized representation of the provided value
   * (without a field name, as might be suitable for a value included in a JSON
   * array) for a JSON-formatted log message to the given buffer.
   *
   * @param  value   The value to be appended to the buffer in tokenized form.
   *                 It must not be {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   * @param  buffer  The buffer to which the tokenized value should be appended.
   *                 It must not be {@code null}.
   */
  public abstract void logCompletelyTokenizedValueToJSONFormattedLog(
              @NotNull final T value,
              @NotNull final byte[] pepper,
              @NotNull final JSONBuffer buffer);



  /**
   * Indicates whether this syntax supports tokenizing individual components of
   * the entire value.
   *
   * @return  {@code true} if this syntax supports tokenizing individual
   *          components of the entire value, or {@code false} if not.
   */
  public abstract boolean supportsTokenizedComponents();



  /**
   * Determines whether the provided value string represents a value that has
   * had one or more components tokenized.
   *
   * @param  valueString  The value for which to make the determination.  It
   *                      must not be {@code null}.
   *
   * @return  {@code true} if the provided value string represents a value that
   *          has had one or more components tokenized, or {@code false} if not.
   */
  public boolean valueStringIncludesTokenizedComponent(
                      @NotNull final String valueString)
  {
    final int tokenStartPos = valueString.indexOf(TOKEN_PREFIX_STRING);
    return ((tokenStartPos >= 0) &&
         (valueString.indexOf(TOKEN_SUFFIX_STRING,
              TOKEN_PREFIX_STRING.length()) > 0));
  }



  /**
   * Indicates whether values with one or more tokenized components still
   * conform to this syntax.
   *
   * @return  {@code true} if values with one or more tokenized components still
   *          conform to this syntax.
   */
  public abstract boolean valueWithTokenizedComponentsConformsToSyntax();



  /**
   * Retrieves a string that provides a representation of the given value with
   * zero or more of its components tokenized.  If this syntax does not support
   * tokenized components, then the entire value should be tokenized.
   * <BR><BR>
   * The resulting tokens will protect components of the provided value by
   * representing them in a way that makes it at infeasible to determine what
   * the original components were. However, tokenizing the same value with the
   * same pepper should consistently yield the same token value, so that it will
   * be possible to identify the same value across multiple log messages.
   *
   * @param  value   The value whose components should be tokenized.  It must
   *                 not be {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   *
   * @return  A string that represents a tokenized representation of the
   *          provided value.
   */
  @NotNull()
  public String tokenizeComponents(@NotNull final T value,
                                   @NotNull final byte[] pepper)
  {
    final ByteStringBuffer buffer = getTemporaryBuffer();
    try
    {
      tokenizeComponents(value, pepper, buffer);
      return buffer.toString();
    }
    finally
    {
      releaseTemporaryBuffer(buffer);
    }
  }



  /**
   * Appends a string representation of the given value with zero or more of its
   * components tokenized to the provided buffer.  If this syntax does not
   * support tokenized components, then the entire value should be tokenized.
   * <BR><BR>
   * The resulting tokens will protect components of the provided value by
   * representing them in a way that makes it at infeasible to determine what
   * the original components were. However, tokenizing the same value with the
   * same pepper should consistently yield the same token value, so that it will
   * be possible to identify the same value across multiple log messages.
   *
   * @param  value   The value whose components should be tokenized.  It must
   *                 not be {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   * @param  buffer  The buffer to which the tokenized representation should be
   *                 appended.  It must not be {@code null}.
   */
  public void tokenizeComponents(@NotNull final T value,
                                 @NotNull final byte[] pepper,
                                 @NotNull final ByteStringBuffer buffer)
  {
    tokenizeEntireValue(value, pepper, buffer);
  }



  /**
   * Appends a representation of the specified field (both field name and value)
   * with tokenized value components for a text-formatted log message to the
   * given buffer.  If this syntax does not support tokenizing components within
   * a value, then it should tokenize the entire value.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   * @param  pepper      A pepper used to provide brute-force protection for the
   *                     resulting token.  The pepper value should be kept
   *                     secret so that it is not available to unauthorized
   *                     users who might be able to view log information,
   *                     although the same pepper value should be consistently
   *                     provided when tokenizing values so that the same value
   *                     will consistently yield the same token.  It must not be
   *                     {@code null} and should not be empty.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logTokenizedComponentsFieldToTextFormattedLog(
              @NotNull final String fieldName,
              @NotNull final T fieldValue,
              @NotNull final byte[] pepper,
              @NotNull final ByteStringBuffer buffer);



  /**
   * Appends a representation of the specified field (both field name and value)
   * with tokenized value components for a JSON-formatted log message to the
   * given buffer.  If this syntax does not support tokenizing components within
   * a value, then it should tokenize the entire value.
   *
   * @param  fieldName   The name for the field.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   * @param  pepper      A pepper used to provide brute-force protection for the
   *                     resulting token.  The pepper value should be kept
   *                     secret so that it is not available to unauthorized
   *                     users who might be able to view log information,
   *                     although the same pepper value should be consistently
   *                     provided when tokenizing values so that the same value
   *                     will consistently yield the same token.  It must not be
   *                     {@code null} and should not be empty.
   * @param  buffer      The buffer to which the sanitized log field should be
   *                     appended.  It must not be {@code null}.
   */
  public abstract void logTokenizedComponentsFieldToJSONFormattedLog(
              @NotNull final String fieldName,
              @NotNull final T fieldValue,
              @NotNull final byte[] pepper,
              @NotNull final JSONBuffer buffer);



  /**
   * Appends a representation of the provided value (without a field name, as
   * might be suitable for a value included in a JSON array) with tokenized
   * value components for a JSON-formatted log message to the given buffer.  If
   * this syntax does not support tokenizing components within a value, then it
   * should tokenize the entire value.
   *
   * @param  value   The value to be appended to the buffer in tokenized form.
   *                 It must not be {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   * @param  buffer  The buffer to which the tokenized value should be appended.
   *                 It must not be {@code null}.
   */
  public abstract void logTokenizedComponentsValueToJSONFormattedLog(
              @NotNull final T value,
              @NotNull final byte[] pepper,
              @NotNull final JSONBuffer buffer);



  /**
   * Retrieves a tokenized representation of the provided string.
   *
   * @param  string  The string to be tokenized.  It must not be {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   *
   * @return  A tokenized representation of the provided string.
   */
  @NotNull()
  protected final String tokenize(@NotNull final String string,
                                  @NotNull final byte[] pepper)
  {
    final ByteStringBuffer buffer = getTemporaryBuffer();
    try
    {
      tokenize(string, pepper, buffer);
      return buffer.toString();
    }
    finally
    {
      releaseTemporaryBuffer(buffer);
    }

  }



  /**
   * Appends a tokenized representation of the provided string to the given
   * buffer.
   *
   * @param  string  The string to be tokenized.  It must not be {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   * @param  buffer  The buffer to which the tokenized representation should be
   *                 appended.  It must not be {@code null}.
   */
  protected final void tokenize(@NotNull final String string,
                                @NotNull final byte[] pepper,
                                @NotNull final ByteStringBuffer buffer)
  {
    tokenize(StaticUtils.getBytes(string), pepper, buffer);
  }



  /**
   * Appends a tokenized representation of the provided bytes to the given
   * buffer.
   *
   * @param  bytes   The bytes to be tokenized.  It must not be {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   * @param  buffer  The buffer to which the tokenized representation should be
   *                 appended.  It must not be {@code null}.
   */
  protected final void tokenize(@NotNull final byte[] bytes,
                                @NotNull final byte[] pepper,
                                @NotNull final ByteStringBuffer buffer)
  {
    // Concatenate the provided bytes and the pepper.
    final ByteStringBuffer concatBuffer = getTemporaryBuffer();
    try
    {
      concatBuffer.append(bytes);
      concatBuffer.append(pepper);


      // Compute a digest of the concatenated value.
      final byte[] digestBytes = sha256(concatBuffer);


      // Base64-encode a portion of the digest to use as the token.  Use the
      // base64url syntax to avoid including the plus and slash characters,
      // which might cause issues in certain cases (for example, the plus sign
      // needs to be escaped in DNs because it would otherwise represent the
      // start of the next component of a multivalued RDN).
      buffer.append(TOKEN_PREFIX_STRING);
      Base64.urlEncode(digestBytes, 0, TOKEN_DIGEST_BYTES_LENGTH, buffer,
           false);
      buffer.append(TOKEN_SUFFIX_STRING);
    }
    finally
    {
      releaseTemporaryBuffer(concatBuffer);
    }
  }



  /**
   * Retrieves a SHA-256 digest of the contents of the provided buffer.
   *
   * @param  buffer  The buffer containing the data to digest.  It must not be
   *                 {@code null}.
   *
   * @return  The bytes that comprise the SHA-256 digest.
   */
  @NotNull()
  protected final byte[] sha256(@NotNull final ByteStringBuffer buffer)
  {
    MessageDigest digest = threadLocalDigests.get();
    if (digest == null)
    {
      try
      {
        digest = CryptoHelper.getMessageDigest(TOKEN_DIGEST_ALGORITHM);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPRuntimeException(new LDAPException(
             ResultCode.ENCODING_ERROR,
             ERR_LOG_SYNTAX_TOKENIZE_DIGEST_ERROR.get(TOKEN_DIGEST_ALGORITHM),
             e));
      }
    }

    digest.update(buffer.getBackingArray(), 0, buffer.length());
    return digest.digest();
  }



  /**
   * Retrieves a temporary thread-local buffer that may be used during
   * processing.  When it is no longer needed, the buffer should be returned
   * with the {@link #releaseTemporaryBuffer(ByteStringBuffer)} method.
   *
   * @return  A temporary thread-local buffer that may be used during
   *          processing.
   */
  @NotNull()
  protected ByteStringBuffer getTemporaryBuffer()
  {
    LinkedList<ByteStringBuffer> bufferList = threadLocalBuffers.get();
    if (bufferList == null)
    {
      bufferList = new LinkedList<>();
      threadLocalBuffers.set(bufferList);
    }

    if (bufferList.isEmpty())
    {
      return new ByteStringBuffer();
    }

    return bufferList.remove();
  }



  /**
   * Releases the provided temporary buffer.
   *
   * @param  buffer  The buffer to release.  It must not be {@code null}.
   */
  protected void releaseTemporaryBuffer(@NotNull final ByteStringBuffer buffer)
  {
    buffer.clear();

    LinkedList<ByteStringBuffer> bufferList = threadLocalBuffers.get();
    if (bufferList == null)
    {
      bufferList = new LinkedList<>();
      threadLocalBuffers.set(bufferList);
    }

    bufferList.add(buffer);
  }
}
