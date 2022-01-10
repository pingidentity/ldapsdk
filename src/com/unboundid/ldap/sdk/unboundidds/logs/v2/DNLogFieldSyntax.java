/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2;



import java.util.Collection;
import java.util.Set;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DNEscapingStrategy;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBuffer;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.LogMessages.*;



/**
 * This class defines a log field syntax for distinguished name values.  This
 * syntax allows individual attribute values to be redacted or tokenized within
 * the DNs.  If a DN is completely redacted, then the redacted representation
 * will be "<code>redacted={REDACTED}</code>".  If a DN is completely tokenized,
 * then the tokenized representation will be
 * "<code>tokenized={TOKENIZED:token-value}</code>", where token-value will be
 * replaced with a generated value.
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
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DNLogFieldSyntax
       extends LogFieldSyntax<DN>
{
  /**
   * The name for this syntax.
   */
  @NotNull public static final String SYNTAX_NAME = "dn";



  /**
   * The string representation that will be used for a DN that is completely
   * redacted.
   */
  @NotNull private static final String REDACTED_DN_STRING =
       "redacted={REDACTED}";



  // Indicates whether all attributes should be considered sensitive when
  // redacting or tokenizing components.
  private final boolean allAttributesAreSensitive;

  // The schema to use in processing.
  @Nullable private final Schema schema;

  // The set of the names and OIDs for the specific attributes whose values
  // should not be redacted or tokenized.
  @NotNull private final Set<String> excludedSensitiveAttributes;

  // The set of the names and OIDs for the specific attributes whose values
  // should be redacted or tokenized.
  @NotNull private final Set<String> includedSensitiveAttributes;



  /**
   * Creates a new DN log field syntax instance that can optionally define
   * specific attributes to include in or exclude from redaction or
   * tokenization.  If any include attributes are specified, then only the
   * values of those attributes will be considered sensitive and will have
   * their values tokenized or redacted.  If any exclude
   * attributes are specified, then the values of any attributes except those
   * will be considered sensitive.  If no include attributes and no exclude
   * attributes are specified, then all attributes will be considered sensitive
   * and will have their values tokenized or redacted.
   *
   * @param  maxStringLengthCharacters    The maximum length (in characters) to
   *                                      use for strings within values.
   *                                      Strings that are longer than this
   *                                      should be truncated before inclusion
   *                                      in the log.  This value must be
   *                                      greater than or equal to zero.
   * @param  schema                       The schema to use in processing.  It
   *                                      may optionally be {@code null} if no
   *                                      schema should be used.
   * @param  includedSensitiveAttributes  The set of names and OIDs for the
   *                                      specific attributes whose values
   *                                      should be considered sensitive and
   *                                      should have their values redacted or
   *                                      tokenized by methods that operate on
   *                                      value components.  This may be
   *                                      {@code null} or empty if no included
   *                                      sensitive attributes should be
   *                                      defined.
   * @param  excludedSensitiveAttributes  The set of names and OIDs for the
   *                                      specific attributes whose values
   *                                      should not be considered sensitive and
   *                                      should not have their values redacted
   *                                      or tokenized by methods that operate
   *                                      on value components.  This may be
   *                                      {@code null} or empty if no excluded
   *                                      sensitive attributes should be
   *                                      defined.
   */
  public DNLogFieldSyntax(
              final int maxStringLengthCharacters,
              @Nullable final Schema schema,
              @Nullable final Collection<String> includedSensitiveAttributes,
              @Nullable final Collection<String> excludedSensitiveAttributes)
  {
    super(maxStringLengthCharacters);

    this.schema = schema;
    this.includedSensitiveAttributes =
         AttributeBasedLogFieldSyntaxHelper.getAttributeSet(schema,
              includedSensitiveAttributes);
    this.excludedSensitiveAttributes =
         AttributeBasedLogFieldSyntaxHelper.getAttributeSet(schema,
              excludedSensitiveAttributes);

    allAttributesAreSensitive = this.includedSensitiveAttributes.isEmpty() &&
         this.excludedSensitiveAttributes.isEmpty();
  }



  /**
   * Retrieves a set containing the names and/or OIDs of the attributes that
   * will be considered sensitive and will have their values redacted or
   * tokenized in methods that operate on DN components.
   *
   * @return  A set containing the names and/or OIDs of the attributes that will
   *          be considered sensitive, or an empty list if no included sensitive
   *          attributes are defined.
   */
  @NotNull()
  public Set<String> getIncludedSensitiveAttributes()
  {
    return includedSensitiveAttributes;
  }



  /**
   * Retrieves a set containing the names and/or OIDs of the attributes that
   * will not be considered sensitive and will have not their values redacted or
   * tokenized in methods that operate on DN components.
   *
   * @return  A set containing the names and/or OIDs of the attributes that will
   *          not be considered sensitive, or an empty list if no excluded
   *          sensitive attributes are defined.
   */
  @NotNull()
  public Set<String> getExcludedSensitiveAttributes()
  {
    return excludedSensitiveAttributes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSyntaxName()
  {
    return SYNTAX_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void valueToSanitizedString(@NotNull final DN value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    final RDN[] originalRDNs = value.getRDNs();
    final RDN[] sanitizedRDNs = new RDN[originalRDNs.length];
    for (int i=0; i < originalRDNs.length; i++)
    {
      final String[] attributeNames = originalRDNs[i].getAttributeNames();
      final String[] originalValues = originalRDNs[i].getAttributeValues();
      final String[] sanitizedValues = new String[originalValues.length];
      for (int j=0; j < originalValues.length; j++)
      {
        sanitizedValues[j] = sanitize(originalValues[j]);
      }

      sanitizedRDNs[i] = new RDN(attributeNames, sanitizedValues, schema);
    }

    final DN sanitizedDN = new DN(sanitizedRDNs);
    sanitizedDN.toString(buffer, DNEscapingStrategy.DEFAULT);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final DN fieldValue,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    valueToSanitizedString(fieldValue, buffer);
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final DN fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, valueToSanitizedString(fieldValue));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public DN parseValue(@NotNull final String valueString)
         throws RedactedValueException, TokenizedValueException,
                LogSyntaxException
  {
    try
    {
      return new DN(valueString, schema);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (valueStringIsCompletelyRedacted(valueString))
      {
        throw new RedactedValueException(
             ERR_DN_LOG_SYNTAX_CANNOT_PARSE_REDACTED.get(), e);
      }
      else if (valueStringIsCompletelyTokenized(valueString))
      {
        throw new TokenizedValueException(
             ERR_DN_LOG_SYNTAX_CANNOT_PARSE_TOKENIZED.get(), e);
      }
      else
      {
        throw new LogSyntaxException(
             ERR_DN_LOG_SYNTAX_CANNOT_PARSE.get(), e);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueStringIsCompletelyRedacted(
                      @NotNull final String valueString)
  {
    return valueString.equals(REDACTED_STRING) ||
         valueString.equals(REDACTED_DN_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean completelyRedactedValueConformsToSyntax()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void redactEntireValue(@NotNull final ByteStringBuffer buffer)
  {
    buffer.append(REDACTED_DN_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    buffer.append(REDACTED_DN_STRING);
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, REDACTED_DN_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsRedactedComponents()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueWithRedactedComponentsConformsToSyntax()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void redactComponents(@NotNull final DN value,
                               @NotNull final ByteStringBuffer buffer)
  {
    final RDN[] originalRDNs = value.getRDNs();
    final RDN[] redactedRDNs = new RDN[originalRDNs.length];
    for (int i=0; i < originalRDNs.length; i++)
    {
      final RDN rdn = originalRDNs[i];
      final String[] attributeNames = rdn.getAttributeNames();
      final String[] originalValues = rdn.getAttributeValues();
      final String[] redactedValues = rdn.getAttributeValues();
      for (int j=0; j < attributeNames.length; j++)
      {
        if (shouldRedactOrTokenize(attributeNames[j]))
        {
          redactedValues[j] = REDACTED_STRING;
        }
        else
        {
          redactedValues[j] = sanitize(originalValues[j]);
        }
      }

      redactedRDNs[i] = new RDN(attributeNames, redactedValues, schema);
    }

    final DN redactedDN = new DN(redactedRDNs);
    redactedDN.toString(buffer, DNEscapingStrategy.DEFAULT);
  }



  /**
   * Indicates whether values of the specified attribute should be redacted or
   * tokenized.
   *
   * @param  attributeName  The name or OID of the attribute for which to make
   *                        the determination.  It must not be {@code null}.
   *
   * @return  {@code true} if values of the specified attribute should be
   *          redacted or tokenized, or {@code false} if not.
   */
  private boolean shouldRedactOrTokenize(@NotNull final String attributeName)
  {
    if (allAttributesAreSensitive)
    {
      return true;
    }

    final String lowerName = StaticUtils.toLowerCase(attributeName);
    if (includedSensitiveAttributes.contains(lowerName))
    {
      return true;
    }

    if (excludedSensitiveAttributes.isEmpty())
    {
      return false;
    }
    else
    {
      return (! excludedSensitiveAttributes.contains(lowerName));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final DN fieldValue,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    redactComponents(fieldValue, buffer);
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final DN fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, redactComponents(fieldValue));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueStringIsCompletelyTokenized(
                      @NotNull final String valueString)
  {
    return super.valueStringIsCompletelyTokenized(valueString) ||
         (valueString.startsWith("tokenized="+ TOKEN_PREFIX_STRING) &&
              valueString.endsWith(TOKEN_SUFFIX_STRING));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean completelyTokenizedValueConformsToSyntax()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void tokenizeEntireValue(@NotNull final DN value,
                                  @NotNull final byte[] pepper,
                                  @NotNull final ByteStringBuffer buffer)
  {
    buffer.append("tokenized=");
    tokenize(value.toNormalizedString(), pepper, buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final DN fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    tokenizeEntireValue(fieldValue, pepper, buffer);
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final DN fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, tokenizeEntireValue(fieldValue, pepper));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsTokenizedComponents()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueWithTokenizedComponentsConformsToSyntax()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void tokenizeComponents(@NotNull final DN value,
                                 @NotNull final byte[] pepper,
                                 @NotNull final ByteStringBuffer buffer)
  {
    final RDN[] originalRDNs = value.getRDNs();
    final RDN[] tokenizedRDNs = new RDN[originalRDNs.length];
    for (int i=0; i < originalRDNs.length; i++)
    {
      final RDN rdn = originalRDNs[i];
      final String[] attributeNames = rdn.getAttributeNames();
      final String[] tokenizedValues = new String[attributeNames.length];
      for (int j=0; j < attributeNames.length; j++)
      {
        if (shouldRedactOrTokenize(attributeNames[j]))
        {
          tokenizedValues[j] =
               AttributeBasedLogFieldSyntaxHelper.tokenizeValue(this, schema,
                    attributeNames[j], rdn.getByteArrayAttributeValues()[j],
                    pepper);
        }
        else
        {
          tokenizedValues[j] = sanitize(rdn.getAttributeValues()[j]);
        }
      }

      tokenizedRDNs[i] = new RDN(attributeNames, tokenizedValues, schema);
    }

    final DN tokenizedDN = new DN(tokenizedRDNs);
    tokenizedDN.toString(buffer, DNEscapingStrategy.DEFAULT);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final DN fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    tokenizeComponents(fieldValue, pepper, buffer);
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final DN fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, tokenizeComponents(fieldValue, pepper));
  }
}
