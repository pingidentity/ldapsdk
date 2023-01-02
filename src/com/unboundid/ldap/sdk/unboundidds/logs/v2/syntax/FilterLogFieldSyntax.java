/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Collection;
import java.util.Set;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBuffer;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.
                   LogSyntaxMessages.*;



/**
 * This class defines a log field syntax for search filter values.  This syntax
 * allows individual attribute values to be redacted or tokenized within the
 * filters.  If a filter is completely redacted, then the redacted
 * representation will be "<code>(redacted={REDACTED})</code>".  If a filter is
 * completely tokenized, then the tokenized representation will be
 * "<code>(tokenized={TOKENIZED:token-value})</code>", where token-value will be
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
public final class FilterLogFieldSyntax
       extends LogFieldSyntax<Filter>
{
  /**
   * The name for this syntax.
   */
  @NotNull public static final String SYNTAX_NAME = "filter";



  /**
   * The string representation that will be used for a DN that is completely
   * redacted.
   */
  @NotNull private static final String REDACTED_FILTER_STRING =
       "(redacted={REDACTED})";



  // Indicates whether all attributes should be considered sensitive when
  // redacting or tokenizing components.
  private final boolean allAttributesAreSensitive;

  // The set of the names and OIDs for the specific attributes whose values
  // should not be redacted or tokenized.
  @NotNull private final Set<String> excludedSensitiveAttributes;

  // The set of the names and OIDs for the specific attributes whose values
  // should be redacted or tokenized.
  @NotNull private final Set<String> includedSensitiveAttributes;



  /**
   * Creates a new filter log field syntax instance that can optionally
   * define specific attributes to include in or exclude from redaction or
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
  public FilterLogFieldSyntax(
              final int maxStringLengthCharacters,
              @Nullable final Schema schema,
              @Nullable final Collection<String> includedSensitiveAttributes,
              @Nullable final Collection<String> excludedSensitiveAttributes)
  {
    super(maxStringLengthCharacters);

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
   * tokenized in methods that operate on filter components.
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
   * tokenized in methods that operate on filter components.
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
  public void valueToSanitizedString(@NotNull final Filter value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(sanitizeFilter(value).toString());
  }



  /**
   * Retrieves a sanitized version of the provided filter.
   *
   * @param  filter  The filter to sanitize.  It must not be {@code null}.
   *
   * @return  A sanitized version of the provided filter.
   */
  @NotNull()
  private Filter sanitizeFilter(@NotNull final Filter filter)
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
        final Filter[] originalANDComponents = filter.getComponents();
        final Filter[] sanitizedANDComponents =
             new Filter[originalANDComponents.length];
        for (int i=0; i < originalANDComponents.length; i++)
        {
          sanitizedANDComponents[i] = sanitizeFilter(originalANDComponents[i]);
        }
        return Filter.createANDFilter(sanitizedANDComponents);

      case Filter.FILTER_TYPE_OR:
        final Filter[] originalORComponents = filter.getComponents();
        final Filter[] sanitizedORComponents =
             new Filter[originalORComponents.length];
        for (int i=0; i < originalORComponents.length; i++)
        {
          sanitizedORComponents[i] = sanitizeFilter(originalORComponents[i]);
        }
        return Filter.createORFilter(sanitizedORComponents);

      case Filter.FILTER_TYPE_NOT:
        return Filter.createNOTFilter(sanitizeFilter(filter.getNOTComponent()));

      case Filter.FILTER_TYPE_EQUALITY:
        return Filter.createEqualityFilter(filter.getAttributeName(),
             sanitize(filter.getAssertionValue()));

      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
        return Filter.createGreaterOrEqualFilter(filter.getAttributeName(),
             sanitize(filter.getAssertionValue()));

      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
        return Filter.createLessOrEqualFilter(filter.getAttributeName(),
             sanitize(filter.getAssertionValue()));

      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        return Filter.createApproximateMatchFilter(filter.getAttributeName(),
             sanitize(filter.getAssertionValue()));

      case Filter.FILTER_TYPE_SUBSTRING:
        final String originalSubInitial = filter.getSubInitialString();
        final String sanitizedSubInitial =
             (originalSubInitial == null) ? null : sanitize(originalSubInitial);

        final String originalSubFinal = filter.getSubFinalString();
        final String sanitizedSubFinal =
             (originalSubFinal == null) ? null : sanitize(originalSubFinal);

        final String[] originalSubAny = filter.getSubAnyStrings();
        final String[] sanitizedSubAny = new String[originalSubAny.length];
        for (int i=0; i < originalSubAny.length; i++)
        {
          sanitizedSubAny[i] = sanitize(originalSubAny[i]);
        }

        return Filter.createSubstringFilter(filter.getAttributeName(),
             sanitizedSubInitial, sanitizedSubAny, sanitizedSubFinal);

      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        return Filter.createExtensibleMatchFilter(filter.getAttributeName(),
             filter.getMatchingRuleID(), filter.getDNAttributes(),
             sanitize(filter.getAssertionValue()));

      case Filter.FILTER_TYPE_PRESENCE:
      default:
        return filter;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Filter fieldValue,
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
                   @NotNull final Filter fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, valueToSanitizedString(fieldValue));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedValueToJSONFormattedLog(
              @NotNull final Filter value,
              @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(valueToSanitizedString(value));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Filter parseValue(@NotNull final String valueString)
         throws RedactedValueException, TokenizedValueException,
                LogSyntaxException
  {
    try
    {
      return Filter.create(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (valueStringIsCompletelyRedacted(valueString))
      {
        throw new RedactedValueException(
             ERR_FILTER_LOG_SYNTAX_CANNOT_PARSE_REDACTED.get(), e);
      }
      else if (valueStringIsCompletelyTokenized(valueString))
      {
        throw new TokenizedValueException(
             ERR_FILTER_LOG_SYNTAX_CANNOT_PARSE_TOKENIZED.get(), e);
      }
      else
      {
        throw new LogSyntaxException(
             ERR_FILTER_LOG_SYNTAX_CANNOT_PARSE.get(), e);
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
         valueString.equals(REDACTED_FILTER_STRING);
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
    buffer.append(REDACTED_FILTER_STRING);
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
    buffer.append(REDACTED_FILTER_STRING);
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
    buffer.appendString(fieldName, REDACTED_FILTER_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedValueToJSONFormattedLog(
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(REDACTED_FILTER_STRING);
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
  public void redactComponents(@NotNull final Filter value,
                               @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(redactFilter(value).toString());
  }



  /**
   * Retrieves a redacted version of the provided filter.
   *
   * @param  filter  The filter to redact.  It must not be {@code null}.
   *
   * @return  A redacted version of the provided filter.
   */
  @NotNull()
  private Filter redactFilter(@NotNull final Filter filter)
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
        final Filter[] originalANDComponents = filter.getComponents();
        final Filter[] redactedANDComponents =
             new Filter[originalANDComponents.length];
        for (int i=0; i < originalANDComponents.length; i++)
        {
          redactedANDComponents[i] = redactFilter(originalANDComponents[i]);
        }
        return Filter.createANDFilter(redactedANDComponents);

      case Filter.FILTER_TYPE_OR:
        final Filter[] originalORComponents = filter.getComponents();
        final Filter[] redactedORComponents =
             new Filter[originalORComponents.length];
        for (int i=0; i < originalORComponents.length; i++)
        {
          redactedORComponents[i] = redactFilter(originalORComponents[i]);
        }
        return Filter.createORFilter(redactedORComponents);

      case Filter.FILTER_TYPE_NOT:
        return Filter.createNOTFilter(redactFilter(filter.getNOTComponent()));

      case Filter.FILTER_TYPE_EQUALITY:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createEqualityFilter(filter.getAttributeName(),
               REDACTED_STRING);
        }
        else
        {
          return Filter.createEqualityFilter(filter.getAttributeName(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createGreaterOrEqualFilter(filter.getAttributeName(),
               REDACTED_STRING);
        }
        else
        {
          return Filter.createGreaterOrEqualFilter(filter.getAttributeName(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createLessOrEqualFilter(filter.getAttributeName(),
               REDACTED_STRING);
        }
        else
        {
          return Filter.createLessOrEqualFilter(filter.getAttributeName(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createApproximateMatchFilter(filter.getAttributeName(),
               REDACTED_STRING);
        }
        else
        {
          return Filter.createApproximateMatchFilter(filter.getAttributeName(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_SUBSTRING:
        final String redactedSubInitial;
        final String redactedSubFinal;
        final String originalSubInitial = filter.getSubInitialString();
        final String originalSubFinal = filter.getSubFinalString();
        final String[] originalSubAny = filter.getSubAnyStrings();
        final String[] redactedSubAny = new String[originalSubAny.length];
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          redactedSubInitial =
               (originalSubInitial == null) ? null : REDACTED_STRING;
          redactedSubFinal =
               (originalSubFinal == null) ? null : REDACTED_STRING;
          Arrays.fill(redactedSubAny, REDACTED_STRING);
        }
        else
        {
          redactedSubInitial = (originalSubInitial == null)
               ? null
               : sanitize(originalSubInitial);
          redactedSubFinal = (originalSubFinal == null)
               ? null
               : sanitize(originalSubFinal);
          for (int i=0; i < originalSubAny.length; i++)
          {
            redactedSubAny[i] = sanitize(originalSubAny[i]);
          }
        }

        return Filter.createSubstringFilter(filter.getAttributeName(),
             redactedSubInitial, redactedSubAny, redactedSubFinal);

      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createExtensibleMatchFilter(filter.getAttributeName(),
               filter.getMatchingRuleID(), filter.getDNAttributes(),
               REDACTED_STRING);
        }
        else
        {
          return Filter.createExtensibleMatchFilter(filter.getAttributeName(),
               filter.getMatchingRuleID(), filter.getDNAttributes(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_PRESENCE:
        return filter;

      default:
        // This should never happen.
        return Filter.createEqualityFilter("redacted", "{REDACTED}");
    }
  }



  /**
   * Indicates whether values of the specified attribute should be redacted or
   * tokenized.
   *
   * @param  attributeName  The name or OID of the attribute for which to make
   *                        the determination.  It may be {@code null} if no
   *                        attribute name is available.
   *
   * @return  {@code true} if values of the specified attribute should be
   *          redacted or tokenized, or {@code false} if not.
   */
  private boolean shouldRedactOrTokenize(@Nullable final String attributeName)
  {
    if (allAttributesAreSensitive)
    {
      return true;
    }

    if (attributeName == null)
    {
      return (! excludedSensitiveAttributes.isEmpty());
    }

    final String lowerName =
         StaticUtils.toLowerCase(Attribute.getBaseName(attributeName));
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
                   @NotNull final Filter fieldValue,
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
                   @NotNull final Filter fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, redactComponents(fieldValue));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsValueToJSONFormattedLog(
                   @NotNull final Filter value,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(redactComponents(value));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueStringIsCompletelyTokenized(
                      @NotNull final String valueString)
  {
    return super.valueStringIsCompletelyTokenized(valueString) ||
         (valueString.startsWith("(tokenized="+ TOKEN_PREFIX_STRING) &&
              valueString.endsWith(TOKEN_SUFFIX_STRING + ')'));
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
  public void tokenizeEntireValue(@NotNull final Filter value,
                                  @NotNull final byte[] pepper,
                                  @NotNull final ByteStringBuffer buffer)
  {
    buffer.append("(tokenized=");
    tokenize(value.toNormalizedString(), pepper, buffer);
    buffer.append(')');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Filter fieldValue,
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
                   @NotNull final Filter fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, tokenizeEntireValue(fieldValue, pepper));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedValueToJSONFormattedLog(
                   @NotNull final Filter value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(tokenizeEntireValue(value, pepper));
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
  public void tokenizeComponents(@NotNull final Filter value,
                                 @NotNull final byte[] pepper,
                                 @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(tokenizeFilter(value, pepper).toString());
  }



  /**
   * Retrieves a tokenized version of the provided filter.
   *
   * @param  filter  The filter to tokenize.  It must not be {@code null}.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   *
   * @return  A tokenized version of the provided filter.
   */
  @NotNull()
  private Filter tokenizeFilter(@NotNull final Filter filter,
                                @NotNull final byte[] pepper)
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
        final Filter[] originalANDComponents = filter.getComponents();
        final Filter[] tokenizedANDComponents =
             new Filter[originalANDComponents.length];
        for (int i=0; i < originalANDComponents.length; i++)
        {
          tokenizedANDComponents[i] =
               tokenizeFilter(originalANDComponents[i], pepper);
        }
        return Filter.createANDFilter(tokenizedANDComponents);

      case Filter.FILTER_TYPE_OR:
        final Filter[] originalORComponents = filter.getComponents();
        final Filter[] tokenizedORComponents =
             new Filter[originalORComponents.length];
        for (int i=0; i < originalORComponents.length; i++)
        {
          tokenizedORComponents[i] =
               tokenizeFilter(originalORComponents[i], pepper);
        }
        return Filter.createORFilter(tokenizedORComponents);

      case Filter.FILTER_TYPE_NOT:
        return Filter.createNOTFilter(
             tokenizeFilter(filter.getNOTComponent(), pepper));

      case Filter.FILTER_TYPE_EQUALITY:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createEqualityFilter(filter.getAttributeName(),
               tokenize(filter.getAssertionValue(), pepper));
        }
        else
        {
          return Filter.createEqualityFilter(filter.getAttributeName(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createGreaterOrEqualFilter(filter.getAttributeName(),
               tokenize(filter.getAssertionValue(), pepper));
        }
        else
        {
          return Filter.createGreaterOrEqualFilter(filter.getAttributeName(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createLessOrEqualFilter(filter.getAttributeName(),
               tokenize(filter.getAssertionValue(), pepper));
        }
        else
        {
          return Filter.createLessOrEqualFilter(filter.getAttributeName(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createApproximateMatchFilter(filter.getAttributeName(),
               tokenize(filter.getAssertionValue(), pepper));
        }
        else
        {
          return Filter.createApproximateMatchFilter(filter.getAttributeName(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_SUBSTRING:
        final String tokenizedSubInitial;
        final String tokenizedSubFinal;
        final String originalSubInitial = filter.getSubInitialString();
        final String originalSubFinal = filter.getSubFinalString();
        final String[] originalSubAny = filter.getSubAnyStrings();
        final String[] tokenizedSubAny = new String[originalSubAny.length];
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          tokenizedSubInitial = (originalSubInitial == null)
               ? null
               : tokenize(originalSubInitial, pepper);
          tokenizedSubFinal = (originalSubFinal == null)
               ? null
               : tokenize(originalSubFinal, pepper);
          for (int i=0; i < originalSubAny.length; i++)
          {
            tokenizedSubAny[i] = tokenize(originalSubAny[i], pepper);
          }
        }
        else
        {
          tokenizedSubInitial = (originalSubInitial == null)
               ? null
               : sanitize(originalSubInitial);
          tokenizedSubFinal = (originalSubFinal == null)
               ? null
               : sanitize(originalSubFinal);
          for (int i=0; i < originalSubAny.length; i++)
          {
            tokenizedSubAny[i] = sanitize(originalSubAny[i]);
          }
        }

        return Filter.createSubstringFilter(filter.getAttributeName(),
             tokenizedSubInitial, tokenizedSubAny, tokenizedSubFinal);

      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        if (shouldRedactOrTokenize(filter.getAttributeName()))
        {
          return Filter.createExtensibleMatchFilter(filter.getAttributeName(),
               filter.getMatchingRuleID(), filter.getDNAttributes(),
               tokenize(filter.getAssertionValue(), pepper));
        }
        else
        {
          return Filter.createExtensibleMatchFilter(filter.getAttributeName(),
               filter.getMatchingRuleID(), filter.getDNAttributes(),
               sanitize(filter.getAssertionValue()));
        }

      case Filter.FILTER_TYPE_PRESENCE:
      default:
        return filter;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Filter fieldValue,
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
                   @NotNull final Filter fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, tokenizeComponents(fieldValue, pepper));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsValueToJSONFormattedLog(
                   @NotNull final Filter value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(tokenizeComponents(value, pepper));
  }
}
