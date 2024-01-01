/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBuffer;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.
                   LogSyntaxMessages.*;



/**
 * This class defines a log field syntax for values that are JSON objects.  This
 * syntax allows individual field values to be redacted or tokenized within the
 * JSON objects.  If a JSON object is completely redacted, then the redacted
 * representation will be <code>{ "redacted":"{REDACTED}" }</code>.  If a JSON
 * object is completely tokenized, then the tokenized representation will be
 * <code>{ "tokenized":"{TOKENIZED:token-value}" }</code>", where token-value
 * will be replaced with a generated value.
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
public final class JSONLogFieldSyntax
       extends LogFieldSyntax<JSONObject>
{
  /**
   * The name for this syntax.
   */
  @NotNull public static final String SYNTAX_NAME = "json";



  /**
   * A JSON object that represents a completely redacted value.
   */
  @NotNull private static final JSONObject REDACTED_JSON_OBJECT =
       new JSONObject(new JSONField("redacted", REDACTED_STRING));



  /**
   * The string representation that will be used for a JSON object that is
   * completely redacted.
   */
  @NotNull private static final String REDACTED_JSON_OBJECT_STRING =
       REDACTED_JSON_OBJECT.toSingleLineString();



  /**
   * The string representation that will be used for a JSON object that is
   * completely redacted.
   */
  @NotNull private static final String
       REDACTED_JSON_OBJECT_STRING_WITH_REPLACED_QUOTES =
            REDACTED_JSON_OBJECT_STRING.replace('"', '\'');



  // Indicates whether all fields should be considered sensitive when redacting
  // or tokenizing components.
  private final boolean allFieldsAreSensitive;

  // The set of the names and OIDs for the specific fields whose values should
  // not be redacted or tokenized.
  @NotNull private final Set<String> excludedSensitiveFields;

  // The set of the names and OIDs for the specific fields whose values should
  // be redacted or tokenized.
  @NotNull private final Set<String> includedSensitiveFields;



  /**
   * Creates a new JSON log field syntax instance that can optionally define
   * specific fields to include in or exclude from redaction or tokenization.
   * If any include fields are specified, then only the values of those fields
   * will be considered sensitive and will have their values tokenized or
   * redacted.  If any exclude fields are specified, then the values of any
   * fields except those will be considered sensitive.  If no include fields and
   * no exclude fields are specified, then all fields will be considered
   * sensitive and will have their values tokenized or redacted.
   *
   * @param  maxStringLengthCharacters  The maximum length (in characters) to
   *                                    use for strings within values.  Strings
   *                                    that are longer than this should be
   *                                    truncated before inclusion in the log.
   *                                    This value must be greater than or equal
   *                                    to zero.
   * @param  includedSensitiveFields    The names for the JSON fields whose
   *                                    values should be considered sensitive
   *                                    and should have their values redacted or
   *                                    tokenized by methods that operate on
   *                                    value components.  This may be
   *                                    {@code null} or empty if no included
   *                                    sensitive fields should be defined.
   * @param  excludedSensitiveFields    The names for the specific fields whose
   *                                    values should not be considered
   *                                    sensitive and should not have their
   *                                    values redacted or tokenized by methods
   *                                    that operate on value components.  This
   *                                    may be {@code null} or empty if no
   *                                    excluded sensitive fields should be
   *                                    defined.
   */
  public JSONLogFieldSyntax(
              final int maxStringLengthCharacters,
              @Nullable final Collection<String> includedSensitiveFields,
              @Nullable final Collection<String> excludedSensitiveFields)
  {
    super(maxStringLengthCharacters);

    this.includedSensitiveFields = getLowercaseNames(includedSensitiveFields);
    this.excludedSensitiveFields = getLowercaseNames(excludedSensitiveFields);
    allFieldsAreSensitive = this.includedSensitiveFields.isEmpty() &&
         this.excludedSensitiveFields.isEmpty();
  }



  /**
   * Retrieves a set containing the lowercase representations of the provided
   * names.
   *
   * @param  names  The set of names to be converted to lowercase.  It may be
   *                {@code null} or empty.
   *
   * @return  A set containing the lowercase representations of the provided
   *          names, or an empty set if the given collection is {@code null} or
   *          empty.
   */
  @NotNull()
  private static Set<String> getLowercaseNames(
               @Nullable final Collection<String> names)
  {
    if (names == null)
    {
      return Collections.emptySet();
    }
    else
    {
      final Set<String> lowercaseNames = new HashSet<>();
      for (final String name : names)
      {
        lowercaseNames.add(StaticUtils.toLowerCase(name));
      }

      return Collections.unmodifiableSet(lowercaseNames);
    }
  }



  /**
   * Retrieves the names of the JSON fields whose values should be considered
   * sensitive and should have their values redacted or tokenized by methods
   * that operate on value components.
   *
   * @return  The names of the JSON fields whose values should be considered
   *          sensitive, or an empty list if no included sensitive field names
   *          have been defined.
   */
  @NotNull()
  public Set<String> getIncludedSensitiveFields()
  {
    return includedSensitiveFields;
  }



  /**
   * Retrieves the names of the JSON fields whose values should not be
   * considered sensitive and should not have their values redacted or tokenized
   * by methods that operate on value components.
   *
   * @return  The names of the JSON fields whose values should not be considered
   *          sensitive, or an empty list if no excluded sensitive field names
   *          have been defined.
   */
  @NotNull()
  public Set<String> getExcludedSensitiveFields()
  {
    return excludedSensitiveFields;
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
  public void valueToSanitizedString(@NotNull final JSONObject value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(sanitize(value).toSingleLineString());
  }



  /**
   * Sanitizes the provided JSON value.
   *
   * @param  value  The value to be sanitized.  It must not be {@code null}.
   *
   * @return  A sanitized representation of the provided JSON value.
   */
  @NotNull()
  private JSONValue sanitize(@NotNull final JSONValue value)
  {
    if (value instanceof JSONObject)
    {
      final Map<String,JSONValue> originalFields =
           ((JSONObject) value).getFields();
      final Map<String,JSONValue> sanitizedFields =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(
                originalFields.size()));
      for (final Map.Entry<String,JSONValue> e : originalFields.entrySet())
      {
        sanitizedFields.put(e.getKey(), sanitize(e.getValue()));
      }
      return new JSONObject(sanitizedFields);
    }
    else if (value instanceof JSONArray)
    {
      final List<JSONValue> originalValues = ((JSONArray) value).getValues();
      final List<JSONValue> sanitizedValues =
           new ArrayList<>(originalValues.size());
      for (final JSONValue v : originalValues)
      {
        sanitizedValues.add(sanitize(v));
      }
      return new JSONArray(sanitizedValues);
    }
    else if (value instanceof JSONString)
    {
      final String stringValue = ((JSONString) value).stringValue();
      return new JSONString(sanitize(stringValue));
    }
    else
    {
      return value;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONObject fieldValue,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    buffer.append(valueToSanitizedString(fieldValue).replace('"', '\''));
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONObject fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendValue(fieldName, sanitize(fieldValue));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedValueToJSONFormattedLog(
              @NotNull final JSONObject value,
              @NotNull final JSONBuffer buffer)
  {
    buffer.appendValue(sanitize(value));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject parseValue(@NotNull final String valueString)
         throws RedactedValueException, TokenizedValueException,
                LogSyntaxException
  {
    try
    {
      return new JSONObject(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (valueStringIsCompletelyRedacted(valueString))
      {
        throw new RedactedValueException(
             ERR_JSON_LOG_SYNTAX_CANNOT_PARSE_REDACTED.get(), e);
      }
      else if (valueStringIsCompletelyTokenized(valueString))
      {
        throw new TokenizedValueException(
             ERR_JSON_LOG_SYNTAX_CANNOT_PARSE_TOKENIZED.get(), e);
      }
      else
      {
        throw new LogSyntaxException(
             ERR_JSON_LOG_SYNTAX_CANNOT_PARSE.get(), e);
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
         valueString.equals(REDACTED_JSON_OBJECT_STRING);
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
    buffer.append(REDACTED_JSON_OBJECT_STRING);
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
    buffer.append(REDACTED_JSON_OBJECT_STRING_WITH_REPLACED_QUOTES);
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
    buffer.appendValue(fieldName, REDACTED_JSON_OBJECT);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedValueToJSONFormattedLog(
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendValue(REDACTED_JSON_OBJECT);
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
  public void redactComponents(@NotNull final JSONObject value,
                               @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(redactValue(value).toString());
  }



  /**
   * Retrieves a redacted representation of the provided JSON value.
   *
   * @param  value  The value to be redacted.
   *
   * @return  A redacted representation of the provided JSON value.
   */
  @NotNull()
  private JSONValue redactValue(@NotNull final JSONValue value)
  {
    if (value instanceof JSONObject)
    {
      final Map<String,JSONValue> originalFields =
           ((JSONObject) value).getFields();
      final Map<String,JSONValue> redactedFields =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(
                originalFields.size()));
      for (final Map.Entry<String,JSONValue> e : originalFields.entrySet())
      {
        final String fieldName = e.getKey();
        if (shouldRedactOrTokenize(fieldName))
        {
          redactedFields.put(fieldName, new JSONString(REDACTED_STRING));
        }
        else
        {
          redactedFields.put(fieldName, redactValue(e.getValue()));
        }
      }
      return new JSONObject(redactedFields);
    }
    else if (value instanceof JSONArray)
    {
      final List<JSONValue> originalValues = ((JSONArray) value).getValues();
      final List<JSONValue> redactedValues =
           new ArrayList<>(originalValues.size());
      for (final JSONValue v : originalValues)
      {
        redactedValues.add(redactValue(v));
      }
      return new JSONArray(redactedValues);
    }
    else
    {
      return sanitize(value);
    }
  }



  /**
   * Indicates whether values of the specified field should be redacted or
   * tokenized.
   *
   * @param  fieldName  The name of the field for which to make the
   *                    determination.
   *
   * @return  {@code true} if values of the specified field should be redacted
   *          or tokenized, or {@code false} if not.
   */
  private boolean shouldRedactOrTokenize(@NotNull final String fieldName)
  {
    if (allFieldsAreSensitive)
    {
      return true;
    }

    final String lowerName = StaticUtils.toLowerCase(fieldName);
    if (includedSensitiveFields.contains(lowerName))
    {
      return true;
    }

    if (excludedSensitiveFields.isEmpty())
    {
      return false;
    }
    else
    {
      return (! excludedSensitiveFields.contains(lowerName));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONObject fieldValue,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    buffer.append(redactComponents(fieldValue).replace('"', '\''));
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONObject fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendValue(fieldName, redactValue(fieldValue));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsValueToJSONFormattedLog(
                   @NotNull final JSONObject value,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendValue(redactValue(value));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueStringIsCompletelyTokenized(
                      @NotNull final String valueString)
  {
    if (super.valueStringIsCompletelyTokenized(valueString))
    {
      return true;
    }

    try
    {
      final JSONObject jsonObject = new JSONObject(valueString);
      final Map<String,JSONValue> fields = jsonObject.getFields();
      return ((fields.size() == 1) &&
           fields.containsKey("tokenized"));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }
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
  public void tokenizeEntireValue(@NotNull final JSONObject value,
                                  @NotNull final byte[] pepper,
                                  @NotNull final ByteStringBuffer buffer)
  {
    final JSONObject tokenizedObject = new JSONObject(
         new JSONField("tokenized",
              tokenize(value.toNormalizedString(), pepper)));
    buffer.append(tokenizedObject.toSingleLineString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONObject fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    buffer.append(tokenizeEntireValue(fieldValue, pepper).replace('"', '\''));
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONObject fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendValue(fieldName,
         new JSONObject(new JSONField("tokenized",
              tokenize(fieldValue.toNormalizedString(), pepper))));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedValueToJSONFormattedLog(
                   @NotNull final JSONObject value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendValue(new JSONObject(new JSONField("tokenized",
         tokenize(value.toNormalizedString(), pepper))));
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
  public void tokenizeComponents(@NotNull final JSONObject value,
                                 @NotNull final byte[] pepper,
                                 @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(tokenizeValue(value, pepper).toString());
  }



  /**
   * Retrieves a tokenized representation of the provided JSON value.
   *
   * @param  value  The value to be tokenized.
   * @param  pepper  A pepper used to provide brute-force protection for the
   *                 resulting token.  The pepper value should be kept secret so
   *                 that it is not available to unauthorized users who might be
   *                 able to view log information, although the same pepper
   *                 value should be consistently provided when tokenizing
   *                 values so that the same value will consistently yield the
   *                 same token.  It must not be {@code null} and should not be
   *                 empty.
   *
   * @return  A tokenized representation of the provided JSON value.
   */
  @NotNull()
  private JSONValue tokenizeValue(@NotNull final JSONValue value,
                                  @NotNull final byte[] pepper)
  {
    if (value instanceof JSONObject)
    {
      final Map<String,JSONValue> originalFields =
           ((JSONObject) value).getFields();
      final Map<String,JSONValue> tokenizedFields =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(
                originalFields.size()));
      for (final Map.Entry<String,JSONValue> e : originalFields.entrySet())
      {
        final String fieldName = e.getKey();
        final JSONValue fieldValue = e.getValue();
        if (shouldRedactOrTokenize(fieldName))
        {
          final String tokenizedValue =
               tokenize(fieldValue.toNormalizedString(), pepper);
          tokenizedFields.put(fieldName, new JSONString(tokenizedValue));
        }
        else
        {
          tokenizedFields.put(fieldName, tokenizeValue(fieldValue, pepper));
        }
      }
      return new JSONObject(tokenizedFields);
    }
    else if (value instanceof JSONArray)
    {
      final List<JSONValue> originalValues = ((JSONArray) value).getValues();
      final List<JSONValue> tokenizedValues =
           new ArrayList<>(originalValues.size());
      for (final JSONValue v : originalValues)
      {
        tokenizedValues.add(tokenizeValue(v, pepper));
      }
      return new JSONArray(tokenizedValues);
    }
    else
    {
      return sanitize(value);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONObject fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    buffer.append(tokenizeComponents(fieldValue, pepper).replace('"', '\''));
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONObject fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendValue(fieldName, tokenizeValue(fieldValue, pepper));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsValueToJSONFormattedLog(
                   @NotNull final JSONObject value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendValue(tokenizeValue(value, pepper));
  }
}
