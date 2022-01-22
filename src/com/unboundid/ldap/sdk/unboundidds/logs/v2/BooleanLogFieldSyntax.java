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



import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBuffer;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.LogMessages.*;



/**
 * This class defines a log field syntax for Boolean values.  This syntax does
 * not support redacting or tokenizing individual components within the values.
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
public final class BooleanLogFieldSyntax
       extends LogFieldSyntax<Boolean>
{
  /**
   * The name for this syntax.
   */
  @NotNull public static final String SYNTAX_NAME = "boolean";



  /**
   * A singleton instance of this log field syntax.
   */
  @NotNull private static final BooleanLogFieldSyntax INSTANCE =
       new BooleanLogFieldSyntax();



  /**
   * Creates a new instance of this log field syntax implementation.
   */
  private BooleanLogFieldSyntax()
  {
    super(100);
  }



  /**
   * Retrieves a singleton instance of this log field syntax.
   *
   * @return  A singleton instance of this log field syntax.
   */
  @NotNull()
  public static BooleanLogFieldSyntax getInstance()
  {
    return INSTANCE;
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
  @NotNull()
  public String valueToSanitizedString(@NotNull final Boolean value)
  {
    return value.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void valueToSanitizedString(@NotNull final Boolean value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Boolean fieldValue,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append('=');
    buffer.append(fieldValue.toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Boolean fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendBoolean(fieldName, fieldValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedValueToJSONFormattedLog(
              @NotNull final Boolean value,
              @NotNull final JSONBuffer buffer)
  {
    buffer.appendBoolean(value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Boolean parseValue(@NotNull final String valueString)
         throws RedactedValueException, TokenizedValueException,
                LogSyntaxException
  {
    final String lowerValue = StaticUtils.toLowerCase(valueString);
    if (lowerValue.equals("true"))
    {
      return Boolean.TRUE;
    }
    else if (lowerValue.equals("false"))
    {
      return Boolean.FALSE;
    }
    else if (valueStringIncludesRedactedComponent(valueString))
    {
      throw new RedactedValueException(
           ERR_BOOLEAN_LOG_SYNTAX_CANNOT_PARSE_REDACTED.get());
    }
    else if (valueStringIncludesTokenizedComponent(valueString))
    {
      throw new TokenizedValueException(
           ERR_BOOLEAN_LOG_SYNTAX_CANNOT_PARSE_TOKENIZED.get());
    }
    else
    {
      throw new LogSyntaxException(
           ERR_BOOLEAN_LOG_SYNTAX_CANNOT_PARSE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean completelyRedactedValueConformsToSyntax()
  {
    return false;
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
    buffer.append("=\"{REDACTED}\"");
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, REDACTED_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedValueToJSONFormattedLog(
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(REDACTED_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsRedactedComponents()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueWithRedactedComponentsConformsToSyntax()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Boolean fieldValue,
                   @NotNull final ByteStringBuffer buffer)
  {
    logCompletelyRedactedFieldToTextFormattedLog(fieldName, buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Boolean fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyRedactedFieldToJSONFormattedLog(fieldName, buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsValueToJSONFormattedLog(
                   @NotNull final Boolean value,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyRedactedValueToJSONFormattedLog(buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean completelyTokenizedValueConformsToSyntax()
  {
    return false;
  }




  /**
   * {@inheritDoc}
   */
  @Override()
  public void tokenizeEntireValue(@NotNull final Boolean value,
                                  @NotNull final byte[] pepper,
                                  @NotNull final ByteStringBuffer buffer)
  {
    tokenize(value.toString(), pepper, buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Boolean fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    tokenize(fieldValue.toString(), pepper, buffer);
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Boolean fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, tokenize(fieldValue.toString(), pepper));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedValueToJSONFormattedLog(
                   @NotNull final Boolean value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(tokenize(value.toString(), pepper));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsTokenizedComponents()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueWithTokenizedComponentsConformsToSyntax()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Boolean fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final ByteStringBuffer buffer)
  {
    logCompletelyTokenizedFieldToTextFormattedLog(fieldName, fieldValue, pepper,
         buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Boolean fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyTokenizedFieldToJSONFormattedLog(fieldName, fieldValue, pepper,
         buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsValueToJSONFormattedLog(
                   @NotNull final Boolean value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyTokenizedValueToJSONFormattedLog(value, pepper, buffer);
  }
}
