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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an access log field syntax for values that are a
 * comma-delimited list of strings.  This syntax does support redacting and
 * tokenizing the individual items in the list.
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
public final class CommaDelimitedStringListAccessLogFieldSyntax
       extends AccessLogFieldSyntax<List<String>>
{
  /**
   * The name for this syntax.
   */
  @NotNull public static final String SYNTAX_NAME =
       "comma-delimited-string-list";



  /**
   * Creates a new instance of this access log field syntax implementation.
   *
   * @param  maxStringLengthCharacters  The maximum length (in characters) to
   *                                    use for strings within values.  Strings
   *                                    that are longer than this should be
   *                                    truncated before inclusion in the log.
   *                                    This value must be greater than or equal
   *                                    to zero.
   */
  public CommaDelimitedStringListAccessLogFieldSyntax(
              final int maxStringLengthCharacters)
  {
    super(maxStringLengthCharacters);
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
  public void valueToSanitizedString(@NotNull final List<String> value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    final Iterator<String> iterator = value.iterator();
    while (iterator.hasNext())
    {
      sanitize(iterator.next(), buffer);
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> parseValue(@NotNull final String valueString)
  {
    final List<String> list = new ArrayList<>();
    int lastCommaPos = -1;
    int commaPos = valueString.indexOf(',');
    while (commaPos >= 0)
    {
      final String item =
           valueString.substring((lastCommaPos + 1), commaPos).trim();
      list.add(item);
      lastCommaPos = commaPos;
      commaPos = valueString.indexOf(',', (lastCommaPos + 1));
    }

    final String item = valueString.substring(lastCommaPos + 1).trim();
    if (! (item.isEmpty() && list.isEmpty()))
    {
      list.add(item);
    }

    return Collections.unmodifiableList(list);
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
  public void redactComponents(@NotNull final List<String> value,
                               @NotNull final ByteStringBuffer buffer)
  {
    final Iterator<String> iterator = value.iterator();
    while (iterator.hasNext())
    {
      buffer.append(REDACTED_STRING);
      iterator.next();
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
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
  @NotNull()
  public String tokenizeEntireValue(@NotNull final List<String> value,
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
   * {@inheritDoc}
   */
  @Override()
  public void tokenizeEntireValue(@NotNull final List<String> value,
                                  @NotNull final byte[] pepper,
                                  @NotNull final ByteStringBuffer buffer)
  {
    tokenize(valueToSanitizedString(value), pepper, buffer);
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
  public void tokenizeComponents(@NotNull final List<String> value,
                                 @NotNull final byte[] pepper,
                                 @NotNull final ByteStringBuffer buffer)
  {
    final Iterator<String> iterator = value.iterator();
    while (iterator.hasNext())
    {
      buffer.append(tokenize(iterator.next(), pepper));

      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }
  }
}
