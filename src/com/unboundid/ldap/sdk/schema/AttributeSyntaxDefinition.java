/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.schema;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.LinkedHashMap;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.schema.SchemaMessages.*;



/**
 * This class provides a data structure that describes an LDAP attribute syntax
 * schema element.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AttributeSyntaxDefinition
       extends SchemaElement
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8593718232711987488L;



  // The set of extensions for this attribute syntax.
  @NotNull private final Map<String,String[]> extensions;

  // The description for this attribute syntax.
  @Nullable private final String description;

  // The string representation of this attribute syntax.
  @NotNull private final String attributeSyntaxString;

  // The OID for this attribute syntax.
  @NotNull private final String oid;



  /**
   * Creates a new attribute syntax from the provided string representation.
   *
   * @param  s  The string representation of the attribute syntax to create,
   *            using the syntax described in RFC 4512 section 4.1.5.  It must
   *            not be {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as an
   *                         attribute syntax definition.
   */
  public AttributeSyntaxDefinition(@NotNull final String s)
         throws LDAPException
  {
    Validator.ensureNotNull(s);

    attributeSyntaxString = s.trim();

    // The first character must be an opening parenthesis.
    final int length = attributeSyntaxString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ATTRSYNTAX_DECODE_EMPTY.get());
    }
    else if (attributeSyntaxString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ATTRSYNTAX_DECODE_NO_OPENING_PAREN.get(
                                   attributeSyntaxString));
    }


    // Skip over any spaces until we reach the start of the OID, then read the
    // OID until we find the next space.
    int pos = skipSpaces(attributeSyntaxString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(attributeSyntaxString, pos, length, buffer);
    oid = buffer.toString();


    // Technically, attribute syntax elements are supposed to appear in a
    // specific order, but we'll be lenient and allow remaining elements to come
    // in any order.
    String descr = null;
    final Map<String,String[]> exts  =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));

    while (true)
    {
      // Skip over any spaces until we find the next element.
      pos = skipSpaces(attributeSyntaxString, pos, length);

      // Read until we find the next space or the end of the string.  Use that
      // token to figure out what to do next.
      final int tokenStartPos = pos;
      while ((pos < length) && (attributeSyntaxString.charAt(pos) != ' '))
      {
        pos++;
      }

      final String token = attributeSyntaxString.substring(tokenStartPos, pos);
      final String lowerToken = StaticUtils.toLowerCase(token);
      if (lowerToken.equals(")"))
      {
        // This indicates that we're at the end of the value.  There should not
        // be any more closing characters.
        if (pos < length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRSYNTAX_DECODE_CLOSE_NOT_AT_END.get(
                                       attributeSyntaxString));
        }
        break;
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(attributeSyntaxString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(attributeSyntaxString, pos, length, token, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRSYNTAX_DECODE_MULTIPLE_DESC.get(
                                       attributeSyntaxString));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(attributeSyntaxString, pos, length);

        final ArrayList<String> valueList = new ArrayList<>(5);
        pos = readQDStrings(attributeSyntaxString, pos, length, token,
             valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRSYNTAX_DECODE_DUP_EXT.get(
                                       attributeSyntaxString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRSYNTAX_DECODE_UNEXPECTED_TOKEN.get(
                                       attributeSyntaxString, token));
      }
    }

    description = descr;
    extensions  = Collections.unmodifiableMap(exts);
  }



  /**
   * Creates a new attribute syntax use with the provided information.
   *
   * @param  oid          The OID for this attribute syntax.  It must not be
   *                      {@code null}.
   * @param  description  The description for this attribute syntax.  It may be
   *                      {@code null} if there is no description.
   * @param  extensions   The set of extensions for this attribute syntax.  It
   *                      may be {@code null} or empty if there should not be
   *                      any extensions.
   */
  public AttributeSyntaxDefinition(@NotNull final String oid,
              @Nullable final String description,
              @Nullable final Map<String,String[]> extensions)
  {
    Validator.ensureNotNull(oid);

    this.oid         = oid;
    this.description = description;

    if (extensions == null)
    {
      this.extensions = Collections.emptyMap();
    }
    else
    {
      this.extensions = Collections.unmodifiableMap(extensions);
    }

    final StringBuilder buffer = new StringBuilder();
    createDefinitionString(buffer);
    attributeSyntaxString = buffer.toString();
  }



  /**
   * Constructs a string representation of this attribute syntax definition in
   * the provided buffer.
   *
   * @param  buffer  The buffer in which to construct a string representation of
   *                 this attribute syntax definition.
   */
  private void createDefinitionString(@NotNull final StringBuilder buffer)
  {
    buffer.append("( ");
    buffer.append(oid);

    if (description != null)
    {
      buffer.append(" DESC '");
      encodeValue(description, buffer);
      buffer.append('\'');
    }

    for (final Map.Entry<String,String[]> e : extensions.entrySet())
    {
      final String   name   = e.getKey();
      final String[] values = e.getValue();
      if (values.length == 1)
      {
        buffer.append(' ');
        buffer.append(name);
        buffer.append(" '");
        encodeValue(values[0], buffer);
        buffer.append('\'');
      }
      else
      {
        buffer.append(' ');
        buffer.append(name);
        buffer.append(" (");
        for (final String value : values)
        {
          buffer.append(" '");
          encodeValue(value, buffer);
          buffer.append('\'');
        }
        buffer.append(" )");
      }
    }

    buffer.append(" )");
  }



  /**
   * Retrieves the OID for this attribute syntax.
   *
   * @return  The OID for this attribute syntax.
   */
  @NotNull()
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the description for this attribute syntax, if available.
   *
   * @return  The description for this attribute syntax, or {@code null} if
   *          there is no description defined.
   */
  @Nullable()
  public String getDescription()
  {
    return description;
  }



  /**
   * Retrieves the set of extensions for this matching rule use.  They will be
   * mapped from the extension name (which should start with "X-") to the set
   * of values for that extension.
   *
   * @return  The set of extensions for this matching rule use.
   */
  @NotNull()
  public Map<String,String[]> getExtensions()
  {
    return extensions;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SchemaElementType getSchemaElementType()
  {
    return SchemaElementType.ATTRIBUTE_SYNTAX;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    return oid.hashCode();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof AttributeSyntaxDefinition))
    {
      return false;
    }

    final AttributeSyntaxDefinition d = (AttributeSyntaxDefinition) o;
    return (oid.equals(d.oid) &&
         StaticUtils.bothNullOrEqualIgnoreCase(description, d.description) &&
         extensionsEqual(extensions, d.extensions));
  }



  /**
   * Retrieves a string representation of this attribute syntax, in the format
   * described in RFC 4512 section 4.1.5.
   *
   * @return  A string representation of this attribute syntax definition.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return attributeSyntaxString;
  }
}
