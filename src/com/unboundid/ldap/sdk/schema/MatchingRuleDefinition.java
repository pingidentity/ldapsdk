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
 * This class provides a data structure that describes an LDAP matching rule
 * schema element.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MatchingRuleDefinition
       extends SchemaElement
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8214648655449007967L;



  // Indicates whether this matching rule is declared obsolete.
  private final boolean isObsolete;

  // The set of extensions for this matching rule.
  @NotNull private final Map<String,String[]> extensions;

  // The description for this matching rule.
  @Nullable private final String description;

  // The string representation of this matching rule.
  @NotNull private final String matchingRuleString;

  // The OID for this matching rule.
  @NotNull private final String oid;

  // The OID of the syntax for this matching rule.
  @NotNull private final String syntaxOID;

  // The set of names for this matching rule.
  @NotNull private final String[] names;



  /**
   * Creates a new matching rule from the provided string representation.
   *
   * @param  s  The string representation of the matching rule to create, using
   *            the syntax described in RFC 4512 section 4.1.3.  It must not be
   *            {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as a
   *                         matching rule definition.
   */
  public MatchingRuleDefinition(@NotNull final String s)
         throws LDAPException
  {
    Validator.ensureNotNull(s);

    matchingRuleString = s.trim();

    // The first character must be an opening parenthesis.
    final int length = matchingRuleString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MR_DECODE_EMPTY.get());
    }
    else if (matchingRuleString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MR_DECODE_NO_OPENING_PAREN.get(
                                   matchingRuleString));
    }


    // Skip over any spaces until we reach the start of the OID, then read the
    // OID until we find the next space.
    int pos = skipSpaces(matchingRuleString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(matchingRuleString, pos, length, buffer);
    oid = buffer.toString();


    // Technically, matching rule elements are supposed to appear in a specific
    // order, but we'll be lenient and allow remaining elements to come in any
    // order.
    final ArrayList<String> nameList = new ArrayList<>(1);
    String descr = null;
    Boolean obsolete = null;
    String synOID = null;
    final Map<String,String[]> exts =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));

    while (true)
    {
      // Skip over any spaces until we find the next element.
      pos = skipSpaces(matchingRuleString, pos, length);

      // Read until we find the next space or the end of the string.  Use that
      // token to figure out what to do next.
      final int tokenStartPos = pos;
      while ((pos < length) && (matchingRuleString.charAt(pos) != ' '))
      {
        pos++;
      }

      // It's possible that the token could be smashed right up against the
      // closing parenthesis.  If that's the case, then extract just the token
      // and handle the closing parenthesis the next time through.
      String token = matchingRuleString.substring(tokenStartPos, pos);
      if ((token.length() > 1) && (token.endsWith(")")))
      {
        token = token.substring(0, token.length() - 1);
        pos--;
      }

      final String lowerToken = StaticUtils.toLowerCase(token);
      if (lowerToken.equals(")"))
      {
        // This indicates that we're at the end of the value.  There should not
        // be any more closing characters.
        if (pos < length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MR_DECODE_CLOSE_NOT_AT_END.get(
                                       matchingRuleString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(matchingRuleString, pos, length);
          pos = readQDStrings(matchingRuleString, pos, length, token, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MR_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(matchingRuleString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(matchingRuleString, pos, length, token, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MR_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleString, "DESC"));
        }
      }
      else if (lowerToken.equals("obsolete"))
      {
        if (obsolete == null)
        {
          obsolete = true;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MR_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("syntax"))
      {
        if (synOID == null)
        {
          pos = skipSpaces(matchingRuleString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(matchingRuleString, pos, length, buffer);
          synOID = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MR_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleString, "SYNTAX"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(matchingRuleString, pos, length);

        final ArrayList<String> valueList = new ArrayList<>(5);
        pos = readQDStrings(matchingRuleString, pos, length, token, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MR_DECODE_DUP_EXT.get(matchingRuleString,
                                                            token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_MR_DECODE_UNEXPECTED_TOKEN.get(
                                     matchingRuleString, token));
      }
    }

    description = descr;
    syntaxOID   = synOID;
    if (syntaxOID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MR_DECODE_NO_SYNTAX.get(matchingRuleString));
    }

    names = new String[nameList.size()];
    nameList.toArray(names);

    isObsolete = (obsolete != null);

    extensions = Collections.unmodifiableMap(exts);
  }



  /**
   * Creates a new matching rule with the provided information.
   *
   * @param  oid          The OID for this matching rule.  It must not be
   *                      {@code null}.
   * @param  name         The names for this matching rule.  It may be
   *                      {@code null} if the matching rule should only be
   *                      referenced by OID.
   * @param  description  The description for this matching rule.  It may be
   *                      {@code null} if there is no description.
   * @param  syntaxOID    The syntax OID for this matching rule.  It must not be
   *                      {@code null}.
   * @param  extensions   The set of extensions for this matching rule.
   *                      It may be {@code null} or empty if there should not be
   *                      any extensions.
   */
  public MatchingRuleDefinition(@NotNull final String oid,
                                @Nullable final String name,
                                @Nullable final String description,
                                @NotNull final String syntaxOID,
                                @Nullable final Map<String,String[]> extensions)
  {
    this(oid, ((name == null) ? null : new String[] { name }), description,
         false, syntaxOID, extensions);
  }



  /**
   * Creates a new matching rule with the provided information.
   *
   * @param  oid          The OID for this matching rule.  It must not be
   *                      {@code null}.
   * @param  names        The set of names for this matching rule.  It may be
   *                      {@code null} or empty if the matching rule should only
   *                      be referenced by OID.
   * @param  description  The description for this matching rule.  It may be
   *                      {@code null} if there is no description.
   * @param  isObsolete   Indicates whether this matching rule is declared
   *                      obsolete.
   * @param  syntaxOID    The syntax OID for this matching rule.  It must not be
   *                      {@code null}.
   * @param  extensions   The set of extensions for this matching rule.
   *                      It may be {@code null} or empty if there should not be
   *                      any extensions.
   */
  public MatchingRuleDefinition(@NotNull final String oid,
                                @Nullable final String[] names,
                                @Nullable final String description,
                                final boolean isObsolete,
                                @NotNull final String syntaxOID,
                                @Nullable final Map<String,String[]> extensions)
  {
    Validator.ensureNotNull(oid, syntaxOID);

    this.oid                   = oid;
    this.description           = description;
    this.isObsolete            = isObsolete;
    this.syntaxOID             = syntaxOID;

    if (names == null)
    {
      this.names = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

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
    matchingRuleString = buffer.toString();
  }



  /**
   * Constructs a string representation of this matching rule definition in the
   * provided buffer.
   *
   * @param  buffer  The buffer in which to construct a string representation of
   *                 this matching rule definition.
   */
  private void createDefinitionString(@NotNull final StringBuilder buffer)
  {
    buffer.append("( ");
    buffer.append(oid);

    if (names.length == 1)
    {
      buffer.append(" NAME '");
      buffer.append(names[0]);
      buffer.append('\'');
    }
    else if (names.length > 1)
    {
      buffer.append(" NAME (");
      for (final String name : names)
      {
        buffer.append(" '");
        buffer.append(name);
        buffer.append('\'');
      }
      buffer.append(" )");
    }

    if (description != null)
    {
      buffer.append(" DESC '");
      encodeValue(description, buffer);
      buffer.append('\'');
    }

    if (isObsolete)
    {
      buffer.append(" OBSOLETE");
    }

    buffer.append(" SYNTAX ");
    buffer.append(syntaxOID);

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
   * Retrieves the OID for this matching rule.
   *
   * @return  The OID for this matching rule.
   */
  @NotNull()
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the set of names for this matching rule.
   *
   * @return  The set of names for this matching rule, or an empty array if it
   *          does not have any names.
   */
  @NotNull()
  public String[] getNames()
  {
    return names;
  }



  /**
   * Retrieves the primary name that can be used to reference this matching
   * rule.  If one or more names are defined, then the first name will be used.
   * Otherwise, the OID will be returned.
   *
   * @return  The primary name that can be used to reference this matching rule.
   */
  @NotNull()
  public String getNameOrOID()
  {
    if (names.length == 0)
    {
      return oid;
    }
    else
    {
      return names[0];
    }
  }



  /**
   * Indicates whether the provided string matches the OID or any of the names
   * for this matching rule.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string matches the OID or any of the
   *          names for this matching rule, or {@code false} if not.
   */
  public boolean hasNameOrOID(@NotNull final String s)
  {
    for (final String name : names)
    {
      if (s.equalsIgnoreCase(name))
      {
        return true;
      }
    }

    return s.equalsIgnoreCase(oid);
  }



  /**
   * Retrieves the description for this matching rule, if available.
   *
   * @return  The description for this matching rule, or {@code null} if there
   *          is no description defined.
   */
  @Nullable()
  public String getDescription()
  {
    return description;
  }



  /**
   * Indicates whether this matching rule is declared obsolete.
   *
   * @return  {@code true} if this matching rule is declared obsolete, or
   *          {@code false} if it is not.
   */
  public boolean isObsolete()
  {
    return isObsolete;
  }



  /**
   * Retrieves the OID of the syntax for this matching rule.
   *
   * @return  The OID of the syntax for this matching rule.
   */
  @NotNull()
  public String getSyntaxOID()
  {
    return syntaxOID;
  }



  /**
   * Retrieves the set of extensions for this matching rule.  They will be
   * mapped from the extension name (which should start with "X-") to the set
   * of values for that extension.
   *
   * @return  The set of extensions for this matching rule.
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
    return SchemaElementType.MATCHING_RULE;
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

    if (! (o instanceof MatchingRuleDefinition))
    {
      return false;
    }

    final MatchingRuleDefinition d = (MatchingRuleDefinition) o;
    return (oid.equals(d.oid) &&
         syntaxOID.equals(d.syntaxOID) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         StaticUtils.bothNullOrEqualIgnoreCase(description, d.description) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions));
  }



  /**
   * Retrieves a string representation of this matching rule definition, in the
   * format described in RFC 4512 section 4.1.3.
   *
   * @return  A string representation of this matching rule definition.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return matchingRuleString;
  }
}
