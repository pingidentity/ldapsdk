/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.LinkedHashMap;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.schema.SchemaMessages.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a data structure that describes an LDAP matching rule use
 * schema element.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MatchingRuleUseDefinition
       extends SchemaElement
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2366143311976256897L;



  // Indicates whether this matching rule use is declared obsolete.
  private final boolean isObsolete;

  // The set of extensions for this matching rule use.
  private final Map<String,String[]> extensions;

  // The description for this matching rule use.
  private final String description;

  // The string representation of this matching rule use.
  private final String matchingRuleUseString;

  // The OID for this matching rule use.
  private final String oid;

  // The set of attribute types to to which this matching rule use applies.
  private final String[] applicableTypes;

  // The set of names for this matching rule use.
  private final String[] names;



  /**
   * Creates a new matching rule use from the provided string representation.
   *
   * @param  s  The string representation of the matching rule use to create,
   *            using the syntax described in RFC 4512 section 4.1.4.  It must
   *            not be {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as a
   *                         matching rule use definition.
   */
  public MatchingRuleUseDefinition(final String s)
         throws LDAPException
  {
    ensureNotNull(s);

    matchingRuleUseString = s.trim();

    // The first character must be an opening parenthesis.
    final int length = matchingRuleUseString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MRU_DECODE_EMPTY.get());
    }
    else if (matchingRuleUseString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MRU_DECODE_NO_OPENING_PAREN.get(
                                   matchingRuleUseString));
    }


    // Skip over any spaces until we reach the start of the OID, then read the
    // OID until we find the next space.
    int pos = skipSpaces(matchingRuleUseString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(matchingRuleUseString, pos, length, buffer);
    oid = buffer.toString();


    // Technically, matching rule use elements are supposed to appear in a
    // specific order, but we'll be lenient and allow remaining elements to come
    // in any order.
    final ArrayList<String> nameList = new ArrayList<String>(1);
    final ArrayList<String> typeList = new ArrayList<String>(1);
    String               descr       = null;
    Boolean              obsolete    = null;
    final Map<String,String[]> exts  = new LinkedHashMap<String,String[]>();

    while (true)
    {
      // Skip over any spaces until we find the next element.
      pos = skipSpaces(matchingRuleUseString, pos, length);

      // Read until we find the next space or the end of the string.  Use that
      // token to figure out what to do next.
      final int tokenStartPos = pos;
      while ((pos < length) && (matchingRuleUseString.charAt(pos) != ' '))
      {
        pos++;
      }

      // It's possible that the token could be smashed right up against the
      // closing parenthesis.  If that's the case, then extract just the token
      // and handle the closing parenthesis the next time through.
      String token = matchingRuleUseString.substring(tokenStartPos, pos);
      if ((token.length() > 1) && (token.endsWith(")")))
      {
        token = token.substring(0, token.length() - 1);
        pos--;
      }

      final String lowerToken = toLowerCase(token);
      if (lowerToken.equals(")"))
      {
        // This indicates that we're at the end of the value.  There should not
        // be any more closing characters.
        if (pos < length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MRU_DECODE_CLOSE_NOT_AT_END.get(
                                       matchingRuleUseString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(matchingRuleUseString, pos, length);
          pos = readQDStrings(matchingRuleUseString, pos, length, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MRU_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleUseString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(matchingRuleUseString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(matchingRuleUseString, pos, length, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MRU_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleUseString, "DESC"));
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
                                  ERR_MRU_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleUseString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("applies"))
      {
        if (typeList.isEmpty())
        {
          pos = skipSpaces(matchingRuleUseString, pos, length);
          pos = readOIDs(matchingRuleUseString, pos, length, typeList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MRU_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleUseString, "APPLIES"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(matchingRuleUseString, pos, length);

        final ArrayList<String> valueList = new ArrayList<String>();
        pos = readQDStrings(matchingRuleUseString, pos, length, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MRU_DECODE_DUP_EXT.get(
                                       matchingRuleUseString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_MRU_DECODE_UNEXPECTED_TOKEN.get(
                                     matchingRuleUseString, token));
      }
    }

    description = descr;

    names = new String[nameList.size()];
    nameList.toArray(names);

    if (typeList.isEmpty())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MRU_DECODE_NO_APPLIES.get(
                                   matchingRuleUseString));
    }

    applicableTypes = new String[typeList.size()];
    typeList.toArray(applicableTypes);

    isObsolete = (obsolete != null);

    extensions = Collections.unmodifiableMap(exts);
  }



  /**
   * Creates a new matching rule use with the provided information.
   *
   * @param  oid              The OID for this matching rule use.  It must not
   *                          be {@code null}.
   * @param  name             The name for this matching rule use.  It may be
   *                          {@code null} or empty if the matching rule use
   *                          should only be referenced by OID.
   * @param  description      The description for this matching rule use.  It
   *                          may be {@code null} if there is no description.
   * @param  applicableTypes  The set of attribute types to which this matching
   *                          rule use applies.  It must not be empty or
   *                          {@code null}.
   * @param  extensions       The set of extensions for this matching rule use.
   *                          It may be {@code null} or empty if there should
   *                          not be any extensions.
   */
  public MatchingRuleUseDefinition(final String oid, final String name,
                                   final String description,
                                   final String[] applicableTypes,
                                   final Map<String,String[]> extensions)
  {
    this(oid, ((name == null) ? null : new String[] { name }), description,
         false, applicableTypes, extensions);
  }



  /**
   * Creates a new matching rule use with the provided information.
   *
   * @param  oid              The OID for this matching rule use.  It must not
   *                          be {@code null}.
   * @param  name             The name for this matching rule use.  It may be
   *                          {@code null} or empty if the matching rule use
   *                          should only be referenced by OID.
   * @param  description      The description for this matching rule use.  It
   *                          may be {@code null} if there is no description.
   * @param  applicableTypes  The set of attribute types to which this matching
   *                          rule use applies.  It must not be empty or
   *                          {@code null}.
   * @param  extensions       The set of extensions for this matching rule use.
   *                          It may be {@code null} or empty if there should
   *                          not be any extensions.
   */
  public MatchingRuleUseDefinition(final String oid, final String name,
                                   final String description,
                                   final Collection<String> applicableTypes,
                                   final Map<String,String[]> extensions)
  {
    this(oid, ((name == null) ? null : new String[] { name }), description,
         false, toArray(applicableTypes), extensions);
  }



  /**
   * Creates a new matching rule use with the provided information.
   *
   * @param  oid              The OID for this matching rule use.  It must not
   *                          be {@code null}.
   * @param  names            The set of names for this matching rule use.  It
   *                          may be {@code null} or empty if the matching rule
   *                          use should only be referenced by OID.
   * @param  description      The description for this matching rule use.  It
   *                          may be {@code null} if there is no description.
   * @param  isObsolete       Indicates whether this matching rule use is
   *                          declared obsolete.
   * @param  applicableTypes  The set of attribute types to which this matching
   *                          rule use applies.  It must not be empty or
   *                          {@code null}.
   * @param  extensions       The set of extensions for this matching rule use.
   *                          It may be {@code null} or empty if there should
   *                          not be any extensions.
   */
  public MatchingRuleUseDefinition(final String oid, final String[] names,
                                   final String description,
                                   final boolean isObsolete,
                                   final String[] applicableTypes,
                                   final Map<String,String[]> extensions)
  {
    ensureNotNull(oid, applicableTypes);
    ensureFalse(applicableTypes.length == 0);

    this.oid             = oid;
    this.description     = description;
    this.isObsolete      = isObsolete;
    this.applicableTypes = applicableTypes;

    if (names == null)
    {
      this.names = NO_STRINGS;
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
    matchingRuleUseString = buffer.toString();
  }



  /**
   * Constructs a string representation of this matching rule use definition in
   * the provided buffer.
   *
   * @param  buffer  The buffer in which to construct a string representation of
   *                 this matching rule use definition.
   */
  private void createDefinitionString(final StringBuilder buffer)
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

    if (applicableTypes.length == 1)
    {
      buffer.append(" APPLIES ");
      buffer.append(applicableTypes[0]);
    }
    else if (applicableTypes.length > 1)
    {
      buffer.append(" APPLIES (");
      for (int i=0; i < applicableTypes.length; i++)
      {
        if (i > 0)
        {
          buffer.append(" $");
        }

        buffer.append(' ');
        buffer.append(applicableTypes[i]);
      }
      buffer.append(" )");
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
   * Retrieves the OID for this matching rule use.
   *
   * @return  The OID for this matching rule use.
   */
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the set of names for this matching rule use.
   *
   * @return  The set of names for this matching rule use, or an empty array if
   *          it does not have any names.
   */
  public String[] getNames()
  {
    return names;
  }



  /**
   * Retrieves the primary name that can be used to reference this matching
   * rule use.  If one or more names are defined, then the first name will be
   * used.  Otherwise, the OID will be returned.
   *
   * @return  The primary name that can be used to reference this matching rule
   *          use.
   */
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
   * for this matching rule use.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string matches the OID or any of the
   *          names for this matching rule use, or {@code false} if not.
   */
  public boolean hasNameOrOID(final String s)
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
   * Retrieves the description for this matching rule use, if available.
   *
   * @return  The description for this matching rule use, or {@code null} if
   *          there is no description defined.
   */
  public String getDescription()
  {
    return description;
  }



  /**
   * Indicates whether this matching rule use is declared obsolete.
   *
   * @return  {@code true} if this matching rule use is declared obsolete, or
   *          {@code false} if it is not.
   */
  public boolean isObsolete()
  {
    return isObsolete;
  }



  /**
   * Retrieves the names or OIDs of the attribute types to which this matching
   * rule use applies.
   *
   * @return  The names or OIDs of the attribute types to which this matching
   *          rule use applies.
   */
  public String[] getApplicableAttributeTypes()
  {
    return applicableTypes;
  }



  /**
   * Retrieves the set of extensions for this matching rule use.  They will be
   * mapped from the extension name (which should start with "X-") to the set
   * of values for that extension.
   *
   * @return  The set of extensions for this matching rule use.
   */
  public Map<String,String[]> getExtensions()
  {
    return extensions;
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
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof MatchingRuleUseDefinition))
    {
      return false;
    }

    final MatchingRuleUseDefinition d = (MatchingRuleUseDefinition) o;
    return (oid.equals(d.oid) &&
         stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         stringsEqualIgnoreCaseOrderIndependent(applicableTypes,
              d.applicableTypes) &&
         bothNullOrEqualIgnoreCase(description, d.description) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions));
  }



  /**
   * Retrieves a string representation of this matching rule definition, in the
   * format described in RFC 4512 section 4.1.4.
   *
   * @return  A string representation of this matching rule use definition.
   */
  @Override()
  public String toString()
  {
    return matchingRuleUseString;
  }
}
