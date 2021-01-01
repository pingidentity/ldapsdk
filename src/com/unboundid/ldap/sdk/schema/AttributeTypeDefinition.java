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
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.schema.SchemaMessages.*;



/**
 * This class provides a data structure that describes an LDAP attribute type
 * schema element.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AttributeTypeDefinition
       extends SchemaElement
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6688185196734362719L;



  // The usage for this attribute type.
  @NotNull private final AttributeUsage usage;

  // Indicates whether this attribute type is declared collective.
  private final boolean isCollective;

  // Indicates whether this attribute type is declared no-user-modification.
  private final boolean isNoUserModification;

  // Indicates whether this attribute type is declared obsolete.
  private final boolean isObsolete;

  // Indicates whether this attribute type is declared single-valued.
  private final boolean isSingleValued;

  // The set of extensions for this attribute type.
  @NotNull private final Map<String,String[]> extensions;

  // The string representation of this attribute type.
  @NotNull private final String attributeTypeString;

  // The description for this attribute type.
  @Nullable private final String description;

  // The name/OID of the equality matching rule for this attribute type.
  @Nullable private final String equalityMatchingRule;

  // The OID for this attribute type.
  @NotNull private final String oid;

  // The name/OID of the ordering matching rule for this attribute type.
  @Nullable private final String orderingMatchingRule;

  // The name/OID of the substring matching rule for this attribute type.
  @Nullable private final String substringMatchingRule;

  // The name of the superior type for this attribute type.
  @Nullable private final String superiorType;

  // The OID of the syntax for this attribute type.
  @Nullable private final String syntaxOID;

  // The set of names for this attribute type.
  @NotNull private final String[] names;



  /**
   * Creates a new attribute type from the provided string representation.
   *
   * @param  s  The string representation of the attribute type to create, using
   *            the syntax described in RFC 4512 section 4.1.2.  It must not be
   *            {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as an
   *                         attribute type definition.
   */
  public AttributeTypeDefinition(@NotNull final String s)
         throws LDAPException
  {
    Validator.ensureNotNull(s);

    attributeTypeString = s.trim();

    // The first character must be an opening parenthesis.
    final int length = attributeTypeString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ATTRTYPE_DECODE_EMPTY.get());
    }
    else if (attributeTypeString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ATTRTYPE_DECODE_NO_OPENING_PAREN.get(
                                   attributeTypeString));
    }


    // Skip over any spaces until we reach the start of the OID, then read the
    // OID until we find the next space.
    int pos = skipSpaces(attributeTypeString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(attributeTypeString, pos, length, buffer);
    oid = buffer.toString();


    // Technically, attribute type elements are supposed to appear in a specific
    // order, but we'll be lenient and allow remaining elements to come in any
    // order.
    final ArrayList<String> nameList = new ArrayList<>(1);
    AttributeUsage attrUsage = null;
    Boolean collective = null;
    Boolean noUserMod = null;
    Boolean obsolete = null;
    Boolean singleValue = null;
    final Map<String,String[]> exts  =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));
    String descr = null;
    String eqRule = null;
    String ordRule = null;
    String subRule = null;
    String supType = null;
    String synOID = null;

    while (true)
    {
      // Skip over any spaces until we find the next element.
      pos = skipSpaces(attributeTypeString, pos, length);

      // Read until we find the next space or the end of the string.  Use that
      // token to figure out what to do next.
      final int tokenStartPos = pos;
      while ((pos < length) && (attributeTypeString.charAt(pos) != ' '))
      {
        pos++;
      }

      String token = attributeTypeString.substring(tokenStartPos, pos);

      // It's possible that the token could be smashed right up against the
      // closing parenthesis.  If that's the case, then extract just the token
      // and handle the closing parenthesis the next time through.
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
                                  ERR_ATTRTYPE_DECODE_CLOSE_NOT_AT_END.get(
                                       attributeTypeString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(attributeTypeString, pos, length);
          pos = readQDStrings(attributeTypeString, pos, length, token,
               nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(attributeTypeString, pos, length, token, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "DESC"));
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
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("sup"))
      {
        if (supType == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          supType = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "SUP"));
        }
      }
      else if (lowerToken.equals("equality"))
      {
        if (eqRule == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          eqRule = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "EQUALITY"));
        }
      }
      else if (lowerToken.equals("ordering"))
      {
        if (ordRule == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          ordRule = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "ORDERING"));
        }
      }
      else if (lowerToken.equals("substr"))
      {
        if (subRule == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          subRule = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "SUBSTR"));
        }
      }
      else if (lowerToken.equals("syntax"))
      {
        if (synOID == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          synOID = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "SYNTAX"));
        }
      }
      else if (lowerToken.equals("single-value"))
      {
        if (singleValue == null)
        {
          singleValue = true;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "SINGLE-VALUE"));
        }
      }
      else if (lowerToken.equals("collective"))
      {
        if (collective == null)
        {
          collective = true;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "COLLECTIVE"));
        }
      }
      else if (lowerToken.equals("no-user-modification"))
      {
        if (noUserMod == null)
        {
          noUserMod = true;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString,
                                       "NO-USER-MODIFICATION"));
        }
      }
      else if (lowerToken.equals("usage"))
      {
        if (attrUsage == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);

          final String usageStr = StaticUtils.toLowerCase(buffer.toString());
          if (usageStr.equals("userapplications"))
          {
            attrUsage = AttributeUsage.USER_APPLICATIONS;
          }
          else if (usageStr.equals("directoryoperation"))
          {
            attrUsage = AttributeUsage.DIRECTORY_OPERATION;
          }
          else if (usageStr.equals("distributedoperation"))
          {
            attrUsage = AttributeUsage.DISTRIBUTED_OPERATION;
          }
          else if (usageStr.equals("dsaoperation"))
          {
            attrUsage = AttributeUsage.DSA_OPERATION;
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_ATTRTYPE_DECODE_INVALID_USAGE.get(
                                         attributeTypeString, usageStr));
          }
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "USAGE"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(attributeTypeString, pos, length);

        final ArrayList<String> valueList = new ArrayList<>(5);
        pos = readQDStrings(attributeTypeString, pos, length, token, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_DUP_EXT.get(
                                       attributeTypeString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_ATTRTYPE_DECODE_UNEXPECTED_TOKEN.get(
                                     attributeTypeString, token));
      }
    }

    description           = descr;
    equalityMatchingRule  = eqRule;
    orderingMatchingRule  = ordRule;
    substringMatchingRule = subRule;
    superiorType          = supType;
    syntaxOID             = synOID;

    names = new String[nameList.size()];
    nameList.toArray(names);

    isObsolete           = (obsolete != null);
    isSingleValued       = (singleValue != null);
    isCollective         = (collective != null);
    isNoUserModification = (noUserMod != null);

    if (attrUsage == null)
    {
      usage = AttributeUsage.USER_APPLICATIONS;
    }
    else
    {
      usage = attrUsage;
    }

    extensions = Collections.unmodifiableMap(exts);
  }



  /**
   * Creates a new attribute type with the provided information.
   *
   * @param  oid                    The OID for this attribute type.  It must
   *                                not be {@code null}.
   * @param  name                   The name for this attribute type.  It may be
   *                                {@code null} if the attribute type should
   *                                only be referenced by OID.
   * @param  description            The description for this attribute type.  It
   *                                may be {@code null} if there is no
   *                                description.
   * @param  equalityMatchingRule   The name or OID of the equality matching
   *                                rule for this attribute type.  It may be
   *                                {@code null} if a default rule is to be
   *                                inherited.
   * @param  orderingMatchingRule   The name or OID of the ordering matching
   *                                rule for this attribute type.  It may be
   *                                {@code null} if a default rule is to be
   *                                inherited.
   * @param  substringMatchingRule  The name or OID of the substring matching
   *                                rule for this attribute type.  It may be
   *                                {@code null} if a default rule is to be
   *                                inherited.
   * @param  syntaxOID              The syntax OID for this attribute type.  It
   *                                may be {@code null} if a default syntax is
   *                                to be inherited.
   * @param  isSingleValued         Indicates whether attributes of this type
   *                                are only allowed to have a single value.
   * @param  extensions             The set of extensions for this attribute
   *                                type.  It may be {@code null} or empty if
   *                                there should not be any extensions.
   */
  public AttributeTypeDefinition(@NotNull final String oid,
               @Nullable final String name,
               @Nullable final String description,
               @Nullable final String equalityMatchingRule,
               @Nullable final String orderingMatchingRule,
               @Nullable final String substringMatchingRule,
               @Nullable final String syntaxOID,
               final boolean isSingleValued,
               @Nullable final Map<String,String[]> extensions)
  {
    this(oid, ((name == null) ? null : new String[] { name }), description,
         false, null, equalityMatchingRule, orderingMatchingRule,
         substringMatchingRule, syntaxOID, isSingleValued, false, false,
         AttributeUsage.USER_APPLICATIONS, extensions);
  }



  /**
   * Creates a new attribute type with the provided information.
   *
   * @param  oid                    The OID for this attribute type.  It must
   *                                not be {@code null}.
   * @param  names                  The set of names for this attribute type.
   *                                It may be {@code null} or empty if the
   *                                attribute type should only be referenced by
   *                                OID.
   * @param  description            The description for this attribute type.  It
   *                                may be {@code null} if there is no
   *                                description.
   * @param  isObsolete             Indicates whether this attribute type is
   *                                declared obsolete.
   * @param  superiorType           The name or OID of the superior attribute
   *                                type.  It may be {@code null} if there is no
   *                                superior type.
   * @param  equalityMatchingRule   The name or OID of the equality matching
   *                                rule for this attribute type.  It may be
   *                                {@code null} if a default rule is to be
   *                                inherited.
   * @param  orderingMatchingRule   The name or OID of the ordering matching
   *                                rule for this attribute type.  It may be
   *                                {@code null} if a default rule is to be
   *                                inherited.
   * @param  substringMatchingRule  The name or OID of the substring matching
   *                                rule for this attribute type.  It may be
   *                                {@code null} if a default rule is to be
   *                                inherited.
   * @param  syntaxOID              The syntax OID for this attribute type.  It
   *                                may be {@code null} if a default syntax is
   *                                to be inherited.
   * @param  isSingleValued         Indicates whether attributes of this type
   *                                are only allowed to have a single value.
   * @param  isCollective           Indicates whether this attribute type should
   *                                be considered collective.
   * @param  isNoUserModification   Indicates whether clients should be allowed
   *                                to modify attributes of this type.
   * @param  usage                  The attribute usage for this attribute type.
   *                                It may be {@code null} if the default usage
   *                                of userApplications is to be used.
   * @param  extensions             The set of extensions for this attribute
   *                                type.  It may be {@code null} or empty if
   *                                there should not be any extensions.
   */
  public AttributeTypeDefinition(@NotNull final String oid,
              @Nullable final String[] names,
              @Nullable final String description,
              final boolean isObsolete,
              @Nullable final String superiorType,
              @Nullable final String equalityMatchingRule,
              @Nullable final String orderingMatchingRule,
              @Nullable final String substringMatchingRule,
              @Nullable final String syntaxOID,
              final boolean isSingleValued,
              final boolean isCollective,
              final boolean isNoUserModification,
              @Nullable final AttributeUsage usage,
              @Nullable final Map<String,String[]> extensions)
  {
    Validator.ensureNotNull(oid);

    this.oid                   = oid;
    this.description           = description;
    this.isObsolete            = isObsolete;
    this.superiorType          = superiorType;
    this.equalityMatchingRule  = equalityMatchingRule;
    this.orderingMatchingRule  = orderingMatchingRule;
    this.substringMatchingRule = substringMatchingRule;
    this.syntaxOID             = syntaxOID;
    this.isSingleValued        = isSingleValued;
    this.isCollective          = isCollective;
    this.isNoUserModification  = isNoUserModification;

    if (names == null)
    {
      this.names = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

    if (usage == null)
    {
      this.usage = AttributeUsage.USER_APPLICATIONS;
    }
    else
    {
      this.usage = usage;
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
    attributeTypeString = buffer.toString();
  }



  /**
   * Constructs a string representation of this attribute type definition in the
   * provided buffer.
   *
   * @param  buffer  The buffer in which to construct a string representation of
   *                 this attribute type definition.
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

    if (superiorType != null)
    {
      buffer.append(" SUP ");
      buffer.append(superiorType);
    }

    if (equalityMatchingRule != null)
    {
      buffer.append(" EQUALITY ");
      buffer.append(equalityMatchingRule);
    }

    if (orderingMatchingRule != null)
    {
      buffer.append(" ORDERING ");
      buffer.append(orderingMatchingRule);
    }

    if (substringMatchingRule != null)
    {
      buffer.append(" SUBSTR ");
      buffer.append(substringMatchingRule);
    }

    if (syntaxOID != null)
    {
      buffer.append(" SYNTAX ");
      buffer.append(syntaxOID);
    }

    if (isSingleValued)
    {
      buffer.append(" SINGLE-VALUE");
    }

    if (isCollective)
    {
      buffer.append(" COLLECTIVE");
    }

    if (isNoUserModification)
    {
      buffer.append(" NO-USER-MODIFICATION");
    }

    buffer.append(" USAGE ");
    buffer.append(usage.getName());

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
   * Retrieves the OID for this attribute type.
   *
   * @return  The OID for this attribute type.
   */
  @NotNull()
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the set of names for this attribute type.
   *
   * @return  The set of names for this attribute type, or an empty array if it
   *          does not have any names.
   */
  @NotNull()
  public String[] getNames()
  {
    return names;
  }



  /**
   * Retrieves the primary name that can be used to reference this attribute
   * type.  If one or more names are defined, then the first name will be used.
   * Otherwise, the OID will be returned.
   *
   * @return  The primary name that can be used to reference this attribute
   *          type.
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
   * for this attribute type.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string matches the OID or any of the
   *          names for this attribute type, or {@code false} if not.
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
   * Retrieves the description for this attribute type, if available.
   *
   * @return  The description for this attribute type, or {@code null} if there
   *          is no description defined.
   */
  @Nullable()
  public String getDescription()
  {
    return description;
  }



  /**
   * Indicates whether this attribute type is declared obsolete.
   *
   * @return  {@code true} if this attribute type is declared obsolete, or
   *          {@code false} if it is not.
   */
  public boolean isObsolete()
  {
    return isObsolete;
  }



  /**
   * Retrieves the name or OID of the superior type for this attribute type, if
   * available.
   *
   * @return  The name or OID of the superior type for this attribute type, or
   *          {@code null} if no superior type is defined.
   */
  @Nullable()
  public String getSuperiorType()
  {
    return superiorType;
  }



  /**
   * Retrieves the superior attribute type definition for this attribute type,
   * if available.
   *
   * @param  schema  The schema to use to get the superior attribute type.
   *
   * @return  The superior attribute type definition for this attribute type, or
   *          {@code null} if no superior type is defined, or if the superior
   *          type is not included in the provided schema.
   */
  @Nullable()
  public AttributeTypeDefinition getSuperiorType(@NotNull final Schema schema)
  {
    if (superiorType != null)
    {
      return schema.getAttributeType(superiorType);
    }

    return null;
  }



  /**
   * Retrieves the name or OID of the equality matching rule for this attribute
   * type, if available.
   *
   * @return  The name or OID of the equality matching rule for this attribute
   *          type, or {@code null} if no equality matching rule is defined or a
   *          default rule will be inherited.
   */
  @Nullable()
  public String getEqualityMatchingRule()
  {
    return equalityMatchingRule;
  }



  /**
   * Retrieves the name or OID of the equality matching rule for this attribute
   * type, examining superior attribute types if necessary.
   *
   * @param  schema  The schema to use to get the superior attribute type.
   *
   * @return  The name or OID of the equality matching rule for this attribute
   *          type, or {@code null} if no equality matching rule is defined.
   */
  @Nullable()
  public String getEqualityMatchingRule(@NotNull final Schema schema)
  {
    if (equalityMatchingRule == null)
    {
      final AttributeTypeDefinition sup = getSuperiorType(schema);
      if (sup != null)
      {
        return sup.getEqualityMatchingRule(schema);
      }
    }

    return equalityMatchingRule;
  }



  /**
   * Retrieves the name or OID of the ordering matching rule for this attribute
   * type, if available.
   *
   * @return  The name or OID of the ordering matching rule for this attribute
   *          type, or {@code null} if no ordering matching rule is defined or a
   *          default rule will be inherited.
   */
  @Nullable()
  public String getOrderingMatchingRule()
  {
    return orderingMatchingRule;
  }



  /**
   * Retrieves the name or OID of the ordering matching rule for this attribute
   * type, examining superior attribute types if necessary.
   *
   * @param  schema  The schema to use to get the superior attribute type.
   *
   * @return  The name or OID of the ordering matching rule for this attribute
   *          type, or {@code null} if no ordering matching rule is defined.
   */
  @Nullable()
  public String getOrderingMatchingRule(@NotNull final Schema schema)
  {
    if (orderingMatchingRule == null)
    {
      final AttributeTypeDefinition sup = getSuperiorType(schema);
      if (sup != null)
      {
        return sup.getOrderingMatchingRule(schema);
      }
    }

    return orderingMatchingRule;
  }



  /**
   * Retrieves the name or OID of the substring matching rule for this attribute
   * type, if available.
   *
   * @return  The name or OID of the substring matching rule for this attribute
   *          type, or {@code null} if no substring matching rule is defined or
   *          a default rule will be inherited.
   */
  @Nullable()
  public String getSubstringMatchingRule()
  {
    return substringMatchingRule;
  }



  /**
   * Retrieves the name or OID of the substring matching rule for this attribute
   * type, examining superior attribute types if necessary.
   *
   * @param  schema  The schema to use to get the superior attribute type.
   *
   * @return  The name or OID of the substring matching rule for this attribute
   *          type, or {@code null} if no substring matching rule is defined.
   */
  @Nullable()
  public String getSubstringMatchingRule(@NotNull final Schema schema)
  {
    if (substringMatchingRule == null)
    {
      final AttributeTypeDefinition sup = getSuperiorType(schema);
      if (sup != null)
      {
        return sup.getSubstringMatchingRule(schema);
      }
    }

    return substringMatchingRule;
  }



  /**
   * Retrieves the OID of the syntax for this attribute type, if available.  It
   * may optionally include a minimum upper bound in curly braces.
   *
   * @return  The OID of the syntax for this attribute type, or {@code null} if
   *          the syntax will be inherited.
   */
  @Nullable()
  public String getSyntaxOID()
  {
    return syntaxOID;
  }



  /**
   * Retrieves the OID of the syntax for this attribute type, examining superior
   * types if necessary.  It may optionally include a minimum upper bound in
   * curly braces.
   *
   * @param  schema  The schema to use to get the superior attribute type.
   *
   * @return  The OID of the syntax for this attribute type, or {@code null} if
   *          no syntax is defined.
   */
  @Nullable()
  public String getSyntaxOID(@NotNull final Schema schema)
  {
    if (syntaxOID == null)
    {
      final AttributeTypeDefinition sup = getSuperiorType(schema);
      if (sup != null)
      {
        return sup.getSyntaxOID(schema);
      }
    }

    return syntaxOID;
  }



  /**
   * Retrieves the OID of the syntax for this attribute type, if available.  If
   * the attribute type definition includes a minimum upper bound in curly
   * braces, it will be removed from the value that is returned.
   *
   * @return  The OID of the syntax for this attribute type, or {@code null} if
   *          the syntax will be inherited.
   */
  @Nullable()
  public String getBaseSyntaxOID()
  {
    return getBaseSyntaxOID(syntaxOID);
  }



  /**
   * Retrieves the base OID of the syntax for this attribute type, examining
   * superior types if necessary.    If the attribute type definition includes a
   * minimum upper bound in curly braces, it will be removed from the value that
   * is returned.
   *
   * @param  schema  The schema to use to get the superior attribute type, if
   *                 necessary.
   *
   * @return  The OID of the syntax for this attribute type, or {@code null} if
   *          no syntax is defined.
   */
  @Nullable()
  public String getBaseSyntaxOID(@NotNull final Schema schema)
  {
    return getBaseSyntaxOID(getSyntaxOID(schema));
  }



  /**
   * Retrieves the base OID of the syntax for this attribute type, examining
   * superior types if necessary.    If the attribute type definition includes a
   * minimum upper bound in curly braces, it will be removed from the value that
   * is returned.
   *
   * @param  syntaxOID  The syntax OID (optionally including the minimum upper
   *                    bound element) to examine.
   *
   * @return  The OID of the syntax for this attribute type, or {@code null} if
   *          no syntax is defined.
   */
  @Nullable()
  public static String getBaseSyntaxOID(@Nullable final String syntaxOID)
  {
    if (syntaxOID == null)
    {
      return null;
    }

    final int curlyPos = syntaxOID.indexOf('{');
    if (curlyPos > 0)
    {
      return syntaxOID.substring(0, curlyPos);
    }
    else
    {
      return syntaxOID;
    }
  }



  /**
   * Retrieves the value of the minimum upper bound element of the syntax
   * definition for this attribute type, if defined.  If a minimum upper bound
   * is present (as signified by an integer value in curly braces immediately
   * following the syntax OID without any space between them), then it should
   * serve as an indication to the directory server that it should be prepared
   * to handle values with at least that number of (possibly multi-byte)
   * characters.
   *
   * @return  The value of the minimum upper bound element of the syntax
   *          definition for this attribute type, or -1 if no syntax is defined
   *          defined or if it does not have a valid minimum upper bound.
   */
  public int getSyntaxMinimumUpperBound()
  {
    return getSyntaxMinimumUpperBound(syntaxOID);
  }



  /**
   * Retrieves the value of the minimum upper bound element of the syntax
   * definition for this attribute type, if defined.  If a minimum upper bound
   * is present (as signified by an integer value in curly braces immediately
   * following the syntax OID without any space between them), then it should
   * serve as an indication to the directory server that it should be prepared
   * to handle values with at least that number of (possibly multi-byte)
   * characters.
   *
   * @param  schema  The schema to use to get the superior attribute type, if
   *                 necessary.
   *
   * @return  The value of the minimum upper bound element of the syntax
   *          definition for this attribute type, or -1 if no syntax is defined
   *          defined or if it does not have a valid minimum upper bound.
   */
  public int getSyntaxMinimumUpperBound(@NotNull final Schema schema)
  {
    return getSyntaxMinimumUpperBound(getSyntaxOID(schema));
  }



  /**
   * Retrieves the value of the minimum upper bound element of the syntax
   * definition for this attribute type, if defined.  If a minimum upper bound
   * is present (as signified by an integer value in curly braces immediately
   * following the syntax OID without any space between them), then it should
   * serve as an indication to the directory server that it should be prepared
   * to handle values with at least that number of (possibly multi-byte)
   * characters.
   *
   * @param  syntaxOID  The syntax OID (optionally including the minimum upper
   *                    bound element) to examine.
   *
   * @return  The value of the minimum upper bound element of the provided
   *          syntax OID, or -1 if the provided syntax OID is {@code null} or
   *          does not have a valid minimum upper bound.
   */
  public static int getSyntaxMinimumUpperBound(@Nullable final String syntaxOID)
  {
    if (syntaxOID == null)
    {
      return -1;
    }

    final int curlyPos = syntaxOID.indexOf('{');
    if ((curlyPos > 0) && syntaxOID.endsWith("}"))
    {
      try
      {
        return Integer.parseInt(syntaxOID.substring(curlyPos+1,
             syntaxOID.length()-1));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        return -1;
      }
    }
    else
    {
      return -1;
    }
  }



  /**
   * Indicates whether this attribute type is declared single-valued, and
   * therefore attributes of this type will only be allowed to have at most one
   * value.
   *
   * @return  {@code true} if this attribute type is declared single-valued, or
   *          {@code false} if not.
   */
  public boolean isSingleValued()
  {
    return isSingleValued;
  }



  /**
   * Indicates whether this attribute type is declared collective, and therefore
   * values may be dynamically generated as described in RFC 3671.
   *
   * @return  {@code true} if this attribute type is declared collective, or
   *          {@code false} if not.
   */
  public boolean isCollective()
  {
    return isCollective;
  }



  /**
   * Indicates whether this attribute type is declared no-user-modification,
   * and therefore attributes of this type will not be allowed to be altered
   * by clients.
   *
   * @return  {@code true} if this attribute type is declared
   *          no-user-modification, or {@code false} if not.
   */
  public boolean isNoUserModification()
  {
    return isNoUserModification;
  }



  /**
   * Retrieves the attribute usage for this attribute type.
   *
   * @return  The attribute usage for this attribute type.
   */
  @NotNull()
  public AttributeUsage getUsage()
  {
    return usage;
  }



  /**
   * Indicates whether this attribute type has an operational attribute usage.
   *
   * @return  {@code true} if this attribute type has an operational attribute
   *          usage, or {@code false} if not.
   */
  public boolean isOperational()
  {
    return usage.isOperational();
  }



  /**
   * Retrieves the set of extensions for this attribute type.  They will be
   * mapped from the extension name (which should start with "X-") to the set of
   * values for that extension.
   *
   * @return  The set of extensions for this attribute type.
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
    return SchemaElementType.ATTRIBUTE_TYPE;
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

    if (! (o instanceof AttributeTypeDefinition))
    {
      return false;
    }

    final AttributeTypeDefinition d = (AttributeTypeDefinition) o;
    return(oid.equals(d.oid) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         StaticUtils.bothNullOrEqual(usage, d.usage) &&
         StaticUtils.bothNullOrEqualIgnoreCase(description, d.description) &&
         StaticUtils.bothNullOrEqualIgnoreCase(equalityMatchingRule,
              d.equalityMatchingRule) &&
         StaticUtils.bothNullOrEqualIgnoreCase(orderingMatchingRule,
              d.orderingMatchingRule) &&
         StaticUtils.bothNullOrEqualIgnoreCase(substringMatchingRule,
              d.substringMatchingRule) &&
         StaticUtils.bothNullOrEqualIgnoreCase(superiorType, d.superiorType) &&
         StaticUtils.bothNullOrEqualIgnoreCase(syntaxOID, d.syntaxOID) &&
         (isCollective == d.isCollective) &&
         (isNoUserModification == d.isNoUserModification) &&
         (isObsolete == d.isObsolete) &&
         (isSingleValued == d.isSingleValued) &&
         extensionsEqual(extensions, d.extensions));
  }



  /**
   * Retrieves a string representation of this attribute type definition, in the
   * format described in RFC 4512 section 4.1.2.
   *
   * @return  A string representation of this attribute type definition.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return attributeTypeString;
  }
}
