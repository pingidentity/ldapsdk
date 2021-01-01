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
import java.util.Collection;
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
 * This class provides a data structure that describes an LDAP DIT content rule
 * schema element.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DITContentRuleDefinition
       extends SchemaElement
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3224440505307817586L;



  // Indicates whether this DIT content rule is declared obsolete.
  private final boolean isObsolete;

  // The set of extensions for this DIT content rule.
  @NotNull private final Map<String,String[]> extensions;

  // The description for this DIT content rule.
  @Nullable private final String description;

  // The string representation of this DIT content rule.
  @NotNull private final String ditContentRuleString;

  // The OID of the structural object class with which this DIT content rule is
  // associated.
  @NotNull private final String oid;

  // The names/OIDs of the allowed auxiliary classes.
  @NotNull private final String[] auxiliaryClasses;

  // The set of names for this DIT content rule.
  @NotNull private final String[] names;

  // The names/OIDs of the optional attributes.
  @NotNull private final String[] optionalAttributes;

  // The names/OIDs of the prohibited attributes.
  @NotNull private final String[] prohibitedAttributes;

  // The names/OIDs of the required attributes.
  @NotNull private final String[] requiredAttributes;



  /**
   * Creates a new DIT content rule from the provided string representation.
   *
   * @param  s  The string representation of the DIT content rule to create,
   *            using the syntax described in RFC 4512 section 4.1.6.  It must
   *            not be {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as a DIT
   *                         content rule definition.
   */
  public DITContentRuleDefinition(@NotNull final String s)
         throws LDAPException
  {
    Validator.ensureNotNull(s);

    ditContentRuleString = s.trim();

    // The first character must be an opening parenthesis.
    final int length = ditContentRuleString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DCR_DECODE_EMPTY.get());
    }
    else if (ditContentRuleString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DCR_DECODE_NO_OPENING_PAREN.get(
                                   ditContentRuleString));
    }


    // Skip over any spaces until we reach the start of the OID, then read the
    // OID until we find the next space.
    int pos = skipSpaces(ditContentRuleString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(ditContentRuleString, pos, length, buffer);
    oid = buffer.toString();


    // Technically, DIT content elements are supposed to appear in a specific
    // order, but we'll be lenient and allow remaining elements to come in any
    // order.
    final ArrayList<String> nameList = new ArrayList<>(5);
    final ArrayList<String> reqAttrs = new ArrayList<>(10);
    final ArrayList<String> optAttrs = new ArrayList<>(10);
    final ArrayList<String> notAttrs = new ArrayList<>(10);
    final ArrayList<String> auxOCs = new ArrayList<>(10);
    final Map<String,String[]> exts =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));
    Boolean obsolete = null;
    String descr = null;

    while (true)
    {
      // Skip over any spaces until we find the next element.
      pos = skipSpaces(ditContentRuleString, pos, length);

      // Read until we find the next space or the end of the string.  Use that
      // token to figure out what to do next.
      final int tokenStartPos = pos;
      while ((pos < length) && (ditContentRuleString.charAt(pos) != ' '))
      {
        pos++;
      }

      // It's possible that the token could be smashed right up against the
      // closing parenthesis.  If that's the case, then extract just the token
      // and handle the closing parenthesis the next time through.
      String token = ditContentRuleString.substring(tokenStartPos, pos);
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
                                  ERR_DCR_DECODE_CLOSE_NOT_AT_END.get(
                                       ditContentRuleString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readQDStrings(ditContentRuleString, pos, length, token,
               nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(ditContentRuleString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(ditContentRuleString, pos, length, token, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "DESC"));
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
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("aux"))
      {
        if (auxOCs.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readOIDs(ditContentRuleString, pos, length, token, auxOCs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "AUX"));
        }
      }
      else if (lowerToken.equals("must"))
      {
        if (reqAttrs.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readOIDs(ditContentRuleString, pos, length, token, reqAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "MUST"));
        }
      }
      else if (lowerToken.equals("may"))
      {
        if (optAttrs.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readOIDs(ditContentRuleString, pos, length, token, optAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "MAY"));
        }
      }
      else if (lowerToken.equals("not"))
      {
        if (notAttrs.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readOIDs(ditContentRuleString, pos, length, token, notAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "NOT"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(ditContentRuleString, pos, length);

        final ArrayList<String> valueList = new ArrayList<>(5);
        pos = readQDStrings(ditContentRuleString, pos, length, token,
             valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_DUP_EXT.get(
                                       ditContentRuleString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_DCR_DECODE_DUP_EXT.get(
                                     ditContentRuleString, token));
      }
    }

    description = descr;

    names = new String[nameList.size()];
    nameList.toArray(names);

    auxiliaryClasses = new String[auxOCs.size()];
    auxOCs.toArray(auxiliaryClasses);

    requiredAttributes = new String[reqAttrs.size()];
    reqAttrs.toArray(requiredAttributes);

    optionalAttributes = new String[optAttrs.size()];
    optAttrs.toArray(optionalAttributes);

    prohibitedAttributes = new String[notAttrs.size()];
    notAttrs.toArray(prohibitedAttributes);

    isObsolete = (obsolete != null);

    extensions = Collections.unmodifiableMap(exts);
  }



  /**
   * Creates a new DIT content rule with the provided information.
   *
   * @param  oid                   The OID for the structural object class with
   *                               which this DIT content rule is associated.
   *                               It must not be {@code null}.
   * @param  name                  The name for this DIT content rule.  It may
   *                               be {@code null} if the DIT content rule
   *                               should only be referenced by OID.
   * @param  description           The description for this DIT content rule.
   *                               It may be {@code null} if there is no
   *                               description.
   * @param  auxiliaryClasses      The names/OIDs of the auxiliary object
   *                               classes that may be present in entries
   *                               containing this DIT content rule.
   * @param  requiredAttributes    The names/OIDs of the attributes which must
   *                               be present in entries containing this DIT
   *                               content rule.
   * @param  optionalAttributes    The names/OIDs of the attributes which may be
   *                               present in entries containing this DIT
   *                               content rule.
   * @param  prohibitedAttributes  The names/OIDs of the attributes which may
   *                               not be present in entries containing this DIT
   *                               content rule.
   * @param  extensions            The set of extensions for this DIT content
   *                               rule.  It may be {@code null} or empty if
   *                               there should not be any extensions.
   */
  public DITContentRuleDefinition(@NotNull final String oid,
              @Nullable final String name,
              @Nullable final String description,
              @Nullable final String[] auxiliaryClasses,
              @Nullable final String[] requiredAttributes,
              @Nullable final String[] optionalAttributes,
              @Nullable final String[] prohibitedAttributes,
              @Nullable final Map<String,String[]> extensions)
  {
    this(oid, ((name == null) ? null : new String[] { name }), description,
         false, auxiliaryClasses, requiredAttributes, optionalAttributes,
         prohibitedAttributes, extensions);
  }



  /**
   * Creates a new DIT content rule with the provided information.
   *
   * @param  oid                   The OID for the structural object class with
   *                               which this DIT content rule is associated.
   *                               It must not be {@code null}.
   * @param  name                  The name for this DIT content rule.  It may
   *                               be {@code null} if the DIT content rule
   *                               should only be referenced by OID.
   * @param  description           The description for this DIT content rule.
   *                               It may be {@code null} if there is no
   *                               description.
   * @param  auxiliaryClasses      The names/OIDs of the auxiliary object
   *                               classes that may be present in entries
   *                               containing this DIT content rule.
   * @param  requiredAttributes    The names/OIDs of the attributes which must
   *                               be present in entries containing this DIT
   *                               content rule.
   * @param  optionalAttributes    The names/OIDs of the attributes which may be
   *                               present in entries containing this DIT
   *                               content rule.
   * @param  prohibitedAttributes  The names/OIDs of the attributes which may
   *                               not be present in entries containing this DIT
   *                               content rule.
   * @param  extensions            The set of extensions for this DIT content
   *                               rule.  It may be {@code null} or empty if
   *                               there should not be any extensions.
   */
  public DITContentRuleDefinition(@NotNull final String oid,
              @Nullable final String name,
              @Nullable final String description,
              @Nullable final Collection<String> auxiliaryClasses,
              @Nullable final Collection<String> requiredAttributes,
              @Nullable final Collection<String> optionalAttributes,
              @Nullable final Collection<String> prohibitedAttributes,
              @Nullable final Map<String,String[]> extensions)
  {
    this(oid, ((name == null) ? null : new String[] { name }), description,
         false, toArray(auxiliaryClasses), toArray(requiredAttributes),
         toArray(optionalAttributes), toArray(prohibitedAttributes),
         extensions);
  }



  /**
   * Creates a new DIT content rule with the provided information.
   *
   * @param  oid                   The OID for the structural object class with
   *                               which this DIT content rule is associated.
   *                               It must not be {@code null}.
   * @param  names                 The set of names for this DIT content rule.
   *                               It may be {@code null} or empty if the DIT
   *                               content rule should only be referenced by
   *                               OID.
   * @param  description           The description for this DIT content rule.
   *                               It may be {@code null} if there is no
   *                               description.
   * @param  isObsolete            Indicates whether this DIT content rule is
   *                               declared obsolete.
   * @param  auxiliaryClasses      The names/OIDs of the auxiliary object
   *                               classes that may be present in entries
   *                               containing this DIT content rule.
   * @param  requiredAttributes    The names/OIDs of the attributes which must
   *                               be present in entries containing this DIT
   *                               content rule.
   * @param  optionalAttributes    The names/OIDs of the attributes which may be
   *                               present in entries containing this DIT
   *                               content rule.
   * @param  prohibitedAttributes  The names/OIDs of the attributes which may
   *                               not be present in entries containing this DIT
   *                               content rule.
   * @param  extensions            The set of extensions for this DIT content
   *                               rule.  It may be {@code null} or empty if
   *                               there should not be any extensions.
   */
  public DITContentRuleDefinition(@NotNull final String oid,
              @Nullable final String[] names,
              @Nullable final String description,
              final boolean isObsolete,
              @Nullable final String[] auxiliaryClasses,
              @Nullable final String[] requiredAttributes,
              @Nullable final String[] optionalAttributes,
              @Nullable final String[] prohibitedAttributes,
              @Nullable final Map<String,String[]> extensions)
  {
    Validator.ensureNotNull(oid);

    this.oid             = oid;
    this.isObsolete      = isObsolete;
    this.description     = description;

    if (names == null)
    {
      this.names = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

    if (auxiliaryClasses == null)
    {
      this.auxiliaryClasses = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.auxiliaryClasses  = auxiliaryClasses;
    }

    if (requiredAttributes == null)
    {
      this.requiredAttributes = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.requiredAttributes = requiredAttributes;
    }

    if (optionalAttributes == null)
    {
      this.optionalAttributes = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.optionalAttributes = optionalAttributes;
    }

    if (prohibitedAttributes == null)
    {
      this.prohibitedAttributes = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.prohibitedAttributes = prohibitedAttributes;
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
    ditContentRuleString = buffer.toString();
  }



  /**
   * Constructs a string representation of this DIT content rule definition in
   * the provided buffer.
   *
   * @param  buffer  The buffer in which to construct a string representation of
   *                 this DIT content rule definition.
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

    if (auxiliaryClasses.length == 1)
    {
      buffer.append(" AUX ");
      buffer.append(auxiliaryClasses[0]);
    }
    else if (auxiliaryClasses.length > 1)
    {
      buffer.append(" AUX (");
      for (int i=0; i < auxiliaryClasses.length; i++)
      {
        if (i >0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(auxiliaryClasses[i]);
      }
      buffer.append(" )");
    }

    if (requiredAttributes.length == 1)
    {
      buffer.append(" MUST ");
      buffer.append(requiredAttributes[0]);
    }
    else if (requiredAttributes.length > 1)
    {
      buffer.append(" MUST (");
      for (int i=0; i < requiredAttributes.length; i++)
      {
        if (i >0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(requiredAttributes[i]);
      }
      buffer.append(" )");
    }

    if (optionalAttributes.length == 1)
    {
      buffer.append(" MAY ");
      buffer.append(optionalAttributes[0]);
    }
    else if (optionalAttributes.length > 1)
    {
      buffer.append(" MAY (");
      for (int i=0; i < optionalAttributes.length; i++)
      {
        if (i > 0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(optionalAttributes[i]);
      }
      buffer.append(" )");
    }

    if (prohibitedAttributes.length == 1)
    {
      buffer.append(" NOT ");
      buffer.append(prohibitedAttributes[0]);
    }
    else if (prohibitedAttributes.length > 1)
    {
      buffer.append(" NOT (");
      for (int i=0; i < prohibitedAttributes.length; i++)
      {
        if (i > 0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(prohibitedAttributes[i]);
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
   * Retrieves the OID for the structural object class associated with this
   * DIT content rule.
   *
   * @return  The OID for the structural object class associated with this DIT
   *          content rule.
   */
  @NotNull()
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the set of names for this DIT content rule.
   *
   * @return  The set of names for this DIT content rule, or an empty array if
   *          it does not have any names.
   */
  @NotNull()
  public String[] getNames()
  {
    return names;
  }



  /**
   * Retrieves the primary name that can be used to reference this DIT content
   * rule.  If one or more names are defined, then the first name will be used.
   * Otherwise, the structural object class OID will be returned.
   *
   * @return  The primary name that can be used to reference this DIT content
   *          rule.
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
   * for this DIT content rule.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string matches the OID or any of the
   *          names for this DIT content rule, or {@code false} if not.
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
   * Retrieves the description for this DIT content rule, if available.
   *
   * @return  The description for this DIT content rule, or {@code null} if
   *          there is no description defined.
   */
  @Nullable()
  public String getDescription()
  {
    return description;
  }



  /**
   * Indicates whether this DIT content rule is declared obsolete.
   *
   * @return  {@code true} if this DIT content rule is declared obsolete, or
   *          {@code false} if it is not.
   */
  public boolean isObsolete()
  {
    return isObsolete;
  }



  /**
   * Retrieves the names or OIDs of the auxiliary object classes that may be
   * present in entries containing the structural class for this DIT content
   * rule.
   *
   * @return  The names or OIDs of the auxiliary object classes that may be
   *          present in entries containing the structural class for this DIT
   *          content rule.
   */
  @NotNull()
  public String[] getAuxiliaryClasses()
  {
    return auxiliaryClasses;
  }



  /**
   * Retrieves the names or OIDs of the attributes that are required to be
   * present in entries containing the structural object class for this DIT
   * content rule.
   *
   * @return  The names or OIDs of the attributes that are required to be
   *          present in entries containing the structural object class for this
   *          DIT content rule, or an empty array if there are no required
   *          attributes.
   */
  @NotNull()
  public String[] getRequiredAttributes()
  {
    return requiredAttributes;
  }



  /**
   * Retrieves the names or OIDs of the attributes that are optionally allowed
   * to be present in entries containing the structural object class for this
   * DIT content rule.
   *
   * @return  The names or OIDs of the attributes that are optionally allowed to
   *          be present in entries containing the structural object class for
   *          this DIT content rule, or an empty array if there are no required
   *          attributes.
   */
  @NotNull()
  public String[] getOptionalAttributes()
  {
    return optionalAttributes;
  }



  /**
   * Retrieves the names or OIDs of the attributes that are not allowed to be
   * present in entries containing the structural object class for this DIT
   * content rule.
   *
   * @return  The names or OIDs of the attributes that are not allowed to be
   *          present in entries containing the structural object class for this
   *          DIT content rule, or an empty array if there are no required
   *          attributes.
   */
  @NotNull()
  public String[] getProhibitedAttributes()
  {
    return prohibitedAttributes;
  }



  /**
   * Retrieves the set of extensions for this DIT content rule.  They will be
   * mapped from the extension name (which should start with "X-") to the set of
   * values for that extension.
   *
   * @return  The set of extensions for this DIT content rule.
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
    return SchemaElementType.DIT_CONTENT_RULE;
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

    if (! (o instanceof DITContentRuleDefinition))
    {
      return false;
    }

    final DITContentRuleDefinition d = (DITContentRuleDefinition) o;
    return (oid.equals(d.oid) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(auxiliaryClasses,
              d.auxiliaryClasses) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(requiredAttributes,
              d.requiredAttributes) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(optionalAttributes,
              d.optionalAttributes) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(
              prohibitedAttributes, d.prohibitedAttributes) &&
         StaticUtils.bothNullOrEqualIgnoreCase(description, d.description) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions));
  }



  /**
   * Retrieves a string representation of this DIT content rule definition, in
   * the format described in RFC 4512 section 4.1.6.
   *
   * @return  A string representation of this DIT content rule definition.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return ditContentRuleString;
  }
}
