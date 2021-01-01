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
import java.util.HashSet;
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
 * This class provides a data structure that describes an LDAP DIT structure
 * rule schema element.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DITStructureRuleDefinition
       extends SchemaElement
{
  /**
   * A pre-allocated zero-element integer array.
   */
  @NotNull private static final int[] NO_INTS = new int[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3233223742542121140L;



  // Indicates whether this DIT structure rule is declared obsolete.
  private final boolean isObsolete;

  // The rule ID for this DIT structure rule.
  private final int ruleID;

  // The set of superior rule IDs for this DIT structure rule.
  @NotNull private final int[] superiorRuleIDs;

  // The set of extensions for this DIT content rule.
  @NotNull private final Map<String,String[]> extensions;

  // The description for this DIT content rule.
  @Nullable private final String description;

  // The string representation of this DIT structure rule.
  @NotNull private final String ditStructureRuleString;

  // The name/OID of the name form with which this DIT structure rule is
  // associated.
  @NotNull private final String nameFormID;

  // The set of names for this DIT structure rule.
  @NotNull private final String[] names;



  /**
   * Creates a new DIT structure rule from the provided string representation.
   *
   * @param  s  The string representation of the DIT structure rule to create,
   *            using the syntax described in RFC 4512 section 4.1.7.1.  It must
   *            not be {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as a DIT
   *                         structure rule definition.
   */
  public DITStructureRuleDefinition(@NotNull final String s)
         throws LDAPException
  {
    Validator.ensureNotNull(s);

    ditStructureRuleString = s.trim();

    // The first character must be an opening parenthesis.
    final int length = ditStructureRuleString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DSR_DECODE_EMPTY.get());
    }
    else if (ditStructureRuleString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DSR_DECODE_NO_OPENING_PAREN.get(
                                   ditStructureRuleString));
    }


    // Skip over any spaces until we reach the start of the OID, then read the
    // rule ID until we find the next space.
    int pos = skipSpaces(ditStructureRuleString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(ditStructureRuleString, pos, length, buffer);
    final String ruleIDStr = buffer.toString();
    try
    {
      ruleID = Integer.parseInt(ruleIDStr);
    }
    catch (final NumberFormatException nfe)
    {
      Debug.debugException(nfe);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DSR_DECODE_RULE_ID_NOT_INT.get(
                                   ditStructureRuleString),
                              nfe);
    }


    // Technically, DIT structure elements are supposed to appear in a specific
    // order, but we'll be lenient and allow remaining elements to come in any
    // order.
    final ArrayList<Integer> supList = new ArrayList<>(1);
    final ArrayList<String> nameList = new ArrayList<>(1);
    final Map<String,String[]> exts =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));
    Boolean obsolete = null;
    String descr = null;
    String nfID = null;

    while (true)
    {
      // Skip over any spaces until we find the next element.
      pos = skipSpaces(ditStructureRuleString, pos, length);

      // Read until we find the next space or the end of the string.  Use that
      // token to figure out what to do next.
      final int tokenStartPos = pos;
      while ((pos < length) && (ditStructureRuleString.charAt(pos) != ' '))
      {
        pos++;
      }

      // It's possible that the token could be smashed right up against the
      // closing parenthesis.  If that's the case, then extract just the token
      // and handle the closing parenthesis the next time through.
      String token = ditStructureRuleString.substring(tokenStartPos, pos);
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
                                  ERR_DSR_DECODE_CLOSE_NOT_AT_END.get(
                                       ditStructureRuleString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(ditStructureRuleString, pos, length);
          pos = readQDStrings(ditStructureRuleString, pos, length, token,
               nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(ditStructureRuleString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(ditStructureRuleString, pos, length, token,
               buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "DESC"));
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
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("form"))
      {
        if (nfID == null)
        {
          pos = skipSpaces(ditStructureRuleString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(ditStructureRuleString, pos, length, buffer);
          nfID = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "FORM"));
        }
      }
      else if (lowerToken.equals("sup"))
      {
        if (supList.isEmpty())
        {
          final ArrayList<String> supStrs = new ArrayList<>(1);

          pos = skipSpaces(ditStructureRuleString, pos, length);
          pos = readOIDs(ditStructureRuleString, pos, length, token, supStrs);

          supList.ensureCapacity(supStrs.size());
          for (final String supStr : supStrs)
          {
            try
            {
              supList.add(Integer.parseInt(supStr));
            }
            catch (final NumberFormatException nfe)
            {
              Debug.debugException(nfe);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                                      ERR_DSR_DECODE_SUP_ID_NOT_INT.get(
                                           ditStructureRuleString),
                                      nfe);
            }
          }
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "SUP"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(ditStructureRuleString, pos, length);

        final ArrayList<String> valueList = new ArrayList<>(5);
        pos = readQDStrings(ditStructureRuleString, pos, length, token,
             valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_DUP_EXT.get(
                                       ditStructureRuleString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_DSR_DECODE_UNEXPECTED_TOKEN.get(
                                     ditStructureRuleString, token));
      }
    }

    description = descr;
    nameFormID  = nfID;

    if (nameFormID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DSR_DECODE_NO_FORM.get(
                                   ditStructureRuleString));
    }

    names = new String[nameList.size()];
    nameList.toArray(names);

    superiorRuleIDs = new int[supList.size()];
    for (int i=0; i < superiorRuleIDs.length; i++)
    {
      superiorRuleIDs[i] = supList.get(i);
    }

    isObsolete = (obsolete != null);

    extensions = Collections.unmodifiableMap(exts);
  }



  /**
   * Creates a new DIT structure rule with the provided information.
   *
   * @param  ruleID          The rule ID for this DIT structure rule.
   * @param  name            The name for this DIT structure rule.  It may be
   *                         {@code null} if the DIT structure rule should only
   *                         be referenced by rule ID.
   * @param  description     The description for this DIT structure rule.  It
   *                         may be {@code null} if there is no description.
   * @param  nameFormID      The name or OID of the name form with which this
   *                         DIT structure rule is associated.  It must not be
   *                         {@code null}.
   * @param  superiorRuleID  The superior rule ID for this DIT structure rule.
   *                         It may be {@code null} if there are no superior
   *                         rule IDs.
   * @param  extensions      The set of extensions for this DIT structure rule.
   *                         It may be {@code null} or empty if there are no
   *                         extensions.
   */
  public DITStructureRuleDefinition(final int ruleID,
              @Nullable final String name,
              @Nullable final String description,
              @NotNull final String nameFormID,
              @Nullable final Integer superiorRuleID,
              @Nullable final Map<String,String[]> extensions)
  {
    this(ruleID, ((name == null) ? null : new String[] { name }), description,
         false, nameFormID,
         ((superiorRuleID == null) ? null : new int[] { superiorRuleID }),
         extensions);
  }



  /**
   * Creates a new DIT structure rule with the provided information.
   *
   * @param  ruleID           The rule ID for this DIT structure rule.
   * @param  names            The set of names for this DIT structure rule.  It
   *                          may be {@code null} or empty if the DIT structure
   *                          rule should only be referenced by rule ID.
   * @param  description      The description for this DIT structure rule.  It
   *                          may be {@code null} if there is no description.
   * @param  isObsolete       Indicates whether this DIT structure rule is
   *                          declared obsolete.
   * @param  nameFormID       The name or OID of the name form with which this
   *                          DIT structure rule is associated.  It must not be
   *                          {@code null}.
   * @param  superiorRuleIDs  The superior rule IDs for this DIT structure rule.
   *                          It may be {@code null} or empty if there are no
   *                          superior rule IDs.
   * @param  extensions       The set of extensions for this DIT structure rule.
   *                          It may be {@code null} or empty if there are no
   *                          extensions.
   */
  public DITStructureRuleDefinition(final int ruleID,
              @Nullable final String[] names,
              @Nullable final String description,
              final boolean isObsolete,
              @NotNull final String nameFormID,
              @Nullable final int[] superiorRuleIDs,
              @Nullable final Map<String,String[]> extensions)
  {
    Validator.ensureNotNull(nameFormID);

    this.ruleID      = ruleID;
    this.description = description;
    this.isObsolete  = isObsolete;
    this.nameFormID  = nameFormID;

    if (names == null)
    {
      this.names = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

    if (superiorRuleIDs == null)
    {
      this.superiorRuleIDs = NO_INTS;
    }
    else
    {
      this.superiorRuleIDs = superiorRuleIDs;
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
    ditStructureRuleString = buffer.toString();
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
    buffer.append(ruleID);

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

    buffer.append(" FORM ");
    buffer.append(nameFormID);

    if (superiorRuleIDs.length == 1)
    {
      buffer.append(" SUP ");
      buffer.append(superiorRuleIDs[0]);
    }
    else if (superiorRuleIDs.length > 1)
    {
      buffer.append(" SUP (");
      for (final int supID : superiorRuleIDs)
      {
        buffer.append(" $ ");
        buffer.append(supID);
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
   * Retrieves the rule ID for this DIT structure rule.
   *
   * @return  The rule ID for this DIT structure rule.
   */
  public int getRuleID()
  {
    return ruleID;
  }



  /**
   * Retrieves the set of names for this DIT structure rule.
   *
   * @return  The set of names for this DIT structure rule, or an empty array if
   *          it does not have any names.
   */
  @NotNull()
  public String[] getNames()
  {
    return names;
  }



  /**
   * Retrieves the primary name that can be used to reference this DIT structure
   * rule.  If one or more names are defined, then the first name will be used.
   * Otherwise, the string representation of the rule ID will be returned.
   *
   * @return  The primary name that can be used to reference this DIT structure
   *          rule.
   */
  @NotNull()
  public String getNameOrRuleID()
  {
    if (names.length == 0)
    {
      return String.valueOf(ruleID);
    }
    else
    {
      return names[0];
    }
  }



  /**
   * Indicates whether the provided string matches the rule ID or any of the
   * names for this DIT structure rule.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string matches the rule ID or any of
   *          the names for this DIT structure rule, or {@code false} if not.
   */
  public boolean hasNameOrRuleID(@NotNull final String s)
  {
    for (final String name : names)
    {
      if (s.equalsIgnoreCase(name))
      {
        return true;
      }
    }

    return s.equalsIgnoreCase(String.valueOf(ruleID));
  }



  /**
   * Retrieves the description for this DIT structure rule, if available.
   *
   * @return  The description for this DIT structure rule, or {@code null} if
   *          there is no description defined.
   */
  @Nullable()
  public String getDescription()
  {
    return description;
  }



  /**
   * Indicates whether this DIT structure rule is declared obsolete.
   *
   * @return  {@code true} if this DIT structure rule is declared obsolete, or
   *          {@code false} if it is not.
   */
  public boolean isObsolete()
  {
    return isObsolete;
  }



  /**
   * Retrieves the name or OID of the name form with which this DIT structure
   * rule is associated.
   *
   * @return  The name or OID of the name form with which this DIT structure
   *          rule is associated.
   */
  @NotNull()
  public String getNameFormID()
  {
    return nameFormID;
  }



  /**
   * Retrieves the rule IDs of the superior rules for this DIT structure rule.
   *
   * @return  The rule IDs of the superior rules for this DIT structure rule, or
   *          an empty array if there are no superior rule IDs.
   */
  @NotNull()
  public int[] getSuperiorRuleIDs()
  {
    return superiorRuleIDs;
  }



  /**
   * Retrieves the set of extensions for this DIT structure rule.  They will be
   * mapped from the extension name (which should start with "X-") to the set of
   * values for that extension.
   *
   * @return  The set of extensions for this DIT structure rule.
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
    return SchemaElementType.DIT_STRUCTURE_RULE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    return ruleID;
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

    if (! (o instanceof DITStructureRuleDefinition))
    {
      return false;
    }

    final DITStructureRuleDefinition d = (DITStructureRuleDefinition) o;
    if ((ruleID == d.ruleID) &&
         nameFormID.equalsIgnoreCase(d.nameFormID) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions))
    {
      if (superiorRuleIDs.length != d.superiorRuleIDs.length)
      {
        return false;
      }

      final HashSet<Integer> s1 = new HashSet<>(
           StaticUtils.computeMapCapacity(superiorRuleIDs.length));
      final HashSet<Integer> s2 = new HashSet<>(
           StaticUtils.computeMapCapacity(superiorRuleIDs.length));
      for (final int i : superiorRuleIDs)
      {
        s1.add(i);
      }

      for (final int i : d.superiorRuleIDs)
      {
        s2.add(i);
      }

      return s1.equals(s2);
    }
    else
    {
      return false;
    }
  }



  /**
   * Retrieves a string representation of this DIT structure rule definition, in
   * the format described in RFC 4512 section 4.1.7.1.
   *
   * @return  A string representation of this DIT structure rule definition.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return ditStructureRuleString;
  }
}
