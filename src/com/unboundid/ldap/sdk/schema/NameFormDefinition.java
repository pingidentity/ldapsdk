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
 * This class provides a data structure that describes an LDAP name form schema
 * element.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class NameFormDefinition
       extends SchemaElement
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -816231530223449984L;



  // Indicates whether this name form is declared obsolete.
  private final boolean isObsolete;

  // The set of extensions for this name form.
  @NotNull private final Map<String,String[]> extensions;

  // The description for this name form.
  @Nullable private final String description;

  // The string representation of this name form.
  @NotNull private final String nameFormString;

  // The OID for this name form.
  @NotNull private final String oid;

  // The set of names for this name form.
  @NotNull private final String[] names;

  // The name or OID of the structural object class with which this name form
  // is associated.
  @NotNull private final String structuralClass;

  // The names/OIDs of the optional attributes.
  @NotNull private final String[] optionalAttributes;

  // The names/OIDs of the required attributes.
  @NotNull private final String[] requiredAttributes;



  /**
   * Creates a new name form from the provided string representation.
   *
   * @param  s  The string representation of the name form to create, using the
   *            syntax described in RFC 4512 section 4.1.7.2.  It must not be
   *            {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as a name
   *                         form definition.
   */
  public NameFormDefinition(@NotNull final String s)
         throws LDAPException
  {
    Validator.ensureNotNull(s);

    nameFormString = s.trim();

    // The first character must be an opening parenthesis.
    final int length = nameFormString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_NF_DECODE_EMPTY.get());
    }
    else if (nameFormString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_NF_DECODE_NO_OPENING_PAREN.get(
                                   nameFormString));
    }


    // Skip over any spaces until we reach the start of the OID, then read the
    // OID until we find the next space.
    int pos = skipSpaces(nameFormString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(nameFormString, pos, length, buffer);
    oid = buffer.toString();


    // Technically, name form elements are supposed to appear in a specific
    // order, but we'll be lenient and allow remaining elements to come in any
    // order.
    final ArrayList<String> nameList = new ArrayList<>(1);
    final ArrayList<String> reqAttrs = new ArrayList<>(10);
    final ArrayList<String> optAttrs = new ArrayList<>(10);
    final Map<String,String[]> exts =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));
    Boolean obsolete = null;
    String descr = null;
    String oc = null;

    while (true)
    {
      // Skip over any spaces until we find the next element.
      pos = skipSpaces(nameFormString, pos, length);

      // Read until we find the next space or the end of the string.  Use that
      // token to figure out what to do next.
      final int tokenStartPos = pos;
      while ((pos < length) && (nameFormString.charAt(pos) != ' '))
      {
        pos++;
      }

      // It's possible that the token could be smashed right up against the
      // closing parenthesis.  If that's the case, then extract just the token
      // and handle the closing parenthesis the next time through.
      String token = nameFormString.substring(tokenStartPos, pos);
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
                                  ERR_NF_DECODE_CLOSE_NOT_AT_END.get(
                                       nameFormString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(nameFormString, pos, length);
          pos = readQDStrings(nameFormString, pos, length, token, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(nameFormString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(nameFormString, pos, length, token, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "DESC"));
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
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("oc"))
      {
        if (oc == null)
        {
          pos = skipSpaces(nameFormString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(nameFormString, pos, length, buffer);
          oc = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "OC"));
        }
      }
      else if (lowerToken.equals("must"))
      {
        if (reqAttrs.isEmpty())
        {
          pos = skipSpaces(nameFormString, pos, length);
          pos = readOIDs(nameFormString, pos, length, token, reqAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "MUST"));
        }
      }
      else if (lowerToken.equals("may"))
      {
        if (optAttrs.isEmpty())
        {
          pos = skipSpaces(nameFormString, pos, length);
          pos = readOIDs(nameFormString, pos, length, token, optAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "MAY"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(nameFormString, pos, length);

        final ArrayList<String> valueList = new ArrayList<>(5);
        pos = readQDStrings(nameFormString, pos, length, token, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_DUP_EXT.get(nameFormString,
                                                            token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_NF_DECODE_UNEXPECTED_TOKEN.get(
                                     nameFormString, token));
      }
    }

    description     = descr;
    structuralClass = oc;

    if (structuralClass == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_NF_DECODE_NO_OC.get(nameFormString));
    }

    names = new String[nameList.size()];
    nameList.toArray(names);

    requiredAttributes = new String[reqAttrs.size()];
    reqAttrs.toArray(requiredAttributes);

    if (reqAttrs.isEmpty())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_NF_DECODE_NO_MUST.get(nameFormString));
    }

    optionalAttributes = new String[optAttrs.size()];
    optAttrs.toArray(optionalAttributes);

    isObsolete = (obsolete != null);

    extensions = Collections.unmodifiableMap(exts);
  }



  /**
   * Creates a new name form with the provided information.
   *
   * @param  oid                The OID for this name form.  It must not be
   *                            {@code null}.
   * @param  name               The name for this name form.  It may be
   *                            {@code null} or empty if the name form should
   *                            only be referenced by OID.
   * @param  description        The description for this name form.  It may be
   *                            {@code null} if there is no description.
   * @param  structuralClass    The name or OID of the structural object class
   *                            with which this name form is associated.  It
   *                            must not be {@code null}.
   * @param  requiredAttribute  he name or OID of the attribute which must be
   *                            present the RDN for entries with the associated
   *                            structural class.  It must not be {@code null}.
   * @param  extensions         The set of extensions for this name form.  It
   *                            may be {@code null} or empty if there should
   *                            not be any extensions.
   */
  public NameFormDefinition(@NotNull final String oid,
                            @Nullable final String name,
                            @Nullable final String description,
                            @NotNull final String structuralClass,
                            @NotNull final String requiredAttribute,
                            @NotNull final Map<String,String[]> extensions)
  {
    this(oid, ((name == null) ? null : new String[] { name }), description,
         false, structuralClass, new String[] { requiredAttribute }, null,
         extensions);
  }



  /**
   * Creates a new name form with the provided information.
   *
   * @param  oid                 The OID for this name form.  It must not be
   *                             {@code null}.
   * @param  names               The set of names for this name form.  It may
   *                             be {@code null} or empty if the name form
   *                             should only be referenced by OID.
   * @param  description         The description for this name form.  It may be
   *                             {@code null} if there is no description.
   * @param  isObsolete          Indicates whether this name form is declared
   *                             obsolete.
   * @param  structuralClass     The name or OID of the structural object class
   *                             with which this name form is associated.  It
   *                             must not be {@code null}.
   * @param  requiredAttributes  The names/OIDs of the attributes which must be
   *                             present the RDN for entries with the associated
   *                             structural class.  It must not be {@code null}
   *                             or empty.
   * @param  optionalAttributes  The names/OIDs of the attributes which may
   *                             optionally be present in the RDN for entries
   *                             with the associated structural class.  It may
   *                             be {@code null} or empty if no optional
   *                             attributes are needed.
   * @param  extensions          The set of extensions for this name form.  It
   *                             may be {@code null} or empty if there should
   *                             not be any extensions.
   */
  public NameFormDefinition(@NotNull final String oid,
                            @Nullable final String[] names,
                            @Nullable final String description,
                            final boolean isObsolete,
                            @NotNull final String structuralClass,
                            @NotNull final String[] requiredAttributes,
                            @Nullable final String[] optionalAttributes,
                            @Nullable final Map<String,String[]> extensions)
  {
    Validator.ensureNotNull(oid, structuralClass, requiredAttributes);
    Validator.ensureFalse(requiredAttributes.length == 0);

    this.oid                = oid;
    this.isObsolete         = isObsolete;
    this.description        = description;
    this.structuralClass    = structuralClass;
    this.requiredAttributes = requiredAttributes;

    if (names == null)
    {
      this.names = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

    if (optionalAttributes == null)
    {
      this.optionalAttributes = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.optionalAttributes = optionalAttributes;
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
    nameFormString = buffer.toString();
  }



  /**
   * Constructs a string representation of this name form definition in the
   * provided buffer.
   *
   * @param  buffer  The buffer in which to construct a string representation of
   *                 this name form definition.
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

    buffer.append(" OC ");
    buffer.append(structuralClass);

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
   * Retrieves the OID for this name form.
   *
   * @return  The OID for this name form.
   */
  @NotNull()
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the set of names for this name form.
   *
   * @return  The set of names for this name form, or an empty array if it does
   *          not have any names.
   */
  @NotNull()
  public String[] getNames()
  {
    return names;
  }



  /**
   * Retrieves the primary name that can be used to reference this name form.
   * If one or more names are defined, then the first name will be used.
   * Otherwise, the OID will be returned.
   *
   * @return  The primary name that can be used to reference this name form.
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
   * for this name form.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string matches the OID or any of the
   *          names for this name form, or {@code false} if not.
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
   * Retrieves the description for this name form, if available.
   *
   * @return  The description for this name form, or {@code null} if there is no
   *          description defined.
   */
  @Nullable()
  public String getDescription()
  {
    return description;
  }



  /**
   * Indicates whether this name form is declared obsolete.
   *
   * @return  {@code true} if this name form is declared obsolete, or
   *          {@code false} if it is not.
   */
  public boolean isObsolete()
  {
    return isObsolete;
  }



  /**
   * Retrieves the name or OID of the structural object class associated with
   * this name form.
   *
   * @return  The name or OID of the structural object class associated with
   *          this name form.
   */
  @NotNull()
  public String getStructuralClass()
  {
    return structuralClass;
  }



  /**
   * Retrieves the names or OIDs of the attributes that are required to be
   * present in the RDN of entries with the associated structural object class.
   *
   * @return  The names or OIDs of the attributes that are required to be
   *          present in the RDN of entries with the associated structural
   *          object class.
   */
  @NotNull()
  public String[] getRequiredAttributes()
  {
    return requiredAttributes;
  }



  /**
   * Retrieves the names or OIDs of the attributes that may optionally be
   * present in the RDN of entries with the associated structural object class.
   *
   * @return  The names or OIDs of the attributes that may optionally be
   *          present in the RDN of entries with the associated structural
   *          object class, or an empty array if there are no optional
   *          attributes.
   */
  @NotNull()
  public String[] getOptionalAttributes()
  {
    return optionalAttributes;
  }



  /**
   * Retrieves the set of extensions for this name form.  They will be mapped
   * from the extension name (which should start with "X-") to the set of values
   * for that extension.
   *
   * @return  The set of extensions for this name form.
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
    return SchemaElementType.NAME_FORM;
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

    if (! (o instanceof NameFormDefinition))
    {
      return false;
    }

    final NameFormDefinition d = (NameFormDefinition) o;
    return (oid.equals(d.oid) &&
         structuralClass.equalsIgnoreCase(d.structuralClass) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(requiredAttributes,
              d.requiredAttributes) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(optionalAttributes,
                   d.optionalAttributes) &&
         StaticUtils.bothNullOrEqualIgnoreCase(description, d.description) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions));
  }



  /**
   * Retrieves a string representation of this name form definition, in the
   * format described in RFC 4512 section 4.1.7.2.
   *
   * @return  A string representation of this name form definition.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return nameFormString;
  }
}
