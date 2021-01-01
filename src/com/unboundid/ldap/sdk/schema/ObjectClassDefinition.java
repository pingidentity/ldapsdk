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
import java.util.HashSet;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;

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
 * This class provides a data structure that describes an LDAP object class
 * schema element.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ObjectClassDefinition
       extends SchemaElement
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3024333376249332728L;



  // Indicates whether this object class is declared obsolete.
  private final boolean isObsolete;

  // The set of extensions for this object class.
  @NotNull private final Map<String,String[]> extensions;

  // The object class type for this object class.
  @Nullable private final ObjectClassType objectClassType;

  // The description for this object class.
  @Nullable private final String description;

  // The string representation of this object class.
  @NotNull private final String objectClassString;

  // The OID for this object class.
  @NotNull private final String oid;

  // The set of names for this object class.
  @NotNull private final String[] names;

  // The names/OIDs of the optional attributes.
  @NotNull private final String[] optionalAttributes;

  // The names/OIDs of the required attributes.
  @NotNull private final String[] requiredAttributes;

  // The set of superior object class names/OIDs.
  @NotNull private final String[] superiorClasses;



  /**
   * Creates a new object class from the provided string representation.
   *
   * @param  s  The string representation of the object class to create, using
   *            the syntax described in RFC 4512 section 4.1.1.  It must not be
   *            {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as an
   *                         object class definition.
   */
  public ObjectClassDefinition(@NotNull final String s)
         throws LDAPException
  {
    Validator.ensureNotNull(s);

    objectClassString = s.trim();

    // The first character must be an opening parenthesis.
    final int length = objectClassString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_OC_DECODE_EMPTY.get());
    }
    else if (objectClassString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_OC_DECODE_NO_OPENING_PAREN.get(
                                   objectClassString));
    }


    // Skip over any spaces until we reach the start of the OID, then read the
    // OID until we find the next space.
    int pos = skipSpaces(objectClassString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(objectClassString, pos, length, buffer);
    oid = buffer.toString();


    // Technically, object class elements are supposed to appear in a specific
    // order, but we'll be lenient and allow remaining elements to come in any
    // order.
    final ArrayList<String> nameList = new ArrayList<>(1);
    final ArrayList<String> supList = new ArrayList<>(1);
    final ArrayList<String> reqAttrs = new ArrayList<>(20);
    final ArrayList<String> optAttrs = new ArrayList<>(20);
    final Map<String,String[]> exts =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));
    Boolean obsolete = null;
    ObjectClassType ocType = null;
    String descr = null;

    while (true)
    {
      // Skip over any spaces until we find the next element.
      pos = skipSpaces(objectClassString, pos, length);

      // Read until we find the next space or the end of the string.  Use that
      // token to figure out what to do next.
      final int tokenStartPos = pos;
      while ((pos < length) && (objectClassString.charAt(pos) != ' '))
      {
        pos++;
      }

      // It's possible that the token could be smashed right up against the
      // closing parenthesis.  If that's the case, then extract just the token
      // and handle the closing parenthesis the next time through.
      String token = objectClassString.substring(tokenStartPos, pos);
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
                                  ERR_OC_DECODE_CLOSE_NOT_AT_END.get(
                                       objectClassString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(objectClassString, pos, length);
          pos = readQDStrings(objectClassString, pos, length, token, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(objectClassString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(objectClassString, pos, length, token, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "DESC"));
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
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("sup"))
      {
        if (supList.isEmpty())
        {
          pos = skipSpaces(objectClassString, pos, length);
          pos = readOIDs(objectClassString, pos, length, token, supList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "SUP"));
        }
      }
      else if (lowerToken.equals("abstract"))
      {
        if (ocType == null)
        {
          ocType = ObjectClassType.ABSTRACT;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_OC_TYPES.get(
                                       objectClassString));
        }
      }
      else if (lowerToken.equals("structural"))
      {
        if (ocType == null)
        {
          ocType = ObjectClassType.STRUCTURAL;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_OC_TYPES.get(
                                       objectClassString));
        }
      }
      else if (lowerToken.equals("auxiliary"))
      {
        if (ocType == null)
        {
          ocType = ObjectClassType.AUXILIARY;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_OC_TYPES.get(
                                       objectClassString));
        }
      }
      else if (lowerToken.equals("must"))
      {
        if (reqAttrs.isEmpty())
        {
          pos = skipSpaces(objectClassString, pos, length);
          pos = readOIDs(objectClassString, pos, length, token, reqAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "MUST"));
        }
      }
      else if (lowerToken.equals("may"))
      {
        if (optAttrs.isEmpty())
        {
          pos = skipSpaces(objectClassString, pos, length);
          pos = readOIDs(objectClassString, pos, length, token, optAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "MAY"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(objectClassString, pos, length);

        final ArrayList<String> valueList = new ArrayList<>(5);
        pos = readQDStrings(objectClassString, pos, length, token, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_DUP_EXT.get(objectClassString,
                                                            token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_OC_DECODE_UNEXPECTED_TOKEN.get(
                                     objectClassString, token));
      }
    }

    description = descr;

    names = new String[nameList.size()];
    nameList.toArray(names);

    superiorClasses = new String[supList.size()];
    supList.toArray(superiorClasses);

    requiredAttributes = new String[reqAttrs.size()];
    reqAttrs.toArray(requiredAttributes);

    optionalAttributes = new String[optAttrs.size()];
    optAttrs.toArray(optionalAttributes);

    isObsolete = (obsolete != null);

    objectClassType = ocType;

    extensions = Collections.unmodifiableMap(exts);
  }



  /**
   * Creates a new object class with the provided information.
   *
   * @param  oid                 The OID for this object class.  It must not be
   *                             {@code null}.
   * @param  name                The name for this object class.  It may be
   *                             {@code null} if the object class should only be
   *                             referenced by OID.
   * @param  description         The description for this object class.  It may
   *                             be {@code null} if there is no description.
   * @param  superiorClass       The name/OID of the superior class for this
   *                             object class.  It may be {@code null} or
   *                             empty if there is no superior class.
   * @param  objectClassType     The object class type for this object class.
   * @param  requiredAttributes  The names/OIDs of the attributes which must be
   *                             present in entries containing this object
   *                             class.
   * @param  optionalAttributes  The names/OIDs of the attributes which may be
   *                             present in entries containing this object
   *                             class.
   * @param  extensions          The set of extensions for this object class.
   *                             It may be {@code null} or empty if there should
   *                             not be any extensions.
   */
  public ObjectClassDefinition(@NotNull final String oid,
                               @Nullable final String name,
                               @Nullable final String description,
                               @Nullable final String superiorClass,
                               @Nullable final ObjectClassType objectClassType,
                               @Nullable final String[] requiredAttributes,
                               @Nullable final String[] optionalAttributes,
                               @Nullable final Map<String,String[]> extensions)
  {
    this(oid, ((name == null) ? null : new String[] { name }), description,
         false,
         ((superiorClass == null) ? null : new String[] { superiorClass }),
         objectClassType, requiredAttributes, optionalAttributes,
         extensions);
  }



  /**
   * Creates a new object class with the provided information.
   *
   * @param  oid                 The OID for this object class.  It must not be
   *                             {@code null}.
   * @param  name                The name for this object class.  It may be
   *                             {@code null} if the object class should only be
   *                             referenced by OID.
   * @param  description         The description for this object class.  It may
   *                             be {@code null} if there is no description.
   * @param  superiorClass       The name/OID of the superior class for this
   *                             object class.  It may be {@code null} or
   *                             empty if there is no superior class.
   * @param  objectClassType     The object class type for this object class.
   * @param  requiredAttributes  The names/OIDs of the attributes which must be
   *                             present in entries containing this object
   *                             class.
   * @param  optionalAttributes  The names/OIDs of the attributes which may be
   *                             present in entries containing this object
   *                             class.
   * @param  extensions          The set of extensions for this object class.
   *                             It may be {@code null} or empty if there should
   *                             not be any extensions.
   */
  public ObjectClassDefinition(@NotNull final String oid,
              @Nullable final String name,
              @Nullable final String description,
              @Nullable final String superiorClass,
              @Nullable final ObjectClassType objectClassType,
              @Nullable final Collection<String> requiredAttributes,
              @Nullable final Collection<String> optionalAttributes,
              @Nullable final Map<String,String[]> extensions)
  {
    this(oid, ((name == null) ? null : new String[] { name }), description,
         false,
         ((superiorClass == null) ? null : new String[] { superiorClass }),
         objectClassType, toArray(requiredAttributes),
         toArray(optionalAttributes), extensions);
  }



  /**
   * Creates a new object class with the provided information.
   *
   * @param  oid                 The OID for this object class.  It must not be
   *                             {@code null}.
   * @param  names               The set of names for this object class.  It may
   *                             be {@code null} or empty if the object class
   *                             should only be referenced by OID.
   * @param  description         The description for this object class.  It may
   *                             be {@code null} if there is no description.
   * @param  isObsolete          Indicates whether this object class is declared
   *                             obsolete.
   * @param  superiorClasses     The names/OIDs of the superior classes for this
   *                             object class.  It may be {@code null} or
   *                             empty if there is no superior class.
   * @param  objectClassType     The object class type for this object class.
   * @param  requiredAttributes  The names/OIDs of the attributes which must be
   *                             present in entries containing this object
   *                             class.
   * @param  optionalAttributes  The names/OIDs of the attributes which may be
   *                             present in entries containing this object
   *                             class.
   * @param  extensions          The set of extensions for this object class.
   *                             It may be {@code null} or empty if there should
   *                             not be any extensions.
   */
  public ObjectClassDefinition(@NotNull final String oid,
                               @Nullable final String[] names,
                               @Nullable final String description,
                               final boolean isObsolete,
                               @Nullable final String[] superiorClasses,
                               @Nullable final ObjectClassType objectClassType,
                               @Nullable final String[] requiredAttributes,
                               @Nullable final String[] optionalAttributes,
                               @Nullable final Map<String,String[]> extensions)
  {
    Validator.ensureNotNull(oid);

    this.oid             = oid;
    this.isObsolete      = isObsolete;
    this.description     = description;
    this.objectClassType = objectClassType;

    if (names == null)
    {
      this.names = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

    if (superiorClasses == null)
    {
      this.superiorClasses = StaticUtils.NO_STRINGS;
    }
    else
    {
      this.superiorClasses = superiorClasses;
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
    objectClassString = buffer.toString();
  }



  /**
   * Constructs a string representation of this object class definition in the
   * provided buffer.
   *
   * @param  buffer  The buffer in which to construct a string representation of
   *                 this object class definition.
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

    if (superiorClasses.length == 1)
    {
      buffer.append(" SUP ");
      buffer.append(superiorClasses[0]);
    }
    else if (superiorClasses.length > 1)
    {
      buffer.append(" SUP (");
      for (int i=0; i < superiorClasses.length; i++)
      {
        if (i > 0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(superiorClasses[i]);
      }
      buffer.append(" )");
    }

    if (objectClassType != null)
    {
      buffer.append(' ');
      buffer.append(objectClassType.getName());
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
   * Retrieves the OID for this object class.
   *
   * @return  The OID for this object class.
   */
  @NotNull()
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the set of names for this object class.
   *
   * @return  The set of names for this object class, or an empty array if it
   *          does not have any names.
   */
  @NotNull()
  public String[] getNames()
  {
    return names;
  }



  /**
   * Retrieves the primary name that can be used to reference this object
   * class.  If one or more names are defined, then the first name will be used.
   * Otherwise, the OID will be returned.
   *
   * @return  The primary name that can be used to reference this object class.
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
   * for this object class.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string matches the OID or any of the
   *          names for this object class, or {@code false} if not.
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
   * Retrieves the description for this object class, if available.
   *
   * @return  The description for this object class, or {@code null} if there is
   *          no description defined.
   */
  @Nullable()
  public String getDescription()
  {
    return description;
  }



  /**
   * Indicates whether this object class is declared obsolete.
   *
   * @return  {@code true} if this object class is declared obsolete, or
   *          {@code false} if it is not.
   */
  public boolean isObsolete()
  {
    return isObsolete;
  }



  /**
   * Retrieves the names or OIDs of the superior classes for this object class,
   * if available.
   *
   * @return  The names or OIDs of the superior classes for this object class,
   *          or an empty array if it does not have any superior classes.
   */
  @NotNull()
  public String[] getSuperiorClasses()
  {
    return superiorClasses;
  }



  /**
   * Retrieves the object class definitions for the superior object classes.
   *
   * @param  schema     The schema to use to retrieve the object class
   *                    definitions.
   * @param  recursive  Indicates whether to recursively include all of the
   *                    superior object class definitions from superior classes.
   *
   * @return  The object class definitions for the superior object classes.
   */
  @NotNull()
  public Set<ObjectClassDefinition> getSuperiorClasses(
              @NotNull final Schema schema, final boolean recursive)
  {
    final LinkedHashSet<ObjectClassDefinition> ocSet =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(10));
    for (final String s : superiorClasses)
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      if (d != null)
      {
        ocSet.add(d);
        if (recursive)
        {
          getSuperiorClasses(schema, d, ocSet);
        }
      }
    }

    return Collections.unmodifiableSet(ocSet);
  }



  /**
   * Recursively adds superior class definitions to the provided set.
   *
   * @param  schema  The schema to use to retrieve the object class definitions.
   * @param  oc      The object class definition to be processed.
   * @param  ocSet   The set to which the definitions should be added.
   */
  private static void getSuperiorClasses(@NotNull final Schema schema,
                           @NotNull final ObjectClassDefinition oc,
                           @NotNull final Set<ObjectClassDefinition> ocSet)
  {
    for (final String s : oc.superiorClasses)
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      if (d != null)
      {
        ocSet.add(d);
        getSuperiorClasses(schema, d, ocSet);
      }
    }
  }



  /**
   * Retrieves the object class type for this object class.  This method will
   * return {@code null} if this object class definition does not explicitly
   * specify the object class type, although in that case, the object class type
   * should be assumed to be {@link ObjectClassType#STRUCTURAL} as per RFC 4512
   * section 4.1.1.
   *
   * @return  The object class type for this object class, or {@code null} if it
   *          is not defined in the schema element.
   */
  @Nullable()
  public ObjectClassType getObjectClassType()
  {
    return objectClassType;
  }



  /**
   * Retrieves the object class type for this object class, recursively
   * examining superior classes if necessary to make the determination.
   * <BR><BR>
   * Note that versions of this method before the 4.0.6 release of the LDAP SDK
   * operated under the incorrect assumption that if an object class definition
   * did not explicitly specify the object class type, it would be inherited
   * from its superclass.  The correct behavior, as per RFC 4512 section 4.1.1,
   * is that if the object class type is not explicitly specified, it should be
   * assumed to be {@link ObjectClassType#STRUCTURAL}.
   *
   * @param  schema  The schema to use to retrieve the definitions for the
   *                 superior object classes.  As of LDAP SDK version 4.0.6,
   *                 this argument is no longer used (and may be {@code null} if
   *                 desired), but this version of the method has been preserved
   *                 both for the purpose of retaining API compatibility with
   *                 previous versions of the LDAP SDK, and to disambiguate it
   *                 from the zero-argument version of the method that returns
   *                 {@code null} if the object class type is not explicitly
   *                 specified.
   *
   * @return  The object class type for this object class, or
   *          {@link ObjectClassType#STRUCTURAL} if it is not explicitly
   *          defined.
   */
  @NotNull()
  public ObjectClassType getObjectClassType(@NotNull final Schema schema)
  {
    if (objectClassType == null)
    {
      return ObjectClassType.STRUCTURAL;
    }
    else
    {
      return objectClassType;
    }
  }



  /**
   * Retrieves the names or OIDs of the attributes that are required to be
   * present in entries containing this object class.  Note that this will not
   * automatically include the set of required attributes from any superior
   * classes.
   *
   * @return  The names or OIDs of the attributes that are required to be
   *          present in entries containing this object class, or an empty array
   *          if there are no required attributes.
   */
  @NotNull()
  public String[] getRequiredAttributes()
  {
    return requiredAttributes;
  }



  /**
   * Retrieves the attribute type definitions for the attributes that are
   * required to be present in entries containing this object class, optionally
   * including the set of required attribute types from superior classes.
   *
   * @param  schema                  The schema to use to retrieve the
   *                                 attribute type definitions.
   * @param  includeSuperiorClasses  Indicates whether to include definitions
   *                                 for required attribute types in superior
   *                                 object classes.
   *
   * @return  The attribute type definitions for the attributes that are
   *          required to be present in entries containing this object class.
   */
  @NotNull()
  public Set<AttributeTypeDefinition> getRequiredAttributes(
              @NotNull final Schema schema,
              final boolean includeSuperiorClasses)
  {
    final HashSet<AttributeTypeDefinition> attrSet =
         new HashSet<>(StaticUtils.computeMapCapacity(20));
    for (final String s : requiredAttributes)
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if (d != null)
      {
        attrSet.add(d);
      }
    }

    if (includeSuperiorClasses)
    {
      for (final String s : superiorClasses)
      {
        final ObjectClassDefinition d = schema.getObjectClass(s);
        if (d != null)
        {
          getSuperiorRequiredAttributes(schema, d, attrSet);
        }
      }
    }

    return Collections.unmodifiableSet(attrSet);
  }



  /**
   * Recursively adds the required attributes from the provided object class
   * to the given set.
   *
   * @param  schema   The schema to use during processing.
   * @param  oc       The object class to be processed.
   * @param  attrSet  The set to which the attribute type definitions should be
   *                  added.
   */
  private static void getSuperiorRequiredAttributes(
                           @NotNull final Schema schema,
                           @NotNull final ObjectClassDefinition oc,
                           @NotNull final Set<AttributeTypeDefinition> attrSet)
  {
    for (final String s : oc.requiredAttributes)
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if (d != null)
      {
        attrSet.add(d);
      }
    }

    for (final String s : oc.superiorClasses)
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      if (d != null)
      {
        getSuperiorRequiredAttributes(schema, d, attrSet);
      }
    }
  }



  /**
   * Retrieves the names or OIDs of the attributes that may optionally be
   * present in entries containing this object class.  Note that this will not
   * automatically include the set of optional attributes from any superior
   * classes.
   *
   * @return  The names or OIDs of the attributes that may optionally be present
   *          in entries containing this object class, or an empty array if
   *          there are no optional attributes.
   */
  @NotNull()
  public String[] getOptionalAttributes()
  {
    return optionalAttributes;
  }



  /**
   * Retrieves the attribute type definitions for the attributes that may
   * optionally be present in entries containing this object class, optionally
   * including the set of optional attribute types from superior classes.
   *
   * @param  schema                  The schema to use to retrieve the
   *                                 attribute type definitions.
   * @param  includeSuperiorClasses  Indicates whether to include definitions
   *                                 for optional attribute types in superior
   *                                 object classes.
   *
   * @return  The attribute type definitions for the attributes that may
   *          optionally be present in entries containing this object class.
   */
  @NotNull()
  public Set<AttributeTypeDefinition> getOptionalAttributes(
              @NotNull final Schema schema,
              final boolean includeSuperiorClasses)
  {
    final HashSet<AttributeTypeDefinition> attrSet =
         new HashSet<>(StaticUtils.computeMapCapacity(20));
    for (final String s : optionalAttributes)
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if (d != null)
      {
        attrSet.add(d);
      }
    }

    if (includeSuperiorClasses)
    {
      final Set<AttributeTypeDefinition> requiredAttrs =
           getRequiredAttributes(schema, true);
      for (final AttributeTypeDefinition d : requiredAttrs)
      {
        attrSet.remove(d);
      }

      for (final String s : superiorClasses)
      {
        final ObjectClassDefinition d = schema.getObjectClass(s);
        if (d != null)
        {
          getSuperiorOptionalAttributes(schema, d, attrSet, requiredAttrs);
        }
      }
    }

    return Collections.unmodifiableSet(attrSet);
  }



  /**
   * Recursively adds the optional attributes from the provided object class
   * to the given set.
   *
   * @param  schema       The schema to use during processing.
   * @param  oc           The object class to be processed.
   * @param  attrSet      The set to which the attribute type definitions should
   *                      be added.
   * @param  requiredSet  x
   */
  private static void getSuperiorOptionalAttributes(
               @NotNull final Schema schema,
               @NotNull final ObjectClassDefinition oc,
               @NotNull final Set<AttributeTypeDefinition> attrSet,
               @NotNull final Set<AttributeTypeDefinition> requiredSet)
  {
    for (final String s : oc.optionalAttributes)
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if ((d != null) && (! requiredSet.contains(d)))
      {
        attrSet.add(d);
      }
    }

    for (final String s : oc.superiorClasses)
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      if (d != null)
      {
        getSuperiorOptionalAttributes(schema, d, attrSet, requiredSet);
      }
    }
  }



  /**
   * Retrieves the set of extensions for this object class.  They will be mapped
   * from the extension name (which should start with "X-") to the set of values
   * for that extension.
   *
   * @return  The set of extensions for this object class.
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
    return SchemaElementType.OBJECT_CLASS;
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

    if (! (o instanceof ObjectClassDefinition))
    {
      return false;
    }

    final ObjectClassDefinition d = (ObjectClassDefinition) o;
    return (oid.equals(d.oid) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(requiredAttributes,
              d.requiredAttributes) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(optionalAttributes,
              d.optionalAttributes) &&
         StaticUtils.stringsEqualIgnoreCaseOrderIndependent(superiorClasses,
              d.superiorClasses) &&
         StaticUtils.bothNullOrEqual(objectClassType, d.objectClassType) &&
         StaticUtils.bothNullOrEqualIgnoreCase(description, d.description) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions));
  }



  /**
   * Retrieves a string representation of this object class definition, in the
   * format described in RFC 4512 section 4.1.1.
   *
   * @return  A string representation of this object class definition.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return objectClassString;
  }
}
