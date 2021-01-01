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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1BufferSet;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSet;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure for holding information about an LDAP
 * attribute, which includes an attribute name (which may include a set of
 * attribute options) and zero or more values.  Attribute objects are immutable
 * and cannot be altered.  However, if an attribute is included in an
 * {@link Entry} object, then it is possible to add and remove attribute values
 * from the entry (which will actually create new Attribute object instances),
 * although this is not allowed for instances of {@link ReadOnlyEntry} and its
 * subclasses.
 * <BR><BR>
 * This class uses the term "attribute name" as an equivalent of what the LDAP
 * specification refers to as an "attribute description".  An attribute
 * description consists of an attribute type name or object identifier (which
 * this class refers to as the "base name") followed by zero or more attribute
 * options, each of which should be prefixed by a semicolon.  Attribute options
 * may be used to provide additional metadata for the attribute and/or its
 * values, or to indicate special handling for the values.  For example,
 * <A HREF="http://www.ietf.org/rfc/rfc3866.txt">RFC 3866</A> describes the use
 * of attribute options to indicate that a value may be associated with a
 * particular language (e.g., "cn;lang-en-US" indicates that the values of that
 * cn attribute should be treated as U.S. English values), and
 * <A HREF="http://www.ietf.org/rfc/rfc4522.txt">RFC 4522</A> describes a binary
 * encoding option that indicates that the server should only attempt to
 * interact with the values as binary data (e.g., "userCertificate;binary") and
 * should not treat them as strings.  An attribute name (which is technically
 * referred to as an "attribute description" in the protocol specification) may
 * have zero, one, or multiple attribute options.  If there are any attribute
 * options, then a semicolon is used to separate the first option from the base
 * attribute name, and to separate each subsequent attribute option from the
 * previous option.
 * <BR><BR>
 * Attribute values can be treated as either strings or byte arrays.  In LDAP,
 * they are always transferred using a binary encoding, but applications
 * frequently treat them as strings and it is often more convenient to do so.
 * However, for some kinds of data (e.g., certificates, images, audio clips, and
 * other "blobs") it may be desirable to only treat them as binary data and only
 * interact with the values as byte arrays.  If you do intend to interact with
 * string values as byte arrays, then it is important to ensure that you use a
 * UTF-8 representation for those values unless you are confident that the
 * directory server will not attempt to treat the value as a string.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Attribute
       implements Serializable
{
  /**
   * The array to use as the set of values when there are no values.
   */
  @NotNull private static final ASN1OctetString[] NO_VALUES =
       new ASN1OctetString[0];



  /**
   * The array to use as the set of byte array values when there are no values.
   */
  @NotNull private static final byte[][] NO_BYTE_VALUES = new byte[0][];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5867076498293567612L;



  // The set of values for this attribute.
  @NotNull private final ASN1OctetString[] values;

  // The hash code for this attribute.
  private int hashCode = -1;

  // The matching rule that should be used for equality determinations.
  @NotNull private final MatchingRule matchingRule;

  // The attribute description for this attribute.
  @NotNull private final String name;



  /**
   * Creates a new LDAP attribute with the specified name and no values.
   *
   * @param  name  The name for this attribute.  It must not be {@code null}.
   */
  public Attribute(@NotNull final String name)
  {
    Validator.ensureNotNull(name);

    this.name = name;

    values = NO_VALUES;
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Creates a new LDAP attribute with the specified name and value.
   *
   * @param  name   The name for this attribute.  It must not be {@code null}.
   * @param  value  The value for this attribute.  It must not be {@code null}.
   */
  public Attribute(@NotNull final String name, @NotNull final String value)
  {
    Validator.ensureNotNull(name, value);

    this.name = name;

    values = new ASN1OctetString[] { new ASN1OctetString(value) };
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Creates a new LDAP attribute with the specified name and value.
   *
   * @param  name   The name for this attribute.  It must not be {@code null}.
   * @param  value  The value for this attribute.  It must not be {@code null}.
   */
  public Attribute(@NotNull final String name, @NotNull final byte[] value)
  {
    Validator.ensureNotNull(name, value);

    this.name = name;
    values = new ASN1OctetString[] { new ASN1OctetString(value) };
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name    The name for this attribute.  It must not be {@code null}.
   * @param  values  The set of values for this attribute.  It must not be
   *                 {@code null}.
   */
  public Attribute(@NotNull final String name, @NotNull final String... values)
  {
    Validator.ensureNotNull(name, values);

    this.name = name;

    this.values = new ASN1OctetString[values.length];
    for (int i=0; i < values.length; i++)
    {
      this.values[i] = new ASN1OctetString(values[i]);
    }
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name    The name for this attribute.  It must not be {@code null}.
   * @param  values  The set of values for this attribute.  It must not be
   *                 {@code null}.
   */
  public Attribute(@NotNull final String name, @NotNull final byte[]... values)
  {
    Validator.ensureNotNull(name, values);

    this.name = name;

    this.values = new ASN1OctetString[values.length];
    for (int i=0; i < values.length; i++)
    {
      this.values[i] = new ASN1OctetString(values[i]);
    }
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name    The name for this attribute.  It must not be {@code null}.
   * @param  values  The set of raw values for this attribute.  It must not be
   *                 {@code null}.
   */
  public Attribute(@NotNull final String name,
                   @NotNull final ASN1OctetString... values)
  {
    Validator.ensureNotNull(name, values);

    this.name   = name;
    this.values = values;

    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name    The name for this attribute.  It must not be {@code null}.
   * @param  values  The set of values for this attribute.  It must not be
   *                 {@code null}.
   */
  public Attribute(@NotNull final String name,
                   @NotNull final Collection<String> values)
  {
    Validator.ensureNotNull(name, values);

    this.name = name;

    this.values = new ASN1OctetString[values.size()];

    int i=0;
    for (final String s : values)
    {
      this.values[i++] = new ASN1OctetString(s);
    }
    matchingRule = CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Creates a new LDAP attribute with the specified name and no values.
   *
   * @param  name          The name for this attribute.  It must not be
   *                       {@code null}.
   * @param  matchingRule  The matching rule to use when comparing values.  It
   *                       must not be {@code null}.
   */
  public Attribute(@NotNull final String name,
                   @NotNull final MatchingRule matchingRule)
  {
    Validator.ensureNotNull(name, matchingRule);

    this.name         = name;
    this.matchingRule = matchingRule;

    values = NO_VALUES;
  }



  /**
   * Creates a new LDAP attribute with the specified name and value.
   *
   * @param  name          The name for this attribute.  It must not be
   *                       {@code null}.
   * @param  matchingRule  The matching rule to use when comparing values.  It
   *                       must not be {@code null}.
   * @param  value         The value for this attribute.  It must not be
   *                       {@code null}.
   */
  public Attribute(@NotNull final String name,
                   @NotNull final MatchingRule matchingRule,
                   @NotNull final String value)
  {
    Validator.ensureNotNull(name, matchingRule, value);

    this.name         = name;
    this.matchingRule = matchingRule;

    values = new ASN1OctetString[] { new ASN1OctetString(value) };
  }



  /**
   * Creates a new LDAP attribute with the specified name and value.
   *
   * @param  name          The name for this attribute.  It must not be
   *                       {@code null}.
   * @param  matchingRule  The matching rule to use when comparing values.  It
   *                       must not be {@code null}.
   * @param  value         The value for this attribute.  It must not be
   *                       {@code null}.
   */
  public Attribute(@NotNull final String name,
                   @NotNull final MatchingRule matchingRule,
                   @NotNull final byte[] value)
  {
    Validator.ensureNotNull(name, matchingRule, value);

    this.name         = name;
    this.matchingRule = matchingRule;

    values = new ASN1OctetString[] { new ASN1OctetString(value) };
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name          The name for this attribute.  It must not be
   *                       {@code null}.
   * @param  matchingRule  The matching rule to use when comparing values.  It
   *                       must not be {@code null}.
   * @param  values        The set of values for this attribute.  It must not be
   *                       {@code null}.
   */
  public Attribute(@NotNull final String name,
                   @NotNull final MatchingRule matchingRule,
                   @NotNull final String... values)
  {
    Validator.ensureNotNull(name, matchingRule, values);

    this.name         = name;
    this.matchingRule = matchingRule;

    this.values = new ASN1OctetString[values.length];
    for (int i=0; i < values.length; i++)
    {
      this.values[i] = new ASN1OctetString(values[i]);
    }
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name          The name for this attribute.  It must not be
   *                       {@code null}.
   * @param  matchingRule  The matching rule to use when comparing values.  It
   *                       must not be {@code null}.
   * @param  values        The set of values for this attribute.  It must not be
   *                       {@code null}.
   */
  public Attribute(@NotNull final String name,
                   @NotNull final MatchingRule matchingRule,
                   @NotNull final byte[]... values)
  {
    Validator.ensureNotNull(name, matchingRule, values);

    this.name         = name;
    this.matchingRule = matchingRule;

    this.values = new ASN1OctetString[values.length];
    for (int i=0; i < values.length; i++)
    {
      this.values[i] = new ASN1OctetString(values[i]);
    }
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name          The name for this attribute.  It must not be
   *                       {@code null}.
   * @param  matchingRule  The matching rule to use when comparing values.  It
   *                       must not be {@code null}.
   * @param  values        The set of values for this attribute.  It must not be
   *                       {@code null}.
   */
  public Attribute(@NotNull final String name,
                   @NotNull final MatchingRule matchingRule,
                   @NotNull final Collection<String> values)
  {
    Validator.ensureNotNull(name, matchingRule, values);

    this.name         = name;
    this.matchingRule = matchingRule;

    this.values = new ASN1OctetString[values.size()];

    int i=0;
    for (final String s : values)
    {
      this.values[i++] = new ASN1OctetString(s);
    }
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name          The name for this attribute.
   * @param  matchingRule  The matching rule for this attribute.
   * @param  values        The set of values for this attribute.
   */
  public Attribute(@NotNull final String name,
                   @NotNull final MatchingRule matchingRule,
                   @NotNull final ASN1OctetString[] values)
  {
    this.name         = name;
    this.matchingRule = matchingRule;
    this.values       = values;
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name    The name for this attribute.  It must not be {@code null}.
   * @param  schema  The schema to use to select the matching rule for this
   *                 attribute.  It may be {@code null} if the default matching
   *                 rule should be used.
   * @param  values  The set of values for this attribute.  It must not be
   *                 {@code null}.
   */
  public Attribute(@NotNull final String name, @Nullable final Schema schema,
                   @NotNull final String... values)
  {
    this(name, MatchingRule.selectEqualityMatchingRule(name, schema), values);
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name    The name for this attribute.  It must not be {@code null}.
   * @param  schema  The schema to use to select the matching rule for this
   *                 attribute.  It may be {@code null} if the default matching
   *                 rule should be used.
   * @param  values  The set of values for this attribute.  It must not be
   *                 {@code null}.
   */
  public Attribute(@NotNull final String name, @Nullable final Schema schema,
                   @NotNull final byte[]... values)
  {
    this(name, MatchingRule.selectEqualityMatchingRule(name, schema), values);
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name    The name for this attribute.  It must not be {@code null}.
   * @param  schema  The schema to use to select the matching rule for this
   *                 attribute.  It may be {@code null} if the default matching
   *                 rule should be used.
   * @param  values  The set of values for this attribute.  It must not be
   *                 {@code null}.
   */
  public Attribute(@NotNull final String name, @Nullable final Schema schema,
                   @NotNull final Collection<String> values)
  {
    this(name, MatchingRule.selectEqualityMatchingRule(name, schema), values);
  }



  /**
   * Creates a new LDAP attribute with the specified name and set of values.
   *
   * @param  name    The name for this attribute.  It must not be {@code null}.
   * @param  schema  The schema to use to select the matching rule for this
   *                 attribute.  It may be {@code null} if the default matching
   *                 rule should be used.
   * @param  values  The set of values for this attribute.  It must not be
   *                 {@code null}.
   */
  public Attribute(@NotNull final String name, @Nullable final Schema schema,
                   @NotNull final ASN1OctetString[] values)
  {
    this(name, MatchingRule.selectEqualityMatchingRule(name, schema), values);
  }



  /**
   * Creates a new attribute containing the merged values of the provided
   * attributes.  Any duplicate values will only be present once in the
   * resulting attribute.  The names of the provided attributes must be the
   * same.
   *
   * @param  attr1  The first attribute containing the values to merge.  It must
   *                not be {@code null}.
   * @param  attr2  The second attribute containing the values to merge.  It
   *                must not be {@code null}.
   *
   * @return  The new attribute containing the values of both of the
   *          provided attributes.
   */
  @NotNull()
  public static Attribute mergeAttributes(@NotNull final Attribute attr1,
                                          @NotNull final Attribute attr2)
  {
    return mergeAttributes(attr1, attr2, attr1.matchingRule);
  }



  /**
   * Creates a new attribute containing the merged values of the provided
   * attributes.  Any duplicate values will only be present once in the
   * resulting attribute.  The names of the provided attributes must be the
   * same.
   *
   * @param  attr1         The first attribute containing the values to merge.
   *                       It must not be {@code null}.
   * @param  attr2         The second attribute containing the values to merge.
   *                       It must not be {@code null}.
   * @param  matchingRule  The matching rule to use to locate matching values.
   *                       It may be {@code null} if the matching rule
   *                       associated with the first attribute should be used.
   *
   * @return  The new attribute containing the values of both of the
   *          provided attributes.
   */
  @NotNull()
  public static Attribute mergeAttributes(@NotNull final Attribute attr1,
                               @NotNull final Attribute attr2,
                               @Nullable final MatchingRule matchingRule)
  {
    Validator.ensureNotNull(attr1, attr2);

    final String name = attr1.name;
    Validator.ensureTrue(name.equalsIgnoreCase(attr2.name));

    final MatchingRule mr;
    if (matchingRule == null)
    {
      mr = attr1.matchingRule;
    }
    else
    {
      mr = matchingRule;
    }

    ASN1OctetString[] mergedValues =
         new ASN1OctetString[attr1.values.length + attr2.values.length];
    System.arraycopy(attr1.values, 0, mergedValues, 0, attr1.values.length);

    int pos = attr1.values.length;
    for (final ASN1OctetString attr2Value : attr2.values)
    {
      if (! attr1.hasValue(attr2Value, mr))
      {
        mergedValues[pos++] = attr2Value;
      }
    }

    if (pos != mergedValues.length)
    {
      // This indicates that there were duplicate values.
      final ASN1OctetString[] newMergedValues = new ASN1OctetString[pos];
      System.arraycopy(mergedValues, 0, newMergedValues, 0, pos);
      mergedValues = newMergedValues;
    }

    return new Attribute(name, mr, mergedValues);
  }



  /**
   * Creates a new attribute containing all of the values of the first attribute
   * that are not contained in the second attribute.  Any values contained in
   * the second attribute that are not contained in the first will be ignored.
   * The names of the provided attributes must be the same.
   *
   * @param  attr1  The attribute from which to remove the values.  It must not
   *                be {@code null}.
   * @param  attr2  The attribute containing the values to remove.  It must not
   *                be {@code null}.
   *
   * @return  A new attribute containing all of the values of the first
   *          attribute not contained in the second.  It may contain zero values
   *          if all the values of the first attribute were also contained in
   *          the second.
   */
  @NotNull()
  public static Attribute removeValues(@NotNull final Attribute attr1,
                                       @NotNull final Attribute attr2)
  {
    return removeValues(attr1, attr2, attr1.matchingRule);
  }



  /**
   * Creates a new attribute containing all of the values of the first attribute
   * that are not contained in the second attribute.  Any values contained in
   * the second attribute that are not contained in the first will be ignored.
   * The names of the provided attributes must be the same.
   *
   * @param  attr1         The attribute from which to remove the values.  It
   *                       must not be {@code null}.
   * @param  attr2         The attribute containing the values to remove.  It
   *                       must not be {@code null}.
   * @param  matchingRule  The matching rule to use to locate matching values.
   *                       It may be {@code null} if the matching rule
   *                       associated with the first attribute should be used.
   *
   * @return  A new attribute containing all of the values of the first
   *          attribute not contained in the second.  It may contain zero values
   *          if all the values of the first attribute were also contained in
   *          the second.
   */
  @NotNull()
  public static Attribute removeValues(@NotNull final Attribute attr1,
                               @NotNull final Attribute attr2,
                               @Nullable final MatchingRule matchingRule)
  {
    Validator.ensureNotNull(attr1, attr2);

    final String name = attr1.name;
    Validator.ensureTrue(name.equalsIgnoreCase(attr2.name));

    final MatchingRule mr;
    if (matchingRule == null)
    {
      mr = attr1.matchingRule;
    }
    else
    {
      mr = matchingRule;
    }

    final ArrayList<ASN1OctetString> newValues =
         new ArrayList<>(Arrays.asList(attr1.values));

    final Iterator<ASN1OctetString> iterator = newValues.iterator();
    while (iterator.hasNext())
    {
      if (attr2.hasValue(iterator.next(), mr))
      {
        iterator.remove();
      }
    }

    final ASN1OctetString[] newValueArray =
         new ASN1OctetString[newValues.size()];
    newValues.toArray(newValueArray);

    return new Attribute(name, mr, newValueArray);
  }



  /**
   * Retrieves the name for this attribute (i.e., the attribute description),
   * which may include zero or more attribute options.
   *
   * @return  The name for this attribute.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the base name for this attribute, which is the name or OID of the
   * attribute type, without any attribute options.  For an attribute without
   * any options, the value returned by this method will be identical the value
   * returned by the {@link #getName} method.
   *
   * @return  The base name for this attribute.
   */
  @NotNull()
  public String getBaseName()
  {
    return getBaseName(name);
  }



  /**
   * Retrieves the base name for an attribute with the given name, which will be
   * the provided name without any attribute options.  If the given name does
   * not include any attribute options, then it will be returned unaltered.  If
   * it does contain one or more attribute options, then the name will be
   * returned without those options.
   *
   * @param  name  The name to be processed.
   *
   * @return  The base name determined from the provided attribute name.
   */
  @NotNull()
  public static String getBaseName(@NotNull final String name)
  {
    final int semicolonPos = name.indexOf(';');
    if (semicolonPos > 0)
    {
      return name.substring(0, semicolonPos);
    }
    else
    {
      return name;
    }
  }



  /**
   * Indicates whether the name of this attribute is valid as per RFC 4512.  The
   * name will be considered valid only if it starts with an ASCII alphabetic
   * character ('a' through 'z', or 'A' through 'Z'), and contains only ASCII
   * alphabetic characters, ASCII numeric digits ('0' through '9'), and the
   * ASCII hyphen character ('-').  It will also be allowed to include zero or
   * more attribute options, in which the option must be separate from the base
   * name by a semicolon and has the same naming constraints as the base name.
   *
   * @return  {@code true} if this attribute has a valid name, or {@code false}
   *          if not.
   */
  public boolean nameIsValid()
  {
    return nameIsValid(name, true);
  }



  /**
   * Indicates whether the provided string represents a valid attribute name as
   * per RFC 4512.  It will be considered valid only if it starts with an ASCII
   * alphabetic character ('a' through 'z', or 'A' through 'Z'), and contains
   * only ASCII alphabetic characters, ASCII numeric digits ('0' through '9'),
   * and the ASCII hyphen character ('-').  It will also be allowed to include
   * zero or more attribute options, in which the option must be separate from
   * the base name by a semicolon and has the same naming constraints as the
   * base name.
   *
   * @param  s  The name for which to make the determination.
   *
   * @return  {@code true} if this attribute has a valid name, or {@code false}
   *          if not.
   */
  public static boolean nameIsValid(@NotNull final String s)
  {
    return nameIsValid(s, true);
  }



  /**
   * Indicates whether the provided string represents a valid attribute name as
   * per RFC 4512.  It will be considered valid only if it starts with an ASCII
   * alphabetic character ('a' through 'z', or 'A' through 'Z'), and contains
   * only ASCII alphabetic characters, ASCII numeric digits ('0' through '9'),
   * and the ASCII hyphen character ('-').  It may optionally be allowed to
   * include zero or more attribute options, in which the option must be
   * separate from the base name by a semicolon and has the same naming
   * constraints as the base name.
   *
   * @param  s             The name for which to make the determination.
   * @param  allowOptions  Indicates whether the provided name will be allowed
   *                       to contain attribute options.
   *
   * @return  {@code true} if this attribute has a valid name, or {@code false}
   *          if not.
   */
  public static boolean nameIsValid(@NotNull final String s,
                                    final boolean allowOptions)
  {
    final int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      return false;
    }

    final char firstChar = s.charAt(0);
    if (! (((firstChar >= 'a') && (firstChar <= 'z')) ||
          ((firstChar >= 'A') && (firstChar <= 'Z'))))
    {
      return false;
    }

    boolean lastWasSemiColon = false;
    for (int i=1; i < length; i++)
    {
      final char c = s.charAt(i);
      if (((c >= 'a') && (c <= 'z')) ||
          ((c >= 'A') && (c <= 'Z')))
      {
        // This will always be acceptable.
        lastWasSemiColon = false;
      }
      else if (((c >= '0') && (c <= '9')) ||
               (c == '-'))
      {
        // These will only be acceptable if the last character was not a
        // semicolon.
        if (lastWasSemiColon)
        {
          return false;
        }

        lastWasSemiColon = false;
      }
      else if (c == ';')
      {
        // This will only be acceptable if attribute options are allowed and the
        // last character was not a semicolon.
        if (lastWasSemiColon || (! allowOptions))
        {
          return false;
        }

        lastWasSemiColon = true;
      }
      else
      {
        return false;
      }
    }

    return (! lastWasSemiColon);
  }



  /**
   * Indicates whether this attribute has any attribute options.
   *
   * @return  {@code true} if this attribute has at least one attribute option,
   *          or {@code false} if not.
   */
  public boolean hasOptions()
  {
    return hasOptions(name);
  }



  /**
   * Indicates whether the provided attribute name contains any options.
   *
   * @param  name  The name for which to make the determination.
   *
   * @return  {@code true} if the provided attribute name has at least one
   *          attribute option, or {@code false} if not.
   */
  public static boolean hasOptions(@NotNull final String name)
  {
    return (name.indexOf(';') > 0);
  }



  /**
   * Indicates whether this attribute has the specified attribute option.
   *
   * @param  option  The attribute option for which to make the determination.
   *
   * @return  {@code true} if this attribute has the specified attribute option,
   *          or {@code false} if not.
   */
  public boolean hasOption(@NotNull final String option)
  {
    return hasOption(name, option);
  }



  /**
   * Indicates whether the provided attribute name has the specified attribute
   * option.
   *
   * @param  name    The name to be examined.
   * @param  option  The attribute option for which to make the determination.
   *
   * @return  {@code true} if the provided attribute name has the specified
   *          attribute option, or {@code false} if not.
   */
  public static boolean hasOption(@NotNull final String name,
                                  @NotNull final String option)
  {
    final Set<String> options = getOptions(name);
    for (final String s : options)
    {
      if (s.equalsIgnoreCase(option))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Retrieves the set of options for this attribute.
   *
   * @return  The set of options for this attribute, or an empty set if there
   *          are none.
   */
  @NotNull()
  public Set<String> getOptions()
  {
    return getOptions(name);
  }



  /**
   * Retrieves the set of options for the provided attribute name.
   *
   * @param  name  The name to be examined.
   *
   * @return  The set of options for the provided attribute name, or an empty
   *          set if there are none.
   */
  @NotNull()
  public static Set<String> getOptions(@NotNull final String name)
  {
    int semicolonPos = name.indexOf(';');
    if (semicolonPos > 0)
    {
      final LinkedHashSet<String> options =
           new LinkedHashSet<>(StaticUtils.computeMapCapacity(5));
      while (true)
      {
        final int nextSemicolonPos = name.indexOf(';', semicolonPos+1);
        if (nextSemicolonPos > 0)
        {
          options.add(name.substring(semicolonPos+1, nextSemicolonPos));
          semicolonPos = nextSemicolonPos;
        }
        else
        {
          options.add(name.substring(semicolonPos+1));
          break;
        }
      }

      return Collections.unmodifiableSet(options);
    }
    else
    {
      return Collections.emptySet();
    }
  }



  /**
   * Retrieves the matching rule instance used by this attribute.
   *
   * @return  The matching rule instance used by this attribute.
   */
  @NotNull()
  public MatchingRule getMatchingRule()
  {
    return matchingRule;
  }



  /**
   * Retrieves the value for this attribute as a string.  If this attribute has
   * multiple values, then the first value will be returned.
   *
   * @return  The value for this attribute, or {@code null} if this attribute
   *          does not have any values.
   */
  @Nullable()
  public String getValue()
  {
    if (values.length == 0)
    {
      return null;
    }

    return values[0].stringValue();
  }



  /**
   * Retrieves the value for this attribute as a byte array.  If this attribute
   * has multiple values, then the first value will be returned.  The returned
   * array must not be altered by the caller.
   *
   * @return  The value for this attribute, or {@code null} if this attribute
   *          does not have any values.
   */
  @Nullable()
  public byte[] getValueByteArray()
  {
    if (values.length == 0)
    {
      return null;
    }

    return values[0].getValue();
  }



  /**
   * Retrieves the value for this attribute as a Boolean.  If this attribute has
   * multiple values, then the first value will be examined.  Values of "true",
   * "t", "yes", "y", "on", and "1" will be interpreted as {@code TRUE}.  Values
   * of "false", "f", "no", "n", "off", and "0" will be interpreted as
   * {@code FALSE}.
   *
   * @return  The Boolean value for this attribute, or {@code null} if this
   *          attribute does not have any values or the value cannot be parsed
   *          as a Boolean.
   */
  @Nullable()
  public Boolean getValueAsBoolean()
  {
    if (values.length == 0)
    {
      return null;
    }

    final String lowerValue = StaticUtils.toLowerCase(values[0].stringValue());
    if (lowerValue.equals("true") || lowerValue.equals("t") ||
        lowerValue.equals("yes") || lowerValue.equals("y") ||
        lowerValue.equals("on") || lowerValue.equals("1"))
    {
      return Boolean.TRUE;
    }
    else if (lowerValue.equals("false") || lowerValue.equals("f") ||
             lowerValue.equals("no") || lowerValue.equals("n") ||
             lowerValue.equals("off") || lowerValue.equals("0"))
    {
      return Boolean.FALSE;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves the value for this attribute as a Date, formatted using the
   * generalized time syntax.  If this attribute has multiple values, then the
   * first value will be examined.
   *
   * @return  The Date value for this attribute, or {@code null} if this
   *          attribute does not have any values or the value cannot be parsed
   *          as a Date.
   */
  @Nullable()
  public Date getValueAsDate()
  {
    if (values.length == 0)
    {
      return null;
    }

    try
    {
      return StaticUtils.decodeGeneralizedTime(values[0].stringValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the value for this attribute as a DN.  If this attribute has
   * multiple values, then the first value will be examined.
   *
   * @return  The DN value for this attribute, or {@code null} if this attribute
   *          does not have any values or the value cannot be parsed as a DN.
   */
  @Nullable()
  public DN getValueAsDN()
  {
    if (values.length == 0)
    {
      return null;
    }

    try
    {
      return new DN(values[0].stringValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the value for this attribute as an Integer.  If this attribute
   * has multiple values, then the first value will be examined.
   *
   * @return  The Integer value for this attribute, or {@code null} if this
   *          attribute does not have any values or the value cannot be parsed
   *          as an Integer.
   */
  @Nullable()
  public Integer getValueAsInteger()
  {
    if (values.length == 0)
    {
      return null;
    }

    try
    {
      return Integer.valueOf(values[0].stringValue());
    }
    catch (final NumberFormatException nfe)
    {
      Debug.debugException(nfe);
      return null;
    }
  }



  /**
   * Retrieves the value for this attribute as a Long.  If this attribute has
   * multiple values, then the first value will be examined.
   *
   * @return  The Long value for this attribute, or {@code null} if this
   *          attribute does not have any values or the value cannot be parsed
   *          as a Long.
   */
  @Nullable()
  public Long getValueAsLong()
  {
    if (values.length == 0)
    {
      return null;
    }

    try
    {
      return Long.valueOf(values[0].stringValue());
    }
    catch (final NumberFormatException nfe)
    {
      Debug.debugException(nfe);
      return null;
    }
  }



  /**
   * Retrieves the set of values for this attribute as strings.  The returned
   * array must not be altered by the caller.
   *
   * @return  The set of values for this attribute, or an empty array if it does
   *          not have any values.
   */
  @NotNull()
  public String[] getValues()
  {
    if (values.length == 0)
    {
      return StaticUtils.NO_STRINGS;
    }

    final String[] stringValues = new String[values.length];
    for (int i=0; i < values.length; i++)
    {
      stringValues[i] = values[i].stringValue();
    }

    return stringValues;
  }



  /**
   * Retrieves the set of values for this attribute as byte arrays.  The
   * returned array must not be altered by the caller.
   *
   * @return  The set of values for this attribute, or an empty array if it does
   *          not have any values.
   */
  @NotNull()
  public byte[][] getValueByteArrays()
  {
    if (values.length == 0)
    {
      return NO_BYTE_VALUES;
    }

    final byte[][] byteValues = new byte[values.length][];
    for (int i=0; i < values.length; i++)
    {
      byteValues[i] = values[i].getValue();
    }

    return byteValues;
  }



  /**
   * Retrieves the set of values for this attribute as an array of ASN.1 octet
   * strings.  The returned array must not be altered by the caller.
   *
   * @return  The set of values for this attribute as an array of ASN.1 octet
   *          strings.
   */
  @NotNull()
  public ASN1OctetString[] getRawValues()
  {
    return values;
  }



  /**
   * Indicates whether this attribute contains at least one value.
   *
   * @return  {@code true} if this attribute has at least one value, or
   *          {@code false} if not.
   */
  public boolean hasValue()
  {
    return (values.length > 0);
  }



  /**
   * Indicates whether this attribute contains the specified value.
   *
   * @param  value  The value for which to make the determination.  It must not
   *                be {@code null}.
   *
   * @return  {@code true} if this attribute has the specified value, or
   *          {@code false} if not.
   */
  public boolean hasValue(@NotNull final String value)
  {
    Validator.ensureNotNull(value);

    return hasValue(new ASN1OctetString(value), matchingRule);
  }



  /**
   * Indicates whether this attribute contains the specified value.
   *
   * @param  value         The value for which to make the determination.  It
   *                       must not be {@code null}.
   * @param  matchingRule  The matching rule to use when making the
   *                       determination.  It must not be {@code null}.
   *
   * @return  {@code true} if this attribute has the specified value, or
   *          {@code false} if not.
   */
  public boolean hasValue(@NotNull final String value,
                          @NotNull final MatchingRule matchingRule)
  {
    Validator.ensureNotNull(value);

    return hasValue(new ASN1OctetString(value), matchingRule);
  }



  /**
   * Indicates whether this attribute contains the specified value.
   *
   * @param  value  The value for which to make the determination.  It must not
   *                be {@code null}.
   *
   * @return  {@code true} if this attribute has the specified value, or
   *          {@code false} if not.
   */
  public boolean hasValue(@NotNull final byte[] value)
  {
    Validator.ensureNotNull(value);

    return hasValue(new ASN1OctetString(value), matchingRule);
  }



  /**
   * Indicates whether this attribute contains the specified value.
   *
   * @param  value         The value for which to make the determination.  It
   *                       must not be {@code null}.
   * @param  matchingRule  The matching rule to use when making the
   *                       determination.  It must not be {@code null}.
   *
   * @return  {@code true} if this attribute has the specified value, or
   *          {@code false} if not.
   */
  public boolean hasValue(@NotNull final byte[] value,
                          @NotNull final MatchingRule matchingRule)
  {
    Validator.ensureNotNull(value);

    return hasValue(new ASN1OctetString(value), matchingRule);
  }



  /**
   * Indicates whether this attribute contains the specified value.
   *
   * @param  value  The value for which to make the determination.
   *
   * @return  {@code true} if this attribute has the specified value, or
   *          {@code false} if not.
   */
  boolean hasValue(@NotNull final ASN1OctetString value)
  {
    return hasValue(value, matchingRule);
  }



  /**
   * Indicates whether this attribute contains the specified value.
   *
   * @param  value         The value for which to make the determination.  It
   *                       must not be {@code null}.
   * @param  matchingRule  The matching rule to use when making the
   *                       determination.  It must not be {@code null}.
   *
   * @return  {@code true} if this attribute has the specified value, or
   *          {@code false} if not.
   */
  boolean hasValue(@NotNull final ASN1OctetString value,
                   @NotNull final MatchingRule matchingRule)
  {
    try
    {
      return matchingRule.matchesAnyValue(value, values);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      // This probably means that the provided value cannot be normalized.  In
      // that case, we'll fall back to a byte-for-byte comparison of the values.
      for (final ASN1OctetString existingValue : values)
      {
        if (value.equalsIgnoreType(existingValue))
        {
          return true;
        }
      }

      return false;
    }
  }



  /**
   * Retrieves the number of values for this attribute.
   *
   * @return  The number of values for this attribute.
   */
  public int size()
  {
    return values.length;
  }



  /**
   * Writes an ASN.1-encoded representation of this attribute to the provided
   * ASN.1 buffer.
   *
   * @param  buffer  The ASN.1 buffer to which the encoded representation should
   *                 be written.
   */
  public void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    buffer.addOctetString(name);

    final ASN1BufferSet valueSet = buffer.beginSet();
    for (final ASN1OctetString value : values)
    {
      buffer.addElement(value);
    }
    valueSet.end();
    attrSequence.end();
  }



  /**
   * Encodes this attribute into a form suitable for use in the LDAP protocol.
   * It will be encoded as a sequence containing the attribute name (as an octet
   * string) and a set of values.
   *
   * @return  An ASN.1 sequence containing the encoded attribute.
   */
  @NotNull()
  public ASN1Sequence encode()
  {
    final ASN1Element[] elements =
    {
      new ASN1OctetString(name),
      new ASN1Set(values)
    };

    return new ASN1Sequence(elements);
  }



  /**
   * Reads and decodes an attribute from the provided ASN.1 stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the attribute.
   *
   * @return  The decoded attribute.
   *
   * @throws  LDAPException  If a problem occurs while trying to read or decode
   *                         the attribute.
   */
  @NotNull()
  public static Attribute readFrom(@NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    return readFrom(reader, null);
  }



  /**
   * Reads and decodes an attribute from the provided ASN.1 stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the attribute.
   * @param  schema  The schema to use to select the appropriate matching rule
   *                 for this attribute.  It may be {@code null} if the default
   *                 matching rule should be selected.
   *
   * @return  The decoded attribute.
   *
   * @throws  LDAPException  If a problem occurs while trying to read or decode
   *                         the attribute.
   */
  @NotNull()
  public static Attribute readFrom(@NotNull final ASN1StreamReader reader,
                                   @Nullable final Schema schema)
         throws LDAPException
  {
    try
    {
      Validator.ensureNotNull(reader.beginSequence());
      final String attrName = reader.readString();
      Validator.ensureNotNull(attrName);

      final MatchingRule matchingRule =
           MatchingRule.selectEqualityMatchingRule(attrName, schema);

      final ArrayList<ASN1OctetString> valueList = new ArrayList<>(10);
      final ASN1StreamReaderSet valueSet = reader.beginSet();
      while (valueSet.hasMoreElements())
      {
        valueList.add(new ASN1OctetString(reader.readBytes()));
      }

      final ASN1OctetString[] values = new ASN1OctetString[valueList.size()];
      valueList.toArray(values);

      return new Attribute(attrName, matchingRule, values);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ATTR_CANNOT_DECODE.get(StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Decodes the provided ASN.1 sequence as an LDAP attribute.
   *
   * @param  encodedAttribute  The ASN.1 sequence to be decoded as an LDAP
   *                           attribute.  It must not be {@code null}.
   *
   * @return  The decoded LDAP attribute.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided ASN.1 sequence as an LDAP attribute.
   */
  @NotNull()
  public static Attribute decode(@NotNull final ASN1Sequence encodedAttribute)
         throws LDAPException
  {
    Validator.ensureNotNull(encodedAttribute);

    final ASN1Element[] elements = encodedAttribute.elements();
    if (elements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_ATTR_DECODE_INVALID_COUNT.get(elements.length));
    }

    final String name =
         ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

    final ASN1Set valueSet;
    try
    {
      valueSet = ASN1Set.decodeAsSet(elements[1]);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ATTR_DECODE_VALUE_SET.get(StaticUtils.getExceptionMessage(ae)),
           ae);
    }

    final ASN1OctetString[] values =
         new ASN1OctetString[valueSet.elements().length];
    for (int i=0; i < values.length; i++)
    {
      values[i] = ASN1OctetString.decodeAsOctetString(valueSet.elements()[i]);
    }

    return new Attribute(name, CaseIgnoreStringMatchingRule.getInstance(),
                         values);
  }



  /**
   * Indicates whether any of the values of this attribute need to be
   * base64-encoded when represented as LDIF.
   *
   * @return  {@code true} if any of the values of this attribute need to be
   *          base64-encoded when represented as LDIF, or {@code false} if not.
   */
  public boolean needsBase64Encoding()
  {
    for (final ASN1OctetString v : values)
    {
      if (needsBase64Encoding(v.getValue()))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Indicates whether the provided value needs to be base64-encoded when
   * represented as LDIF.
   *
   * @param  v  The value for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided value needs to be base64-encoded when
   *          represented as LDIF, or {@code false} if not.
   */
  public static boolean needsBase64Encoding(@NotNull final String v)
  {
    return needsBase64Encoding(StaticUtils.getBytes(v));
  }



  /**
   * Indicates whether the provided value needs to be base64-encoded when
   * represented as LDIF.
   *
   * @param  v  The value for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided value needs to be base64-encoded when
   *          represented as LDIF, or {@code false} if not.
   */
  public static boolean needsBase64Encoding(@NotNull final byte[] v)
  {
    if (v.length == 0)
    {
      return false;
    }

    switch (v[0] & 0xFF)
    {
      case 0x20: // Space
      case 0x3A: // Colon
      case 0x3C: // Less-than
        return true;
    }

    if ((v[v.length-1] & 0xFF) == 0x20)
    {
      return true;
    }

    for (final byte b : v)
    {
      switch (b & 0xFF)
      {
        case 0x00: // NULL
        case 0x0A: // LF
        case 0x0D: // CR
          return true;

        default:
          if ((b & 0x80) != 0x00)
          {
            return true;
          }
          break;
      }
    }

    return false;
  }



  /**
   * Generates a hash code for this LDAP attribute.  It will be the sum of the
   * hash codes for the lowercase attribute name and the normalized values.
   *
   * @return  The generated hash code for this LDAP attribute.
   */
  @Override()
  public int hashCode()
  {
    if (hashCode == -1)
    {
      int c = StaticUtils.toLowerCase(name).hashCode();

      for (final ASN1OctetString value : values)
      {
        try
        {
          c += matchingRule.normalize(value).hashCode();
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          c += value.hashCode();
        }
      }

      hashCode = c;
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this LDAP attribute.  The
   * object will be considered equal to this LDAP attribute only if it is an
   * LDAP attribute with the same name and set of values.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object may be considered equal to
   *          this LDAP attribute, or {@code false} if not.
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

    if (! (o instanceof Attribute))
    {
      return false;
    }

    final Attribute a = (Attribute) o;
    if (! name.equalsIgnoreCase(a.name))
    {
      return false;
    }

    if (values.length != a.values.length)
    {
      return false;
    }

    // For a small set of values, we can just iterate through the values of one
    // and see if they are all present in the other.  However, that can be very
    // expensive for a large set of values, so we'll try to go with a more
    // efficient approach.
    if (values.length > 10)
    {
      // First, create a hash set containing the un-normalized values of the
      // first attribute.
      final HashSet<ASN1OctetString> unNormalizedValues =
           StaticUtils.hashSetOf(values);

      // Next, iterate through the values of the second attribute.  For any
      // values that exist in the un-normalized set, remove them from that
      // set.  For any values that aren't in the un-normalized set, create a
      // new set with the normalized representations of those values.
      HashSet<ASN1OctetString> normalizedMissingValues = null;
      for (final ASN1OctetString value : a.values)
      {
        if (! unNormalizedValues.remove(value))
        {
          if (normalizedMissingValues == null)
          {
            normalizedMissingValues =
                 new HashSet<>(StaticUtils.computeMapCapacity(values.length));
          }

          try
          {
            normalizedMissingValues.add(matchingRule.normalize(value));
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            return false;
          }
        }
      }

      // If the un-normalized set is empty, then that means all the values
      // exactly match without the need to compare the normalized
      // representations.  For any values that are left, then we will need to
      // compare their normalized representations.
      if (normalizedMissingValues != null)
      {
        for (final ASN1OctetString value : unNormalizedValues)
        {
          try
          {
            if (! normalizedMissingValues.contains(
                       matchingRule.normalize(value)))
            {
              return false;
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            return false;
          }
        }
      }
    }
    else
    {
      for (final ASN1OctetString value : values)
      {
        if (! a.hasValue(value))
        {
          return false;
        }
      }
    }


    // If we've gotten here, then we can consider them equal.
    return true;
  }



  /**
   * Retrieves a string representation of this LDAP attribute.
   *
   * @return  A string representation of this LDAP attribute.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this LDAP attribute to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation of this LDAP
   *                 attribute should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("Attribute(name=");
    buffer.append(name);

    if (values.length == 0)
    {
      buffer.append(", values={");
    }
    else if (needsBase64Encoding())
    {
      buffer.append(", base64Values={'");

      for (int i=0; i < values.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }

        buffer.append(Base64.encode(values[i].getValue()));
      }

      buffer.append('\'');
    }
    else
    {
      buffer.append(", values={'");

      for (int i=0; i < values.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }

        buffer.append(values[i].stringValue());
      }

      buffer.append('\'');
    }

    buffer.append("})");
  }
}
