/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.transformations;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import com.unboundid.ldap.matchingrules.BooleanMatchingRule;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.matchingrules.DistinguishedNameMatchingRule;
import com.unboundid.ldap.matchingrules.GeneralizedTimeMatchingRule;
import com.unboundid.ldap.matchingrules.IntegerMatchingRule;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.matchingrules.NumericStringMatchingRule;
import com.unboundid.ldap.matchingrules.OctetStringMatchingRule;
import com.unboundid.ldap.matchingrules.TelephoneNumberMatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadLocalRandom;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;



/**
 * This class provides an implementation of an entry and change record
 * transformation that may be used to scramble the values of a specified set of
 * attributes in a way that attempts to obscure the original values but that
 * preserves the syntax for the values.  When possible the scrambling will be
 * performed in a repeatable manner, so that a given input value will
 * consistently yield the same scrambled representation.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ScrambleAttributeTransformation
       implements EntryTransformation, LDIFChangeRecordTransformation
{
  /**
   * The characters in the set of ASCII numeric digits.
   */
  @NotNull private static final char[] ASCII_DIGITS =
       "0123456789".toCharArray();



  /**
   * The set of ASCII symbols, which are printable ASCII characters that are not
   * letters or digits.
   */
  @NotNull private static final char[] ASCII_SYMBOLS =
       " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".toCharArray();



  /**
   * The characters in the set of lowercase ASCII letters.
   */
  @NotNull private static final char[] LOWERCASE_ASCII_LETTERS =
       "abcdefghijklmnopqrstuvwxyz".toCharArray();



  /**
   * The characters in the set of uppercase ASCII letters.
   */
  @NotNull private static final char[] UPPERCASE_ASCII_LETTERS =
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();



  /**
   * The number of milliseconds in a day.
   */
  private static final long MILLIS_PER_DAY =
       1000L * // 1000 milliseconds per second
       60L *   // 60 seconds per minute
       60L *   // 60 minutes per hour
       24L;    // 24 hours per day



  // Indicates whether to scramble attribute values in entry DNs.
  private final boolean scrambleEntryDNs;

  // The seed to use for the random number generator.
  private final long randomSeed;

  // The time this transformation was created.
  private final long createTime;

  // The schema to use when processing.
  @Nullable private final Schema schema;

  // The names of the attributes to scramble.
  @NotNull private final Map<String,MatchingRule> attributes;

  // The names of the JSON fields to scramble.
  @NotNull private final Set<String> jsonFields;

  // A thread-local collection of reusable random number generators.
  @NotNull private final ThreadLocal<Random> randoms;



  /**
   * Creates a new scramble attribute transformation that will scramble the
   * values of the specified attributes.  A default standard schema will be
   * used, entry DNs will not be scrambled, and if any of the target attributes
   * have values that are JSON objects, the values of all of those objects'
   * fields will be scrambled.
   *
   * @param  attributes  The names or OIDs of the attributes to scramble.
   */
  public ScrambleAttributeTransformation(@NotNull final String... attributes)
  {
    this(null, null, attributes);
  }



  /**
   * Creates a new scramble attribute transformation that will scramble the
   * values of the specified attributes.  A default standard schema will be
   * used, entry DNs will not be scrambled, and if any of the target attributes
   * have values that are JSON objects, the values of all of those objects'
   * fields will be scrambled.
   *
   * @param  attributes  The names or OIDs of the attributes to scramble.
   */
  public ScrambleAttributeTransformation(
              @NotNull final Collection<String> attributes)
  {
    this(null, null, false, attributes, null);
  }



  /**
   * Creates a new scramble attribute transformation that will scramble the
   * values of a specified set of attributes.  Entry DNs will not be scrambled,
   * and if any of the target attributes have values that are JSON objects, the
   * values of all of those objects' fields will be scrambled.
   *
   * @param  schema      The schema to use when processing.  This may be
   *                     {@code null} if a default standard schema should be
   *                     used.  The schema will be used to identify alternate
   *                     names that may be used to reference the attributes, and
   *                     to determine the expected syntax for more accurate
   *                     scrambling.
   * @param  randomSeed  The seed to use for the random number generator when
   *                     scrambling each value.  It may be {@code null} if the
   *                     random seed should be automatically selected.
   * @param  attributes  The names or OIDs of the attributes to scramble.
   */
  public ScrambleAttributeTransformation(@Nullable final Schema schema,
                                         @Nullable final Long randomSeed,
                                         @NotNull final String... attributes)
  {
    this(schema, randomSeed, false, StaticUtils.toList(attributes), null);
  }



  /**
   * Creates a new scramble attribute transformation that will scramble the
   * values of a specified set of attributes.
   *
   * @param  schema            The schema to use when processing.  This may be
   *                           {@code null} if a default standard schema should
   *                           be used.  The schema will be used to identify
   *                           alternate names that may be used to reference the
   *                           attributes, and to determine the expected syntax
   *                           for more accurate scrambling.
   * @param  randomSeed        The seed to use for the random number generator
   *                           when scrambling each value.  It may be
   *                           {@code null} if the random seed should be
   *                           automatically selected.
   * @param  scrambleEntryDNs  Indicates whether to scramble any appropriate
   *                           attributes contained in entry DNs and the values
   *                           of attributes with a DN syntax.
   * @param  attributes        The names or OIDs of the attributes to scramble.
   * @param  jsonFields        The names of the JSON fields whose values should
   *                           be scrambled.  If any field names are specified,
   *                           then any JSON objects to be scrambled will only
   *                           have those fields scrambled (with field names
   *                           treated in a case-insensitive manner) and all
   *                           other fields will be preserved without
   *                           scrambling.  If this is {@code null} or empty,
   *                           then scrambling will be applied for all values in
   *                           all fields.
   */
  public ScrambleAttributeTransformation(@Nullable final Schema schema,
              @Nullable final Long randomSeed,
              final boolean scrambleEntryDNs,
              @NotNull final Collection<String> attributes,
              @Nullable final Collection<String> jsonFields)
  {
    createTime = System.currentTimeMillis();
    randoms = new ThreadLocal<>();

    this.scrambleEntryDNs = scrambleEntryDNs;


    // If a random seed was provided, then use it.  Otherwise, select one.
    if (randomSeed == null)
    {
      this.randomSeed = ThreadLocalRandom.get().nextLong();
    }
    else
    {
      this.randomSeed = randomSeed;
    }


    // If a schema was provided, then use it.  Otherwise, use the default
    // standard schema.
    Schema s = schema;
    if (s == null)
    {
      try
      {
        s = Schema.getDefaultStandardSchema();
      }
      catch (final Exception e)
      {
        // This should never happen.
        Debug.debugException(e);
      }
    }
    this.schema = s;


    // Iterate through the set of provided attribute names.  Identify all of the
    // alternate names (including the OID) that may be used to reference the
    // attribute, and identify the associated matching rule.
    final HashMap<String,MatchingRule> m =
         new HashMap<>(StaticUtils.computeMapCapacity(10));
    for (final String a : attributes)
    {
      final String baseName = StaticUtils.toLowerCase(Attribute.getBaseName(a));

      AttributeTypeDefinition at = null;
      if (schema != null)
      {
        at = schema.getAttributeType(baseName);
      }

      if (at == null)
      {
        m.put(baseName, CaseIgnoreStringMatchingRule.getInstance());
      }
      else
      {
        final MatchingRule mr =
             MatchingRule.selectEqualityMatchingRule(baseName, schema);
        m.put(StaticUtils.toLowerCase(at.getOID()), mr);
        for (final String attrName : at.getNames())
        {
          m.put(StaticUtils.toLowerCase(attrName), mr);
        }
      }
    }
    this.attributes = Collections.unmodifiableMap(m);


    // See if any JSON fields were specified.  If so, then process them.
    if (jsonFields == null)
    {
      this.jsonFields = Collections.emptySet();
    }
    else
    {
      final HashSet<String> fieldNames =
           new HashSet<>(StaticUtils.computeMapCapacity(jsonFields.size()));
      for (final String fieldName : jsonFields)
      {
        fieldNames.add(StaticUtils.toLowerCase(fieldName));
      }
      this.jsonFields = Collections.unmodifiableSet(fieldNames);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry transformEntry(@NotNull final Entry e)
  {
    if (e == null)
    {
      return null;
    }

    final String dn;
    if (scrambleEntryDNs)
    {
      dn = scrambleDN(e.getDN());
    }
    else
    {
      dn = e.getDN();
    }

    final Collection<Attribute> originalAttributes = e.getAttributes();
    final ArrayList<Attribute> scrambledAttributes =
         new ArrayList<>(originalAttributes.size());

    for (final Attribute a : originalAttributes)
    {
      scrambledAttributes.add(scrambleAttribute(a));
    }

    return new Entry(dn, schema, scrambledAttributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public LDIFChangeRecord transformChangeRecord(
                               @NotNull final LDIFChangeRecord r)
  {
    if (r == null)
    {
      return null;
    }


    // If it's an add change record, then just use the same processing as for an
    // entry.
    if (r instanceof LDIFAddChangeRecord)
    {
      final LDIFAddChangeRecord addRecord = (LDIFAddChangeRecord) r;
      return new LDIFAddChangeRecord(transformEntry(addRecord.getEntryToAdd()),
           addRecord.getControls());
    }


    // If it's a delete change record, then see if we need to scramble the DN.
    if (r instanceof LDIFDeleteChangeRecord)
    {
      if (scrambleEntryDNs)
      {
        return new LDIFDeleteChangeRecord(scrambleDN(r.getDN()),
             r.getControls());
      }
      else
      {
        return r;
      }
    }


    // If it's a modify change record, then scramble all of the appropriate
    // modification values.
    if (r instanceof LDIFModifyChangeRecord)
    {
      final LDIFModifyChangeRecord modifyRecord = (LDIFModifyChangeRecord) r;

      final Modification[] originalMods = modifyRecord.getModifications();
      final Modification[] newMods = new Modification[originalMods.length];

      for (int i=0; i < originalMods.length; i++)
      {
        // If the modification doesn't have any values, then just use the
        // original modification.
        final Modification m = originalMods[i];
        if (! m.hasValue())
        {
          newMods[i] = m;
          continue;
        }


        // See if the modification targets an attribute that we should scramble.
        // If not, then just use the original modification.
        final String attrName = StaticUtils.toLowerCase(
             Attribute.getBaseName(m.getAttributeName()));
        if (! attributes.containsKey(attrName))
        {
          newMods[i] = m;
          continue;
        }


        // Scramble the values just like we do for an attribute.
        final Attribute scrambledAttribute =
             scrambleAttribute(m.getAttribute());
        newMods[i] = new Modification(m.getModificationType(),
             m.getAttributeName(), scrambledAttribute.getRawValues());
      }

      if (scrambleEntryDNs)
      {
        return new LDIFModifyChangeRecord(scrambleDN(modifyRecord.getDN()),
             newMods, modifyRecord.getControls());
      }
      else
      {
        return new LDIFModifyChangeRecord(modifyRecord.getDN(), newMods,
             modifyRecord.getControls());
      }
    }


    // If it's a modify DN change record, then see if we need to scramble any
    // of the components.
    if (r instanceof LDIFModifyDNChangeRecord)
    {
      if (scrambleEntryDNs)
      {
        final LDIFModifyDNChangeRecord modDNRecord =
             (LDIFModifyDNChangeRecord) r;
        return new LDIFModifyDNChangeRecord(scrambleDN(modDNRecord.getDN()),
             scrambleDN(modDNRecord.getNewRDN()), modDNRecord.deleteOldRDN(),
             scrambleDN(modDNRecord.getNewSuperiorDN()),
             modDNRecord.getControls());
      }
      else
      {
        return r;
      }
    }


    // This should never happen.
    return r;
  }



  /**
   * Creates a scrambled copy of the provided DN.  If the DN contains any
   * components with attributes to be scrambled, then the values of those
   * attributes will be scrambled appropriately.  If the DN does not contain
   * any components with attributes to be scrambled, then no changes will be
   * made.
   *
   * @param  dn  The DN to be scrambled.
   *
   * @return  A scrambled copy of the provided DN, or the original DN if no
   *          scrambling is required or the provided string cannot be parsed as
   *          a valid DN.
   */
  @Nullable()
  public String scrambleDN(@Nullable() final String dn)
  {
    if (dn == null)
    {
      return null;
    }

    try
    {
      return scrambleDN(new DN(dn)).toString();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return dn;
    }
  }



  /**
   * Creates a scrambled copy of the provided DN.  If the DN contains any
   * components with attributes to be scrambled, then the values of those
   * attributes will be scrambled appropriately.  If the DN does not contain
   * any components with attributes to be scrambled, then no changes will be
   * made.
   *
   * @param  dn  The DN to be scrambled.
   *
   * @return  A scrambled copy of the provided DN, or the original DN if no
   *          scrambling is required.
   */
  @Nullable()
  public DN scrambleDN(@Nullable final DN dn)
  {
    if ((dn == null) || dn.isNullDN())
    {
      return dn;
    }

    boolean changeApplied = false;
    final RDN[] originalRDNs = dn.getRDNs();
    final RDN[] scrambledRDNs = new RDN[originalRDNs.length];
    for (int i=0; i < originalRDNs.length; i++)
    {
      scrambledRDNs[i] = scrambleRDN(originalRDNs[i]);
      if (scrambledRDNs[i] != originalRDNs[i])
      {
        changeApplied = true;
      }
    }

    if (changeApplied)
    {
      return new DN(scrambledRDNs);
    }
    else
    {
      return dn;
    }
  }



  /**
   * Creates a scrambled copy of the provided RDN.  If the RDN contains any
   * attributes to be scrambled, then the values of those attributes will be
   * scrambled appropriately.  If the RDN does not contain any attributes to be
   * scrambled, then no changes will be made.
   *
   * @param  rdn  The RDN to be scrambled.  It must not be {@code null}.
   *
   * @return  A scrambled copy of the provided RDN, or the original RDN if no
   *          scrambling is required.
   */
  @NotNull()
  public RDN scrambleRDN(@NotNull final RDN rdn)
  {
    boolean changeRequired = false;
    final String[] names = rdn.getAttributeNames();
    for (final String s : names)
    {
      final String lowerBaseName =
           StaticUtils.toLowerCase(Attribute.getBaseName(s));
      if (attributes.containsKey(lowerBaseName))
      {
        changeRequired = true;
        break;
      }
    }

    if (! changeRequired)
    {
      return rdn;
    }

    final Attribute[] originalAttrs = rdn.getAttributes();
    final byte[][] scrambledValues = new byte[originalAttrs.length][];
    for (int i=0; i < originalAttrs.length; i++)
    {
      scrambledValues[i] =
           scrambleAttribute(originalAttrs[i]).getValueByteArray();
    }

    return new RDN(names, scrambledValues, schema);
  }



  /**
   * Creates a copy of the provided attribute with its values scrambled if
   * appropriate.
   *
   * @param  a  The attribute to scramble.
   *
   * @return  A copy of the provided attribute with its values scrambled, or
   *          the original attribute if no scrambling should be performed.
   */
  @Nullable()
  public Attribute scrambleAttribute(@NotNull final Attribute a)
  {
    if ((a == null) || (a.size() == 0))
    {
      return a;
    }

    final String baseName = StaticUtils.toLowerCase(a.getBaseName());
    final MatchingRule matchingRule = attributes.get(baseName);
    if (matchingRule == null)
    {
      return a;
    }

    if (matchingRule instanceof BooleanMatchingRule)
    {
      // In the case of a boolean value, we won't try to create reproducible
      // results.  We will just  pick boolean values at random.
      if (a.size() == 1)
      {
        return new Attribute(a.getName(), schema,
             ThreadLocalRandom.get().nextBoolean() ? "TRUE" : "FALSE");
      }
      else
      {
        // This is highly unusual, but since there are only two possible valid
        // boolean values, we will return an attribute with both values,
        // regardless of how many values the provided attribute actually had.
        return new Attribute(a.getName(), schema, "TRUE", "FALSE");
      }
    }
    else if (matchingRule instanceof DistinguishedNameMatchingRule)
    {
      final String[] originalValues = a.getValues();
      final String[] scrambledValues = new String[originalValues.length];
      for (int i=0; i < originalValues.length; i++)
      {
        try
        {
          scrambledValues[i] = scrambleDN(new DN(originalValues[i])).toString();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          scrambledValues[i] = scrambleString(originalValues[i]);
        }
      }

      return new Attribute(a.getName(), schema, scrambledValues);
    }
    else if (matchingRule instanceof GeneralizedTimeMatchingRule)
    {
      final String[] originalValues = a.getValues();
      final String[] scrambledValues = new String[originalValues.length];
      for (int i=0; i < originalValues.length; i++)
      {
        scrambledValues[i] = scrambleGeneralizedTime(originalValues[i]);
      }

      return new Attribute(a.getName(), schema, scrambledValues);
    }
    else if ((matchingRule instanceof IntegerMatchingRule) ||
             (matchingRule instanceof NumericStringMatchingRule) ||
             (matchingRule instanceof TelephoneNumberMatchingRule))
    {
      final String[] originalValues = a.getValues();
      final String[] scrambledValues = new String[originalValues.length];
      for (int i=0; i < originalValues.length; i++)
      {
        scrambledValues[i] = scrambleNumericValue(originalValues[i]);
      }

      return new Attribute(a.getName(), schema, scrambledValues);
    }
    else if (matchingRule instanceof OctetStringMatchingRule)
    {
      // If the target attribute is userPassword, then treat it like an encoded
      // password.
      final byte[][] originalValues = a.getValueByteArrays();
      final byte[][] scrambledValues = new byte[originalValues.length][];
      for (int i=0; i < originalValues.length; i++)
      {
        if (baseName.equals("userpassword") || baseName.equals("2.5.4.35"))
        {
          scrambledValues[i] = StaticUtils.getBytes(scrambleEncodedPassword(
               StaticUtils.toUTF8String(originalValues[i])));
        }
        else
        {
          scrambledValues[i] = scrambleBinaryValue(originalValues[i]);
        }
      }

      return new Attribute(a.getName(), schema, scrambledValues);
    }
    else
    {
      final String[] originalValues = a.getValues();
      final String[] scrambledValues = new String[originalValues.length];
      for (int i=0; i < originalValues.length; i++)
      {
        if (baseName.equals("userpassword") || baseName.equals("2.5.4.35") ||
            baseName.equals("authpassword") ||
            baseName.equals("1.3.6.1.4.1.4203.1.3.4"))
        {
          scrambledValues[i] = scrambleEncodedPassword(originalValues[i]);
        }
        else if (originalValues[i].startsWith("{") &&
                 originalValues[i].endsWith("}"))
        {
          scrambledValues[i] = scrambleJSONObject(originalValues[i]);
        }
        else
        {
          scrambledValues[i] = scrambleString(originalValues[i]);
        }
      }

      return new Attribute(a.getName(), schema, scrambledValues);
    }
  }



  /**
   * Scrambles the provided generalized time value.  If the provided value can
   * be parsed as a valid generalized time, then the resulting value will be a
   * generalized time in the same format but with the timestamp randomized.  The
   * randomly-selected time will adhere to the following constraints:
   * <UL>
   *   <LI>
   *     The range for the timestamp will be twice the size of the current time
   *     and the original timestamp.  If the original timestamp is within one
   *     day of the current time, then the original range will be expanded by
   *     an additional one day.
   *   </LI>
   *   <LI>
   *     If the original timestamp is in the future, then the scrambled
   *     timestamp will also be in the future. Otherwise, it will be in the
   *     past.
   *   </LI>
   * </UL>
   *
   * @param  s  The value to scramble.
   *
   * @return  The scrambled value.
   */
  @Nullable()
  public String scrambleGeneralizedTime(@Nullable final String s)
  {
    if (s == null)
    {
      return null;
    }


    // See if we can parse the value as a generalized time.  If not, then just
    // apply generic scrambling.
    final long decodedTime;
    final Random random = getRandom(s);
    try
    {
      decodedTime = StaticUtils.decodeGeneralizedTime(s).getTime();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return scrambleString(s);
    }


    // We want to choose a timestamp at random, but we still want to pick
    // something that is reasonably close to the provided value.  To start
    // with, see how far away the timestamp is from the time this attribute
    // scrambler was created.  If it's less than one day, then add one day to
    // it.  Then, double the resulting value.
    long timeSpan = Math.abs(createTime - decodedTime);
    if (timeSpan < MILLIS_PER_DAY)
    {
      timeSpan += MILLIS_PER_DAY;
    }

    timeSpan *= 2;


    // Generate a random value between zero and the computed time span.
    final long randomLong = (random.nextLong() & 0x7FFF_FFFF_FFFF_FFFFL);
    final long randomOffset = randomLong % timeSpan;


    // If the provided timestamp is in the future, then add the randomly-chosen
    // offset to the time that this attribute scrambler was created.  Otherwise,
    // subtract it from the time that this attribute scrambler was created.
    final long randomTime;
    if (decodedTime > createTime)
    {
      randomTime = createTime + randomOffset;
    }
    else
    {
      randomTime = createTime - randomOffset;
    }


    // Create a generalized time representation of the provided value.
    final String generalizedTime =
         StaticUtils.encodeGeneralizedTime(randomTime);


    // We want to preserve the original precision and time zone specifier for
    // the timestamp, so just take as much of the generalized time value as we
    // need to do that.
    boolean stillInGeneralizedTime = true;
    final StringBuilder scrambledValue = new StringBuilder(s.length());
    for (int i=0; i < s.length(); i++)
    {
      final char originalCharacter = s.charAt(i);
      if (stillInGeneralizedTime)
      {
        if ((i < generalizedTime.length()) &&
            (originalCharacter >= '0') && (originalCharacter <= '9'))
        {
          final char generalizedTimeCharacter = generalizedTime.charAt(i);
          if ((generalizedTimeCharacter >= '0') &&
              (generalizedTimeCharacter <= '9'))
          {
            scrambledValue.append(generalizedTimeCharacter);
          }
          else
          {
            scrambledValue.append(originalCharacter);
            if (generalizedTimeCharacter != '.')
            {
              stillInGeneralizedTime = false;
            }
          }
        }
        else
        {
          scrambledValue.append(originalCharacter);
          if (originalCharacter != '.')
          {
            stillInGeneralizedTime = false;
          }
        }
      }
      else
      {
        scrambledValue.append(originalCharacter);
      }
    }

    return scrambledValue.toString();
  }



  /**
   * Scrambles the provided value, which is expected to be largely numeric.
   * Only digits will be scrambled, with all other characters left intact.
   * The first digit will be required to be nonzero unless it is also the last
   * character of the string.
   *
   * @param  s  The value to scramble.
   *
   * @return  The scrambled value.
   */
  @Nullable()
  public String scrambleNumericValue(@Nullable final String s)
  {
    if (s == null)
    {
      return null;
    }


    // Scramble all digits in the value, leaving all non-digits intact.
    int firstDigitPos = -1;
    boolean multipleDigits = false;
    final char[] chars = s.toCharArray();
    final Random random = getRandom(s);
    final StringBuilder scrambledValue = new StringBuilder(s.length());
    for (int i=0; i < chars.length; i++)
    {
      final char c = chars[i];
      if ((c >= '0') && (c <= '9'))
      {
        scrambledValue.append(random.nextInt(10));
        if (firstDigitPos < 0)
        {
          firstDigitPos = i;
        }
        else
        {
          multipleDigits = true;
        }
      }
      else
      {
        scrambledValue.append(c);
      }
    }


    // If there weren't any digits, then just scramble the value as an ordinary
    // string.
    if (firstDigitPos < 0)
    {
      return scrambleString(s);
    }


    // If there were multiple digits, then ensure that the first digit is
    // nonzero.
    if (multipleDigits && (scrambledValue.charAt(firstDigitPos) == '0'))
    {
      scrambledValue.setCharAt(firstDigitPos,
           (char) (random.nextInt(9) + (int) '1'));
    }


    return scrambledValue.toString();
  }



  /**
   * Scrambles the provided value, which may contain non-ASCII characters.  The
   * scrambling will be performed as follows:
   * <UL>
   *   <LI>
   *     Each lowercase ASCII letter will be replaced with a randomly-selected
   *     lowercase ASCII letter.
   *   </LI>
   *   <LI>
   *     Each uppercase ASCII letter will be replaced with a randomly-selected
   *     uppercase ASCII letter.
   *   </LI>
   *   <LI>
   *     Each ASCII digit will be replaced with a randomly-selected ASCII digit.
   *   </LI>
   *   <LI>
   *     Each ASCII symbol (all printable ASCII characters not included in one
   *     of the above categories) will be replaced with a randomly-selected
   *     ASCII symbol.
   *   </LI>
   *   <LI>
   *   Each ASCII control character will be replaced with a randomly-selected
   *   printable ASCII character.
   *   </LI>
   *   <LI>
   *     Each non-ASCII byte will be replaced with a randomly-selected non-ASCII
   *     byte.
   *   </LI>
   * </UL>
   *
   * @param  value  The value to scramble.
   *
   * @return  The scrambled value.
   */
  @Nullable()
  public byte[] scrambleBinaryValue(@Nullable final byte[] value)
  {
    if (value == null)
    {
      return null;
    }


    final Random random = getRandom(value);
    final byte[] scrambledValue = new byte[value.length];
    for (int i=0; i < value.length; i++)
    {
      final byte b = value[i];
      if ((b >= 'a') && (b <= 'z'))
      {
        scrambledValue[i] =
             (byte) randomCharacter(LOWERCASE_ASCII_LETTERS, random);
      }
      else if ((b >= 'A') && (b <= 'Z'))
      {
        scrambledValue[i] =
             (byte) randomCharacter(UPPERCASE_ASCII_LETTERS, random);
      }
      else if ((b >= '0') && (b <= '9'))
      {
        scrambledValue[i] = (byte) randomCharacter(ASCII_DIGITS, random);
      }
      else if ((b >= ' ') && (b <= '~'))
      {
        scrambledValue[i] = (byte) randomCharacter(ASCII_SYMBOLS, random);
      }
      else if ((b & 0x80) == 0x00)
      {
        // We don't want to include any control characters in the resulting
        // value, so we will replace this control character with a printable
        // ASCII character.  ASCII control characters are 0x00-0x1F and 0x7F.
        // So the printable ASCII characters are 0x20-0x7E, which is a
        // continuous span of 95 characters starting at 0x20.
        scrambledValue[i] = (byte) (random.nextInt(95) + 0x20);
      }
      else
      {
        // It's a non-ASCII byte, so pick a non-ASCII byte at random.
        scrambledValue[i] = (byte) ((random.nextInt() & 0xFF) | 0x80);
      }
    }

    return scrambledValue;
  }



  /**
   * Scrambles the provided encoded password value.  It is expected that it will
   * either start with a storage scheme name in curly braces (e.g.,
   * "{SSHA256}XrgyNdl3fid7KYdhd/Ju47KJQ5PYZqlUlyzxQ28f/QXUnNd9fupj9g==") or
   * that it will use the authentication password syntax as described in RFC
   * 3112 in which the scheme name is separated from the rest of the password by
   * a dollar sign (e.g.,
   * "SHA256$QGbHtDCi1i4=$8/X7XRGaFCovC5mn7ATPDYlkVoocDD06Zy3lbD4AoO4=").  In
   * either case, the scheme name will be left unchanged but the remainder of
   * the value will be scrambled.
   *
   * @param  s  The encoded password to scramble.
   *
   * @return  The scrambled value.
   */
  @Nullable()
  public String scrambleEncodedPassword(@Nullable final String s)
  {
    if (s == null)
    {
      return null;
    }


    // Check to see if the value starts with a scheme name in curly braces and
    // has something after the closing curly brace.  If so, then preserve the
    // scheme and scramble the rest of the value.
    final int closeBracePos = s.indexOf('}');
    if (s.startsWith("{") && (closeBracePos > 0) &&
        (closeBracePos < (s.length() - 1)))
    {
      return s.substring(0, (closeBracePos+1)) +
           scrambleString(s.substring(closeBracePos+1));
    }


    // Check to see if the value has at least two dollar signs and that they are
    // not the first or last characters of the string.  If so, then the scheme
    // should appear before the first dollar sign.  Preserve that and scramble
    // the rest of the value.
    final int firstDollarPos = s.indexOf('$');
    if (firstDollarPos > 0)
    {
      final int secondDollarPos = s.indexOf('$', (firstDollarPos+1));
      if (secondDollarPos > 0)
      {
        return s.substring(0, (firstDollarPos+1)) +
             scrambleString(s.substring(firstDollarPos+1));
      }
    }


    // It isn't an encoding format that we recognize, so we'll just scramble it
    // like a generic string.
    return scrambleString(s);
  }



  /**
   * Scrambles the provided JSON object value.  If the provided value can be
   * parsed as a valid JSON object, then the resulting value will be a JSON
   * object with all field names preserved and some or all of the field values
   * scrambled.  If this {@code AttributeScrambler} was created with a set of
   * JSON fields, then only the values of those fields will be scrambled;
   * otherwise, all field values will be scrambled.
   *
   * @param  s  The time value to scramble.
   *
   * @return  The scrambled value.
   */
  @Nullable()
  public String scrambleJSONObject(@Nullable final String s)
  {
    if (s == null)
    {
      return null;
    }


    // Try to parse the value as a JSON object.  If this fails, then just
    // scramble it as a generic string.
    final JSONObject o;
    try
    {
      o = new JSONObject(s);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return scrambleString(s);
    }


    final boolean scrambleAllFields = jsonFields.isEmpty();
    final Map<String,JSONValue> originalFields = o.getFields();
    final LinkedHashMap<String,JSONValue> scrambledFields = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(originalFields.size()));
    for (final Map.Entry<String,JSONValue> e : originalFields.entrySet())
    {
      final JSONValue scrambledValue;
      final String fieldName = e.getKey();
      final JSONValue originalValue = e.getValue();
      if (scrambleAllFields ||
          jsonFields.contains(StaticUtils.toLowerCase(fieldName)))
      {
        scrambledValue = scrambleJSONValue(originalValue, true);
      }
      else if (originalValue instanceof JSONArray)
      {
        scrambledValue = scrambleObjectsInArray((JSONArray) originalValue);
      }
      else if (originalValue instanceof JSONObject)
      {
        scrambledValue = scrambleJSONValue(originalValue, false);
      }
      else
      {
        scrambledValue = originalValue;
      }

      scrambledFields.put(fieldName, scrambledValue);
    }

    return new JSONObject(scrambledFields).toString();
  }



  /**
   * Scrambles the provided JSON value.
   *
   * @param  v                  The JSON value to be scrambled.
   * @param  scrambleAllFields  Indicates whether all fields of any JSON object
   *                            should be scrambled.
   *
   * @return  The scrambled JSON value.
   */
  @NotNull()
  private JSONValue scrambleJSONValue(@NotNull final JSONValue v,
                                      final boolean scrambleAllFields)
  {
    if (v instanceof JSONArray)
    {
      final JSONArray a = (JSONArray) v;
      final List<JSONValue> originalValues = a.getValues();
      final ArrayList<JSONValue> scrambledValues =
           new ArrayList<>(originalValues.size());
      for (final JSONValue arrayValue : originalValues)
      {
        scrambledValues.add(scrambleJSONValue(arrayValue, true));
      }
      return new JSONArray(scrambledValues);
    }
    else if (v instanceof JSONBoolean)
    {
      return new JSONBoolean(ThreadLocalRandom.get().nextBoolean());
    }
    else if (v instanceof JSONNumber)
    {
      try
      {
        return new JSONNumber(scrambleNumericValue(v.toString()));
      }
      catch (final Exception e)
      {
        // This should never happen.
        Debug.debugException(e);
        return v;
      }
    }
    else if (v instanceof JSONObject)
    {
      final JSONObject o = (JSONObject) v;
      final Map<String,JSONValue> originalFields = o.getFields();
      final LinkedHashMap<String,JSONValue> scrambledFields =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(
                originalFields.size()));
      for (final Map.Entry<String,JSONValue> e : originalFields.entrySet())
      {
        final JSONValue scrambledValue;
        final String fieldName = e.getKey();
        final JSONValue originalValue = e.getValue();
        if (scrambleAllFields ||
            jsonFields.contains(StaticUtils.toLowerCase(fieldName)))
        {
          scrambledValue = scrambleJSONValue(originalValue, scrambleAllFields);
        }
        else if (originalValue instanceof JSONArray)
        {
          scrambledValue = scrambleObjectsInArray((JSONArray) originalValue);
        }
        else if (originalValue instanceof JSONObject)
        {
          scrambledValue = scrambleJSONValue(originalValue, false);
        }
        else
        {
          scrambledValue = originalValue;
        }

        scrambledFields.put(fieldName, scrambledValue);
      }

      return new JSONObject(scrambledFields);
    }
    else if (v instanceof JSONString)
    {
      final JSONString s = (JSONString) v;
      return new JSONString(scrambleString(s.stringValue()));
    }
    else
    {
      // We should only get here for JSON null values, and we can't scramble
      // those.
      return v;
    }
  }



  /**
   * Creates a new JSON array that will have all the same elements as the
   * provided array except that any values in the array that are JSON objects
   * (including objects contained in nested arrays) will have any appropriate
   * scrambling performed.
   *
   * @param  a  The JSON array for which to scramble any values.
   *
   * @return  The array with any appropriate scrambling performed.
   */
  @NotNull()
  private JSONArray scrambleObjectsInArray(@NotNull final JSONArray a)
  {
    final List<JSONValue> originalValues = a.getValues();
    final ArrayList<JSONValue> scrambledValues =
         new ArrayList<>(originalValues.size());

    for (final JSONValue arrayValue : originalValues)
    {
      if (arrayValue instanceof JSONArray)
      {
        scrambledValues.add(scrambleObjectsInArray((JSONArray) arrayValue));
      }
      else if (arrayValue instanceof JSONObject)
      {
        scrambledValues.add(scrambleJSONValue(arrayValue, false));
      }
      else
      {
        scrambledValues.add(arrayValue);
      }
    }

    return new JSONArray(scrambledValues);
  }



  /**
   * Scrambles the provided string.  The scrambling will be performed as
   * follows:
   * <UL>
   *   <LI>
   *     Each lowercase ASCII letter will be replaced with a randomly-selected
   *     lowercase ASCII letter.
   *   </LI>
   *   <LI>
   *     Each uppercase ASCII letter will be replaced with a randomly-selected
   *     uppercase ASCII letter.
   *   </LI>
   *   <LI>
   *     Each ASCII digit will be replaced with a randomly-selected ASCII digit.
   *   </LI>
   *   <LI>
   *     All other characters will remain unchanged.
   *   <LI>
   * </UL>
   *
   * @param  s  The value to scramble.
   *
   * @return  The scrambled value.
   */
  @Nullable()
  public String scrambleString(@Nullable final String s)
  {
    if (s == null)
    {
      return null;
    }


    final Random random = getRandom(s);
    final StringBuilder scrambledString = new StringBuilder(s.length());
    for (final char c : s.toCharArray())
    {
      if ((c >= 'a') && (c <= 'z'))
      {
        scrambledString.append(
             randomCharacter(LOWERCASE_ASCII_LETTERS, random));
      }
      else if ((c >= 'A') && (c <= 'Z'))
      {
        scrambledString.append(
             randomCharacter(UPPERCASE_ASCII_LETTERS, random));
      }
      else if ((c >= '0') && (c <= '9'))
      {
        scrambledString.append(randomCharacter(ASCII_DIGITS, random));
      }
      else
      {
        scrambledString.append(c);
      }
    }

    return scrambledString.toString();
  }



  /**
   * Retrieves a randomly-selected character from the provided character set.
   *
   * @param  set  The array containing the possible characters to select.
   * @param  r    The random number generator to use to select the character.
   *
   * @return  A randomly-selected character from the provided character set.
   */
  private static char randomCharacter(@NotNull final char[] set,
                                      @NotNull final Random r)
  {
    return set[r.nextInt(set.length)];
  }



  /**
   * Retrieves a random number generator to use in the course of generating a
   * value.  It will be reset with the random seed so that it should yield
   * repeatable output for the same input.
   *
   * @param  value  The value that will be scrambled.  It will contribute to the
   *                random seed that is ultimately used for the random number
   *                generator.
   *
   * @return  A random number generator to use in the course of generating a
   *          value.
   */
  @NotNull()
  private Random getRandom(@NotNull final String value)
  {
    Random r = randoms.get();
    if (r == null)
    {
      r = new Random(randomSeed + value.hashCode());
      randoms.set(r);
    }
    else
    {
      r.setSeed(randomSeed + value.hashCode());
    }

    return r;
  }



  /**
   * Retrieves a random number generator to use in the course of generating a
   * value.  It will be reset with the random seed so that it should yield
   * repeatable output for the same input.
   *
   * @param  value  The value that will be scrambled.  It will contribute to the
   *                random seed that is ultimately used for the random number
   *                generator.
     *
   * @return  A random number generator to use in the course of generating a
   *          value.
   */
  @NotNull()
  private Random getRandom(@NotNull final byte[] value)
  {
    Random r = randoms.get();
    if (r == null)
    {
      r = new Random(randomSeed + Arrays.hashCode(value));
      randoms.set(r);
    }
    else
    {
      r.setSeed(randomSeed + Arrays.hashCode(value));
    }

    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry translate(@NotNull final Entry original,
                         final long firstLineNumber)
  {
    return transformEntry(original);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public LDIFChangeRecord translate(@NotNull final LDIFChangeRecord original,
                                    final long firstLineNumber)
  {
    return transformChangeRecord(original);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry translateEntryToWrite(@NotNull final Entry original)
  {
    return transformEntry(original);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public LDIFChangeRecord translateChangeRecordToWrite(
                               @NotNull final LDIFChangeRecord original)
  {
    return transformChangeRecord(original);
  }
}
