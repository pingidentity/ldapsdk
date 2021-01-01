/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.schema.SchemaMessages.*;



/**
 * This class provides a mechanism for validating entries against a schema.  It
 * provides the ability to customize the types of validation to perform, and can
 * collect information about the entries that fail validation to provide a
 * summary of the problems encountered.
 * <BR><BR>
 * The types of validation that may be performed for each entry include:
 * <UL>
 *   <LI>Ensure that the entry has a valid DN.</LI>
 *   <LI>Ensure that all attribute values used in the entry's RDN are also
 *       present in the entry.</LI>
 *   <LI>Ensure that the entry has exactly one structural object class.</LI>
 *   <LI>Ensure that all of the object classes for the entry are defined in the
 *       schema.</LI>
 *   <LI>Ensure that all of the auxiliary classes for the entry are allowed by
 *       the DIT content rule for the entry's structural object class (if such a
 *        DIT content rule is defined).</LI>
 *   <LI>Ensure that all attributes contained in the entry are defined in the
 *       schema.</LI>
 *   <LI>Ensure that all attributes required by the entry's object classes or
 *       DIT content rule (if defined) are present in the entry.</LI>
 *   <LI>Ensure that all of the user attributes contained in the entry are
 *       allowed by the entry's object classes or DIT content rule (if
 *       defined).</LI>
 *   <LI>Ensure that all attribute values conform to the requirements of the
 *       associated attribute syntax.</LI>
 *   <LI>Ensure that all attributes with multiple values are defined as
 *       multi-valued in the associated schema.</LI>
 *   <LI>If there is a name form associated with the entry's structural object
 *       class, then ensure that the entry's RDN satisfies its constraints.</LI>
 * </UL>
 * All of these forms of validation will be performed by default, but individual
 * types of validation may be enabled or disabled.
 * <BR><BR>
 * This class will not make any attempt to validate compliance with DIT
 * structure rules, nor will it check the OBSOLETE field for any of the schema
 * elements.  In addition, attempts to validate whether attribute values
 * conform to the syntax for the associated attribute type may only be
 * completely accurate for syntaxes supported by the LDAP SDK.
 * <BR><BR>
 * This class is largely threadsafe, and the {@link EntryValidator#entryIsValid}
 * is designed so that it can be invoked concurrently by multiple threads.
 * Note, however, that it is not recommended that the any of the other methods
 * in this class be used while any threads are running the {@code entryIsValid}
 * method because changing the configuration or attempting to retrieve retrieve
 * information may yield inaccurate or inconsistent results.
 */
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class EntryValidator
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8945609557086398241L;



  // A count of the total number of entries examined.
  @NotNull private final AtomicLong entriesExamined;

  // A count of the number of entries missing an attribute value contained in
  // the RDN.
  @NotNull private final AtomicLong entriesMissingRDNValues;

  // A count of the total number of invalid entries encountered.
  @NotNull private final AtomicLong invalidEntries;

  // A count of the number of entries with DNs that could not be parsed.
  @NotNull private final AtomicLong malformedDNs;

  // A count of the number of entries missing a superior object class.
  @NotNull private final AtomicLong missingSuperiorClasses;

  // A count of the number of entries containing multiple structural object
  // classes.
  @NotNull private final AtomicLong multipleStructuralClasses;

  // A count of the number of entries with RDNs that violate the associated
  // name form.
  @NotNull private final AtomicLong nameFormViolations;

  // A count of the number of entries without any object class.
  @NotNull private final AtomicLong noObjectClasses;

  // A count of the number of entries without a structural object class.
  @NotNull private final AtomicLong noStructuralClass;

  // Indicates whether an entry should be considered invalid if it contains an
  // attribute value which violates the associated attribute syntax.
  private boolean checkAttributeSyntax;

  // Indicates whether an entry should be considered invalid if it contains one
  // or more attribute values in its RDN that are not present in the set of
  // entry attributes.
  private boolean checkEntryMissingRDNValues;

  // Indicates whether an entry should be considered invalid if its DN cannot be
  // parsed.
  private boolean checkMalformedDNs;

  // Indicates whether an entry should be considered invalid if it is missing
  // attributes required by its object classes or DIT content rule.
  private boolean checkMissingAttributes;

  // Indicates whether an entry should be considered invalid if it is missing
  // one or more superior object classes.
  private boolean checkMissingSuperiorObjectClasses;

  // Indicates whether an entry should be considered invalid if its RDN does not
  // conform to name form requirements.
  private boolean checkNameForms;

  // Indicates whether an entry should be considered invalid if it contains any
  // attributes which are not allowed by its object classes or DIT content rule.
  private boolean checkProhibitedAttributes;

  // Indicates whether an entry should be considered invalid if it contains an
  // auxiliary class that is not allowed by its DIT content rule or an abstract
  // class that is not associated with a non-abstract class.
  private boolean checkProhibitedObjectClasses;

  // Indicates whether an entry should be considered invalid if it contains any
  // attribute defined as single-valued with more than one values.
  private boolean checkSingleValuedAttributes;

  // Indicates whether an entry should be considered invalid if it does not
  // contain exactly one structural object class.
  private boolean checkStructuralObjectClasses;

  // Indicates whether an entry should be considered invalid if it contains an
  // attribute which is not defined in the schema.
  private boolean checkUndefinedAttributes;

  // Indicates whether an entry should be considered invalid if it contains an
  // object class which is not defined in the schema.
  private boolean checkUndefinedObjectClasses;

  // A map of the attributes with values violating the associated syntax to the
  // number of values found violating the syntax.
  @NotNull private final ConcurrentHashMap<String,AtomicLong>
       attributesViolatingSyntax;

  // A map of the required attribute types that were missing from entries to
  // the number of entries missing them.
  @NotNull private final ConcurrentHashMap<String,AtomicLong> missingAttributes;

  // A map of the prohibited attribute types that were included in entries to
  // the number of entries referencing them.
  @NotNull private final ConcurrentHashMap<String,AtomicLong>
       prohibitedAttributes;

  // A map of the prohibited auxiliary object classes that were included in
  // entries to the number of entries referencing them.
  @NotNull private final ConcurrentHashMap<String,AtomicLong>
       prohibitedObjectClasses;

  // A map of the single-valued attributes with multiple values to the number
  // of entries with multiple values for those attributes.
  @NotNull private final ConcurrentHashMap<String,AtomicLong>
       singleValueViolations;

  // A map of undefined attribute types to the number of entries referencing
  // them.
  @NotNull private final ConcurrentHashMap<String,AtomicLong>
       undefinedAttributes;

  // A map of undefined object classes to the number of entries referencing
  // them.
  @NotNull private final ConcurrentHashMap<String,AtomicLong>
       undefinedObjectClasses;

  // The schema against which entries will be validated.
  @NotNull private final Schema schema;

  // The attribute types for which to ignore syntax violations.
  @NotNull private Set<AttributeTypeDefinition> ignoreSyntaxViolationTypes;



  /**
   * Creates a new entry validator that will validate entries according to the
   * provided schema.
   *
   * @param  schema  The schema against which entries will be validated.
   */
  public EntryValidator(@NotNull final Schema schema)
  {
    this.schema = schema;

    checkAttributeSyntax              = true;
    checkEntryMissingRDNValues        = true;
    checkMalformedDNs                 = true;
    checkMissingAttributes            = true;
    checkMissingSuperiorObjectClasses = true;
    checkNameForms                    = true;
    checkProhibitedAttributes         = true;
    checkProhibitedObjectClasses      = true;
    checkSingleValuedAttributes       = true;
    checkStructuralObjectClasses      = true;
    checkUndefinedAttributes          = true;
    checkUndefinedObjectClasses       = true;

    ignoreSyntaxViolationTypes = Collections.emptySet();

    entriesExamined           = new AtomicLong(0L);
    entriesMissingRDNValues   = new AtomicLong(0L);
    invalidEntries            = new AtomicLong(0L);
    malformedDNs              = new AtomicLong(0L);
    missingSuperiorClasses    = new AtomicLong(0L);
    multipleStructuralClasses = new AtomicLong(0L);
    nameFormViolations        = new AtomicLong(0L);
    noObjectClasses           = new AtomicLong(0L);
    noStructuralClass         = new AtomicLong(0L);

    attributesViolatingSyntax =
         new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));
    missingAttributes =
         new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));
    prohibitedAttributes =
         new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));
    prohibitedObjectClasses =
         new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));
    singleValueViolations =
         new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));
    undefinedAttributes =
         new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));
    undefinedObjectClasses =
         new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they are missing attributes which are required by the object classes or
   * DIT content rule (if applicable) for the entry.
   *
   * @return  {@code true} if entries that are missing attributes required by
   *          its object classes or DIT content rule should be considered
   *          invalid, or {@code false} if not.
   */
  public boolean checkMissingAttributes()
  {
    return checkMissingAttributes;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they are missing attributes which are required by the object classes or DIT
   * content rule (if applicable) for the entry.
   *
   * @param  checkMissingAttributes  Indicates whether the entry validator
   *                                 should consider entries invalid if they are
   *                                 missing required attributes.
   */
  public void setCheckMissingAttributes(final boolean checkMissingAttributes)
  {
    this.checkMissingAttributes = checkMissingAttributes;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they are missing any superior classes for the included set of object
   * classes.
   *
   * @return  {@code true} if entries that are missing superior classes should
   *          be considered invalid, or {@code false} if not.
   */
  public boolean checkMissingSuperiorObjectClasses()
  {
    return checkMissingSuperiorObjectClasses;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they are missing any superior classes for the included set of object
   * classes.
   *
   * @param  checkMissingSuperiorObjectClasses  Indicates whether the entry
   *                                            validator should consider
   *                                            entries invalid if they are
   *                                            missing any superior classes for
   *                                            the included set of object
   *                                            classes.
   */
  public void setCheckMissingSuperiorObjectClasses(
                   final boolean checkMissingSuperiorObjectClasses)
  {
    this.checkMissingSuperiorObjectClasses = checkMissingSuperiorObjectClasses;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * their DNs cannot be parsed.
   *
   * @return  {@code true} if entries with malformed DNs should be considered
   *          invalid, or {@code false} if not.
   */
  public boolean checkMalformedDNs()
  {
    return checkMalformedDNs;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * their DNs cannot be parsed.
   *
   * @param  checkMalformedDNs  Specifies whether entries with malformed DNs
   *                            should be considered invalid.
   */
  public void setCheckMalformedDNs(final boolean checkMalformedDNs)
  {
    this.checkMalformedDNs = checkMalformedDNs;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they contain one or more attribute values in their RDN that are not present
   * in the set of entry attributes.
   *
   * @return  {@code true} if entries missing one or more attribute values
   *          included in their RDNs should be considered invalid, or
   *          {@code false} if not.
   */
  public boolean checkEntryMissingRDNValues()
  {
    return checkEntryMissingRDNValues;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they contain one or more attribute values in their RDN that are not present
   * in the set of entry attributes.
   *
   * @param  checkEntryMissingRDNValues  Indicates whether the entry validator
   *                                     should consider entries invalid if they
   *                                     contain one or more attribute values in
   *                                     their RDN that are not present in the
   *                                     set of entry attributes.
   */
  public void setCheckEntryMissingRDNValues(
                   final boolean checkEntryMissingRDNValues)
  {
    this.checkEntryMissingRDNValues = checkEntryMissingRDNValues;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * the attributes contained in the RDN violate the constraints of the
   * associated name form.
   *
   * @return  {@code true} if entries with RDNs that do not conform to the
   *          associated name form should be considered invalid, or
   *          {@code false} if not.
   */
  public boolean checkNameForms()
  {
    return checkNameForms;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * the attributes contained in the RDN violate the constraints of the
   * associated name form.
   *
   * @param  checkNameForms  Indicates whether the entry validator should
   *                         consider entries invalid if their RDNs violate name
   *                         form constraints.
   */
  public void setCheckNameForms(final boolean checkNameForms)
  {
    this.checkNameForms = checkNameForms;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they contain attributes which are not allowed by (or are prohibited by) the
   * object classes and DIT content rule (if applicable) for the entry.
   *
   * @return  {@code true} if entries should be considered invalid if they
   *          contain attributes which are not allowed, or {@code false} if not.
   */
  public boolean checkProhibitedAttributes()
  {
    return checkProhibitedAttributes;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they contain attributes which are not allowed by (or are prohibited by) the
   * object classes and DIT content rule (if applicable) for the entry.
   *
   * @param  checkProhibitedAttributes  Indicates whether entries should be
   *                                    considered invalid if they contain
   *                                    attributes which are not allowed.
   */
  public void setCheckProhibitedAttributes(
                   final boolean checkProhibitedAttributes)
  {
    this.checkProhibitedAttributes = checkProhibitedAttributes;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they contain auxiliary object classes which are not allowed by the DIT
   * content rule (if applicable) for the entry, or if they contain any abstract
   * object classes which are not subclassed by any non-abstract classes
   * included in the entry.
   *
   * @return  {@code true} if entries should be considered invalid if they
   *          contain prohibited object classes, or {@code false} if not.
   */
  public boolean checkProhibitedObjectClasses()
  {
    return checkProhibitedObjectClasses;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they contain auxiliary object classes which are not allowed by the DIT
   * content rule (if applicable) for the entry, or if they contain any abstract
   * object classes which are not subclassed by any non-abstract classes
   * included in the entry.
   *
   * @param  checkProhibitedObjectClasses  Indicates whether entries should be
   *                                       considered invalid if they contain
   *                                       prohibited object classes.
   */
  public void setCheckProhibitedObjectClasses(
                   final boolean checkProhibitedObjectClasses)
  {
    this.checkProhibitedObjectClasses = checkProhibitedObjectClasses;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they they contain attributes with more than one value which are declared as
   * single-valued in the schema.
   *
   * @return  {@code true} if entries should be considered invalid if they
   *          contain single-valued attributes with more than one value, or
   *          {@code false} if not.
   */
  public boolean checkSingleValuedAttributes()
  {
    return checkSingleValuedAttributes;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they contain attributes with more than one value which are declared as
   * single-valued in the schema.
   *
   * @param  checkSingleValuedAttributes  Indicates whether entries should be
   *                                      considered invalid if they contain
   *                                      single-valued attributes with more
   *                                      than one value.
   */
  public void setCheckSingleValuedAttributes(
                   final boolean checkSingleValuedAttributes)
  {
    this.checkSingleValuedAttributes = checkSingleValuedAttributes;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they do not contain exactly one structural object class (i.e., either do
   * not have any structural object class, or have more than one).
   *
   * @return  {@code true} if entries should be considered invalid if they do
   *          not have exactly one structural object class, or {@code false} if
   *          not.
   */
  public boolean checkStructuralObjectClasses()
  {
    return checkStructuralObjectClasses;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they do not contain exactly one structural object class (i.e., either do
   * not have any structural object class, or have more than one).
   *
   * @param  checkStructuralObjectClasses  Indicates whether entries should be
   *                                       considered invalid if they do not
   *                                       have exactly one structural object
   *                                       class.
   */
  public void setCheckStructuralObjectClasses(
                   final boolean checkStructuralObjectClasses)
  {
    this.checkStructuralObjectClasses = checkStructuralObjectClasses;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they contain attributes which violate the associated attribute syntax.
   *
   * @return  {@code true} if entries should be considered invalid if they
   *          contain attribute values which violate the associated attribute
   *          syntax, or {@code false} if not.
   */
  public boolean checkAttributeSyntax()
  {
    return checkAttributeSyntax;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they contain attributes which violate the associated attribute syntax.
   *
   * @param  checkAttributeSyntax  Indicates whether entries should be
   *                               considered invalid if they violate the
   *                               associated attribute syntax.
   */
  public void setCheckAttributeSyntax(final boolean checkAttributeSyntax)
  {
    this.checkAttributeSyntax = checkAttributeSyntax;
  }



  /**
   * Retrieves the set of attribute types for which syntax violations should be
   * ignored.  If {@link #checkAttributeSyntax()} returns {@code true}, then
   * any attribute syntax violations will be flagged for all attributes except
   * those attributes in this set.  If {@code checkAttributeSyntax()} returns
   * {@code false}, then all syntax violations will be ignored.
   *
   * @return  The set of attribute types for which syntax violations should be
   *          ignored.
   */
  @NotNull()
  public Set<AttributeTypeDefinition> getIgnoreSyntaxViolationsAttributeTypes()
  {
    return ignoreSyntaxViolationTypes;
  }



  /**
   * Specifies the set of attribute types for which syntax violations should be
   * ignored.  This method will only have any effect if
   * {@link #checkAttributeSyntax()} returns {@code true}.
   *
   * @param  attributeTypes  The definitions for the attribute types for  which
   *                         to ignore syntax violations.  It may be
   *                         {@code null} or empty if no violations should be
   *                         ignored.
   */
  public void setIgnoreSyntaxViolationAttributeTypes(
                   @Nullable final AttributeTypeDefinition... attributeTypes)
  {
    if (attributeTypes == null)
    {
      ignoreSyntaxViolationTypes = Collections.emptySet();
    }
    else
    {
      ignoreSyntaxViolationTypes = Collections.unmodifiableSet(
           new HashSet<>(StaticUtils.toList(attributeTypes)));
    }
  }



  /**
   * Specifies the names or OIDs of the attribute types for which syntax
   * violations should be ignored.  This method will only have any effect if
   * {@link #checkAttributeSyntax()} returns {@code true}.
   *
   * @param  attributeTypes  The names or OIDs of the attribute types for  which
   *                         to ignore syntax violations.  It may be
   *                         {@code null} or empty if no violations should be
   *                         ignored.
   */
  public void setIgnoreSyntaxViolationAttributeTypes(
                   @Nullable final String... attributeTypes)
  {
    setIgnoreSyntaxViolationAttributeTypes(StaticUtils.toList(attributeTypes));
  }



  /**
   * Specifies the names or OIDs of the attribute types for which syntax
   * violations should be ignored.  This method will only have any effect if
   * {@link #checkAttributeSyntax()} returns {@code true}.
   *
   * @param  attributeTypes  The names or OIDs of the attribute types for  which
   *                         to ignore syntax violations.  It may be
   *                         {@code null} or empty if no violations should be
   *                         ignored.  Any attribute types not defined in the
   *                         schema will be ignored.
   */
  public void setIgnoreSyntaxViolationAttributeTypes(
                   @Nullable final Collection<String> attributeTypes)
  {
    if (attributeTypes == null)
    {
      ignoreSyntaxViolationTypes = Collections.emptySet();
      return;
    }

    final HashSet<AttributeTypeDefinition> atSet =
         new HashSet<>(StaticUtils.computeMapCapacity(attributeTypes.size()));
    for (final String s : attributeTypes)
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if (d != null)
      {
        atSet.add(d);
      }
    }

    ignoreSyntaxViolationTypes = Collections.unmodifiableSet(atSet);
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they contain attributes which are not defined in the schema.
   *
   * @return  {@code true} if entries should be considered invalid if they
   *          contain attributes which are not defined in the schema, or
   *          {@code false} if not.
   */
  public boolean checkUndefinedAttributes()
  {
    return checkUndefinedAttributes;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they contain attributes which are not defined in the schema.
   *
   * @param  checkUndefinedAttributes  Indicates whether entries should be
   *                                   considered invalid if they contain
   *                                   attributes which are not defined in the
   *                                   schema, or {@code false} if not.
   */
  public void setCheckUndefinedAttributes(
                   final boolean checkUndefinedAttributes)
  {
    this.checkUndefinedAttributes = checkUndefinedAttributes;
  }



  /**
   * Indicates whether the entry validator should consider entries invalid if
   * they contain object classes which are not defined in the schema.
   *
   * @return  {@code true} if entries should be considered invalid if they
   *          contain object classes which are not defined in the schema, or
   *          {@code false} if not.
   */
  public boolean checkUndefinedObjectClasses()
  {
    return checkUndefinedObjectClasses;
  }



  /**
   * Specifies whether the entry validator should consider entries invalid if
   * they contain object classes which are not defined in the schema.
   *
   * @param  checkUndefinedObjectClasses  Indicates whether entries should be
   *                                      considered invalid if they contain
   *                                      object classes which are not defined
   *                                      in the schema.
   */
  public void setCheckUndefinedObjectClasses(
                   final boolean checkUndefinedObjectClasses)
  {
    this.checkUndefinedObjectClasses = checkUndefinedObjectClasses;
  }



  /**
   * Indicates whether the provided entry passes all of the enabled types of
   * validation.
   *
   * @param  entry           The entry to be examined.   It must not be
   *                         {@code null}.
   * @param  invalidReasons  A list to which messages may be added which provide
   *                         information about why the entry is invalid.  It may
   *                         be {@code null} if this information is not needed.
   *
   * @return  {@code true} if the entry conforms to all of the enabled forms of
   *          validation, or {@code false} if the entry fails at least one of
   *          the tests.
   */
  public boolean entryIsValid(@NotNull final Entry entry,
                              @Nullable final List<String> invalidReasons)
  {
    Validator.ensureNotNull(entry);

    boolean entryValid = true;
    entriesExamined.incrementAndGet();

    // Get the parsed DN for the entry.
    RDN rdn = null;
    try
    {
      rdn = entry.getParsedDN().getRDN();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      if (checkMalformedDNs)
      {
        entryValid = false;
        malformedDNs.incrementAndGet();
        if (invalidReasons != null)
        {
          invalidReasons.add(ERR_ENTRY_MALFORMED_DN.get(
               StaticUtils.getExceptionMessage(le)));
        }
      }
    }

    // Get the object class descriptions for the object classes in the entry.
    final HashSet<ObjectClassDefinition> ocSet =
         new HashSet<>(StaticUtils.computeMapCapacity(10));
    final boolean missingOC =
         (! getObjectClasses(entry, ocSet, invalidReasons));
    if (missingOC)
    {
      entryValid = false;
    }

    // If the entry was not missing any object classes, then get the structural
    // class for the entry and use it to get the associated DIT content rule and
    // name form.
    DITContentRuleDefinition ditContentRule = null;
    NameFormDefinition nameForm = null;
    if (! missingOC)
    {
      final AtomicReference<ObjectClassDefinition> ref =
           new AtomicReference<>(null);
      entryValid &= getStructuralClass(ocSet, ref, invalidReasons);
      final ObjectClassDefinition structuralClass = ref.get();
      if (structuralClass != null)
      {
        ditContentRule = schema.getDITContentRule(structuralClass.getOID());
        nameForm =
             schema.getNameFormByObjectClass(structuralClass.getNameOrOID());
      }
    }

    // If we should check for missing required attributes, then do so.
    Set<AttributeTypeDefinition> requiredAttrs = Collections.emptySet();
    if (checkMissingAttributes || checkProhibitedAttributes)
    {
      requiredAttrs = getRequiredAttributes(ocSet, ditContentRule);
      if (checkMissingAttributes)
      {
        entryValid &= checkForMissingAttributes(entry, rdn, requiredAttrs,
                                                invalidReasons);
      }
    }

    // Iterate through all of the attributes in the entry.  Make sure that they
    // are all defined in the schema, that they are allowed to be present in the
    // entry, that their values conform to the associated syntax, and that any
    // single-valued attributes have only one value.
    Set<AttributeTypeDefinition> optionalAttrs = Collections.emptySet();
    if (checkProhibitedAttributes)
    {
      optionalAttrs =
           getOptionalAttributes(ocSet, ditContentRule, requiredAttrs);
    }
    for (final Attribute a : entry.getAttributes())
    {
      entryValid &=
           checkAttribute(a, requiredAttrs, optionalAttrs, invalidReasons);
    }

    // If there is a DIT content rule, then check to ensure that all of the
    // auxiliary object classes are allowed.
    if (checkProhibitedObjectClasses && (ditContentRule != null))
    {
      entryValid &=
           checkAuxiliaryClasses(ocSet, ditContentRule, invalidReasons);
    }

    // Check the entry's RDN to ensure that all attributes are defined in the
    // schema, allowed to be present, and comply with the name form.
    if (rdn != null)
    {
      entryValid &= checkRDN(rdn, entry, requiredAttrs, optionalAttrs, nameForm,
                             invalidReasons);
    }

    if (! entryValid)
    {
      invalidEntries.incrementAndGet();
    }

    return entryValid;
  }



  /**
   * Gets the object classes for the entry, including any that weren't
   * explicitly included but should be because they were superior to classes
   * that were included.
   *
   * @param  entry           The entry to examine.
   * @param  ocSet           The set into which the object class definitions
   *                         should be placed.
   * @param  invalidReasons  A list to which messages may be added which provide
   *                         information about why the entry is invalid.  It may
   *                         be {@code null} if this information is not needed.
   *
   * @return  {@code true} if the entry passed all validation processing
   *          performed by this method, or {@code false} if there were any
   *          failures.
   */
  private boolean getObjectClasses(@NotNull final Entry entry,
                       @NotNull final HashSet<ObjectClassDefinition> ocSet,
                       @Nullable final List<String> invalidReasons)
  {
    final String[] ocValues = entry.getObjectClassValues();
    if ((ocValues == null) || (ocValues.length == 0))
    {
      noObjectClasses.incrementAndGet();
      if (invalidReasons != null)
      {
        invalidReasons.add(ERR_ENTRY_NO_OCS.get());
      }
      return false;
    }

    boolean entryValid = true;
    final HashSet<String> missingOCs =
         new HashSet<>(StaticUtils.computeMapCapacity(ocValues.length));
    for (final String ocName : entry.getObjectClassValues())
    {
      final ObjectClassDefinition d = schema.getObjectClass(ocName);
      if (d == null)
      {
        if (checkUndefinedObjectClasses)
        {
          entryValid = false;
          missingOCs.add(StaticUtils.toLowerCase(ocName));
          updateCount(ocName, undefinedObjectClasses);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_UNDEFINED_OC.get(ocName));
          }
        }
      }
      else
      {
        ocSet.add(d);
      }
    }

    for (final ObjectClassDefinition d : new HashSet<>(ocSet))
    {
      entryValid &= addSuperiorClasses(d, ocSet, missingOCs, invalidReasons);
    }

    return entryValid;
  }



  /**
   * Recursively adds the definition superior class for the provided object
   * class definition to the provided set, if it is not already present.
   *
   * @param  d               The object class definition to process.
   * @param  ocSet           The set into which the object class definitions
   *                         should be placed.
   * @param  missingOCNames  The names of the object classes we already know are
   *                         missing and therefore shouldn't be flagged again.
   * @param  invalidReasons  A list to which messages may be added which provide
   *                         information about why the entry is invalid.  It may
   *                         be {@code null} if this information is not needed.
   *
   * @return  {@code true} if the entry passed all validation processing
   *          performed by this method, or {@code false} if there were any
   *          failures.
   */
  private boolean addSuperiorClasses(@NotNull final ObjectClassDefinition d,
                       @NotNull final HashSet<ObjectClassDefinition> ocSet,
                       @NotNull final HashSet<String> missingOCNames,
                       @Nullable final List<String> invalidReasons)
  {
    boolean entryValid = true;

    for (final String ocName : d.getSuperiorClasses())
    {
      final ObjectClassDefinition supOC = schema.getObjectClass(ocName);
      if (supOC == null)
      {
        if (checkUndefinedObjectClasses)
        {
          entryValid = false;
          final String lowerName = StaticUtils.toLowerCase(ocName);
          if (! missingOCNames.contains(lowerName))
          {
            missingOCNames.add(lowerName);
            updateCount(ocName, undefinedObjectClasses);
            if (invalidReasons != null)
            {
              invalidReasons.add(ERR_ENTRY_UNDEFINED_SUP_OC.get(
                   d.getNameOrOID(), ocName));
            }
          }
        }
      }
      else
      {
        if (! ocSet.contains(supOC))
        {
          ocSet.add(supOC);
          if (checkMissingSuperiorObjectClasses)
          {
            entryValid = false;
            missingSuperiorClasses.incrementAndGet();
            if (invalidReasons != null)
            {
              invalidReasons.add(ERR_ENTRY_MISSING_SUP_OC.get(
                   supOC.getNameOrOID(), d.getNameOrOID()));
            }
          }
        }

        entryValid &=
             addSuperiorClasses(supOC, ocSet, missingOCNames, invalidReasons);
      }
    }

    return entryValid;
  }



  /**
   * Retrieves the structural object class from the set of provided object
   * classes.
   *
   * @param  ocSet            The set of object class definitions for the entry.
   * @param  structuralClass  The reference that will be updated with the
   *                          entry's structural object class.
   * @param  invalidReasons   A list to which messages may be added which
   *                          provide provide information about why the entry is
   *                          invalid.  It may be {@code null} if this
   *                          information is not needed.
   *
   * @return  {@code true} if the entry passes all validation checks performed
   *          by this method, or {@code false} if not.
   */
  private boolean getStructuralClass(
       @NotNull final HashSet<ObjectClassDefinition> ocSet,
       @NotNull final AtomicReference<ObjectClassDefinition> structuralClass,
       @Nullable final List<String> invalidReasons)
  {
    final HashSet<ObjectClassDefinition> ocCopy = new HashSet<>(ocSet);
    for (final ObjectClassDefinition d : ocSet)
    {
      final ObjectClassType t = d.getObjectClassType(schema);
      if (t == ObjectClassType.STRUCTURAL)
      {
        ocCopy.removeAll(d.getSuperiorClasses(schema, true));
      }
      else if (t == ObjectClassType.AUXILIARY)
      {
        ocCopy.remove(d);
        ocCopy.removeAll(d.getSuperiorClasses(schema, true));
      }
    }

    // Iterate through the set of remaining classes and strip out any
    // abstract classes.
    boolean entryValid = true;
    Iterator<ObjectClassDefinition> iterator = ocCopy.iterator();
    while (iterator.hasNext())
    {
      final ObjectClassDefinition d = iterator.next();
      if (d.getObjectClassType(schema) == ObjectClassType.ABSTRACT)
      {
        if (checkProhibitedObjectClasses)
        {
          entryValid = false;
          updateCount(d.getNameOrOID(), prohibitedObjectClasses);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_INVALID_ABSTRACT_CLASS.get(
                 d.getNameOrOID()));
          }
        }
        iterator.remove();
      }
    }

    switch (ocCopy.size())
    {
      case 0:
        if (checkStructuralObjectClasses)
        {
          entryValid = false;
          noStructuralClass.incrementAndGet();
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_NO_STRUCTURAL_CLASS.get());
          }
        }
        break;

      case 1:
        structuralClass.set(ocCopy.iterator().next());
        break;

      default:
        if (checkStructuralObjectClasses)
        {
          entryValid = false;
          multipleStructuralClasses.incrementAndGet();
          if (invalidReasons != null)
          {
            final StringBuilder ocList = new StringBuilder();
            iterator = ocCopy.iterator();
            while (iterator.hasNext())
            {
              ocList.append(iterator.next().getNameOrOID());
              if (iterator.hasNext())
              {
                ocList.append(", ");
              }
            }
            invalidReasons.add(
                 ERR_ENTRY_MULTIPLE_STRUCTURAL_CLASSES.get(ocList));
          }
        }
        break;
    }

    return entryValid;
  }



  /**
   * Retrieves the set of attributes which must be present in entries with the
   * provided set of object classes and DIT content rule.
   *
   * @param  ocSet           The set of object classes for the entry.
   * @param  ditContentRule  The DIT content rule for the entry, if defined.
   *
   * @return  The set of attributes which must be present in entries with the
   *          provided set of object classes and DIT content rule.
   */
  @NotNull()
  private HashSet<AttributeTypeDefinition> getRequiredAttributes(
               @NotNull final HashSet<ObjectClassDefinition> ocSet,
               @Nullable final DITContentRuleDefinition ditContentRule)
  {
    final HashSet<AttributeTypeDefinition> attrSet =
         new HashSet<>(StaticUtils.computeMapCapacity(20));
    for (final ObjectClassDefinition oc : ocSet)
    {
      attrSet.addAll(oc.getRequiredAttributes(schema, false));
    }

    if (ditContentRule != null)
    {
      for (final String s : ditContentRule.getRequiredAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if (d != null)
        {
          attrSet.add(d);
        }
      }
    }

    return attrSet;
  }



  /**
   * Retrieves the set of attributes which may optionally be present in entries
   * with the provided set of object classes and DIT content rule.
   *
   * @param  ocSet            The set of object classes for the entry.
   * @param  ditContentRule   The DIT content rule for the entry, if defined.
   * @param  requiredAttrSet  The set of required attributes for the entry.
   *
   * @return  The set of attributes which may optionally be present in entries
   *          with the provided set of object classes and DIT content rule.
   */
  @NotNull()
  private HashSet<AttributeTypeDefinition> getOptionalAttributes(
               @NotNull final HashSet<ObjectClassDefinition> ocSet,
               @Nullable final DITContentRuleDefinition ditContentRule,
               @NotNull final Set<AttributeTypeDefinition> requiredAttrSet)
  {
    final HashSet<AttributeTypeDefinition> attrSet =
         new HashSet<>(StaticUtils.computeMapCapacity(20));
    for (final ObjectClassDefinition oc : ocSet)
    {
      if (oc.hasNameOrOID("extensibleObject") ||
          oc.hasNameOrOID("1.3.6.1.4.1.1466.101.120.111"))
      {
        attrSet.addAll(schema.getUserAttributeTypes());
        break;
      }

      for (final AttributeTypeDefinition d :
           oc.getOptionalAttributes(schema, false))
      {
        if (! requiredAttrSet.contains(d))
        {
          attrSet.add(d);
        }
      }
    }

    if (ditContentRule != null)
    {
      for (final String s : ditContentRule.getOptionalAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if ((d != null) && (! requiredAttrSet.contains(d)))
        {
          attrSet.add(d);
        }
      }

      for (final String s : ditContentRule.getProhibitedAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if (d != null)
        {
          attrSet.remove(d);
        }
      }
    }

    return attrSet;
  }



  /**
   * Checks the provided entry to determine whether it is missing any required
   * attributes.
   *
   * @param  entry           The entry to examine.
   * @param  rdn             The RDN for the entry, if available.
   * @param  requiredAttrs   The set of attribute types which are required to be
   *                         included in the entry.
   * @param  invalidReasons  A list to which messages may be added which provide
   *                         information about why the entry is invalid.  It may
   *                         be {@code null} if this information is not needed.
   *
   * @return  {@code true} if the entry has all required attributes, or
   *          {@code false} if not.
   */
  private boolean checkForMissingAttributes(@NotNull final Entry entry,
               @Nullable final RDN rdn,
               @NotNull final Set<AttributeTypeDefinition> requiredAttrs,
               @Nullable final List<String> invalidReasons)
  {
    boolean entryValid = true;

    for (final AttributeTypeDefinition d : requiredAttrs)
    {
      boolean found = false;
      for (final String s : d.getNames())
      {
        if (entry.hasAttribute(s) || ((rdn != null) && rdn.hasAttribute(s)))
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        if (! (entry.hasAttribute(d.getOID()) ||
               ((rdn != null) && (rdn.hasAttribute(d.getOID())))))
        {
          entryValid = false;
          updateCount(d.getNameOrOID(), missingAttributes);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_MISSING_REQUIRED_ATTR.get(
                 d.getNameOrOID()));
          }
        }
      }
    }

    return entryValid;
  }



  /**
   * Checks the provided attribute to determine whether it appears to be valid.
   *
   * @param  attr            The attribute to examine.
   * @param  requiredAttrs   The set of attribute types which are required to be
   *                         included in the entry.
   * @param  optionalAttrs   The set of attribute types which may optionally be
   *                         included in the entry.
   * @param  invalidReasons  A list to which messages may be added which provide
   *                         information about why the entry is invalid.  It may
   *                         be {@code null} if this information is not needed.
   *
   * @return  {@code true} if the attribute passed all of the checks and appears
   *          to be valid, or {@code false} if it failed any of the checks.
   */
  private boolean checkAttribute(@NotNull final Attribute attr,
               @NotNull final Set<AttributeTypeDefinition> requiredAttrs,
               @NotNull final Set<AttributeTypeDefinition> optionalAttrs,
               @Nullable final List<String> invalidReasons)
  {
    boolean entryValid = true;

    final AttributeTypeDefinition d =
         schema.getAttributeType(attr.getBaseName());
    if (d == null)
    {
      if (checkUndefinedAttributes)
      {
        entryValid = false;
        updateCount(attr.getBaseName(), undefinedAttributes);
        if (invalidReasons != null)
        {
          invalidReasons.add(ERR_ENTRY_UNDEFINED_ATTR.get(attr.getBaseName()));
        }
      }

      return entryValid;
    }

    if (checkProhibitedAttributes && (! d.isOperational()))
    {
      if (! (requiredAttrs.contains(d) || optionalAttrs.contains(d)))
      {
        entryValid = false;
        updateCount(d.getNameOrOID(), prohibitedAttributes);
        if (invalidReasons != null)
        {
          invalidReasons.add(ERR_ENTRY_ATTR_NOT_ALLOWED.get(d.getNameOrOID()));
        }
      }
    }

    final ASN1OctetString[] rawValues = attr.getRawValues();
    if (checkSingleValuedAttributes && d.isSingleValued() &&
        (rawValues.length > 1))
    {
      entryValid = false;
      updateCount(d.getNameOrOID(), singleValueViolations);
      if (invalidReasons != null)
      {
        invalidReasons.add(
             ERR_ENTRY_ATTR_HAS_MULTIPLE_VALUES.get(d.getNameOrOID()));
      }
    }

    if (checkAttributeSyntax)
    {
      if (! ignoreSyntaxViolationTypes.contains(d))
      {
        final MatchingRule r =
             MatchingRule.selectEqualityMatchingRule(d.getNameOrOID(), schema);
        final Map<String, String[]> extensions = d.getExtensions();
        for (final ASN1OctetString v : rawValues)
        {
          try
          {
            r.normalize(v);
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            entryValid = false;
            updateCount(d.getNameOrOID(), attributesViolatingSyntax);
            if (invalidReasons != null)
            {
              invalidReasons.add(ERR_ENTRY_ATTR_INVALID_SYNTAX.get(
                   v.stringValue(), d.getNameOrOID(),
                   StaticUtils.getExceptionMessage(le)));
            }
          }


          // If the attribute type definition includes an X-ALLOWED-VALUE
          // extension, then make sure the value is in that set.
          final String[] allowedValues = extensions.get("X-ALLOWED-VALUE");
          if (allowedValues != null)
          {
            boolean isAllowed = false;
            for (final String allowedValue : allowedValues)
            {
              try
              {
                if (r.valuesMatch(v, new ASN1OctetString(allowedValue)))
                {
                  isAllowed = true;
                  break;
                }
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
              }
            }

            if (! isAllowed)
            {
              entryValid = false;
              updateCount(d.getNameOrOID(), attributesViolatingSyntax);
              if (invalidReasons != null)
              {
                invalidReasons.add(ERR_ENTRY_ATTR_VALUE_NOT_ALLOWED.get(
                     v.stringValue(), d.getNameOrOID()));
              }
            }
          }


          // If the attribute type definition includes an X-VALUE-REGEX
          // extension, then make sure the value matches one of those regexes.
          final String[] valueRegexes = extensions.get("X-VALUE-REGEX");
          if (valueRegexes != null)
          {
            boolean matchesRegex = false;
            for (final String regex : valueRegexes)
            {
              try
              {
                final Pattern pattern = Pattern.compile(regex);
                if (pattern.matcher(v.stringValue()).matches())
                {
                  matchesRegex = true;
                  break;
                }
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
              }
            }

            if (! matchesRegex)
            {
              entryValid = false;
              updateCount(d.getNameOrOID(), attributesViolatingSyntax);
              if (invalidReasons != null)
              {
                invalidReasons.add(
                     ERR_ENTRY_ATTR_VALUE_NOT_ALLOWED_BY_REGEX.get(
                          v.stringValue(), d.getNameOrOID()));
              }
            }
          }


          // If the attribute type definition includes an X-MIN-VALUE-LENGTH
          // extension, then make sure the value is long enough.
          final String[] minValueLengths = extensions.get("X-MIN-VALUE-LENGTH");
          if (minValueLengths != null)
          {
            int minLength = 0;
            for (final String s : minValueLengths)
            {
              try
              {
                minLength = Math.max(minLength, Integer.parseInt(s));
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
              }
            }

            if (v.stringValue().length() < minLength)
            {
              entryValid = false;
              updateCount(d.getNameOrOID(), attributesViolatingSyntax);
              if (invalidReasons != null)
              {
                invalidReasons.add(
                     ERR_ENTRY_ATTR_VALUE_SHORTER_THAN_MIN_LENGTH.get(
                          v.stringValue(), d.getNameOrOID(), minLength));
              }
            }
          }


          // If the attribute type definition includes an X-MAX-VALUE-LENGTH
          // extension, then make sure the value is short enough.
          final String[] maxValueLengths = extensions.get("X-MAX-VALUE-LENGTH");
          if (maxValueLengths != null)
          {
            int maxLength = Integer.MAX_VALUE;
            for (final String s : maxValueLengths)
            {
              try
              {
                maxLength = Math.min(maxLength, Integer.parseInt(s));
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
              }
            }

            if (v.stringValue().length() > maxLength)
            {
              entryValid = false;
              updateCount(d.getNameOrOID(), attributesViolatingSyntax);
              if (invalidReasons != null)
              {
                invalidReasons.add(
                     ERR_ENTRY_ATTR_VALUE_LONGER_THAN_MAX_LENGTH.get(
                          v.stringValue(), d.getNameOrOID(), maxLength));
              }
            }
          }


          // If the attribute type definition includes an X-MIN-INT-VALUE
          // extension, then make sure the value is large enough.
          final String[] minIntValues = extensions.get("X-MIN-INT-VALUE");
          if (minIntValues != null)
          {
            try
            {
              final long longValue = Long.parseLong(v.stringValue());

              long minAllowedValue = 0L;
              for (final String s : minIntValues)
              {
                try
                {
                  minAllowedValue =
                       Math.max(minAllowedValue, Long.parseLong(s));
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }

              if (longValue < minAllowedValue)
              {
                entryValid = false;
                updateCount(d.getNameOrOID(), attributesViolatingSyntax);
                if (invalidReasons != null)
                {
                  invalidReasons.add(ERR_ENTRY_ATTR_VALUE_INT_TOO_SMALL.get(
                       longValue, d.getNameOrOID(), minAllowedValue));
                }
              }
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              entryValid = false;
              updateCount(d.getNameOrOID(), attributesViolatingSyntax);
              if (invalidReasons != null)
              {
                invalidReasons.add(ERR_ENTRY_ATTR_VALUE_NOT_INT.get(
                     v.stringValue(), d.getNameOrOID(), "X-MIN-INT-VALUE"));
              }
            }
          }


          // If the attribute type definition includes an X-MAX-INT-VALUE
          // extension, then make sure the value is large enough.
          final String[] maxIntValues = extensions.get("X-MAX-INT-VALUE");
          if (maxIntValues != null)
          {
            try
            {
              final long longValue = Long.parseLong(v.stringValue());

              long maxAllowedValue = Long.MAX_VALUE;
              for (final String s : maxIntValues)
              {
                try
                {
                  maxAllowedValue =
                       Math.min(maxAllowedValue, Long.parseLong(s));
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }

              if (longValue > maxAllowedValue)
              {
                entryValid = false;
                updateCount(d.getNameOrOID(), attributesViolatingSyntax);
                if (invalidReasons != null)
                {
                  invalidReasons.add(ERR_ENTRY_ATTR_VALUE_INT_TOO_LARGE.get(
                       longValue, d.getNameOrOID(), maxAllowedValue));
                }
              }
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              entryValid = false;
              updateCount(d.getNameOrOID(), attributesViolatingSyntax);
              if (invalidReasons != null)
              {
                invalidReasons.add(ERR_ENTRY_ATTR_VALUE_NOT_INT.get(
                     v.stringValue(), d.getNameOrOID(), "X-MAX-INT-VALUE"));
              }
            }
          }
        }


        // If the attribute type definition includes an X-MIN-VALUE-COUNT
        // extension, then make sure the value has enough values.
        final String[] minValueCounts = extensions.get("X-MIN-VALUE-COUNT");
        if (minValueCounts != null)
        {
          int minValueCount = 0;
          for (final String s : minValueCounts)
          {
            try
            {
              minValueCount = Math.max(minValueCount, Integer.parseInt(s));
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
            }
          }

          if (rawValues.length < minValueCount)
          {
            entryValid = false;
            updateCount(d.getNameOrOID(), attributesViolatingSyntax);
            if (invalidReasons != null)
            {
              invalidReasons.add(ERR_ENTRY_TOO_FEW_VALUES.get(rawValues.length,
                   d.getNameOrOID(), minValueCount));
            }
          }
        }


        // If the attribute type definition includes an X-MAX-VALUE-COUNT
        // extension, then make sure the value has enough values.
        final String[] maxValueCounts = extensions.get("X-MAX-VALUE-COUNT");
        if (maxValueCounts != null)
        {
          int maxValueCount = Integer.MAX_VALUE;
          for (final String s : maxValueCounts)
          {
            try
            {
              maxValueCount = Math.min(maxValueCount, Integer.parseInt(s));
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
            }
          }

          if (rawValues.length > maxValueCount)
          {
            entryValid = false;
            updateCount(d.getNameOrOID(), attributesViolatingSyntax);
            if (invalidReasons != null)
            {
              invalidReasons.add(ERR_ENTRY_TOO_MANY_VALUES.get(rawValues.length,
                   d.getNameOrOID(), maxValueCount));
            }
          }
        }
      }
    }

    return entryValid;
  }



  /**
   * Ensures that all of the auxiliary object classes contained in the object
   * class set are allowed by the provided DIT content rule.
   *
   * @param  ocSet           The set of object classes contained in the entry.
   * @param  ditContentRule  The DIT content rule to use to make the
   *                         determination.
   * @param  invalidReasons  A list to which messages may be added which provide
   *                         information about why the entry is invalid.  It may
   *                         be {@code null} if this information is not needed.
   *
   * @return  {@code true} if the entry passes all checks performed by this
   *          method, or {@code false} if not.
   */
  private boolean checkAuxiliaryClasses(
               @NotNull final HashSet<ObjectClassDefinition> ocSet,
               @NotNull final DITContentRuleDefinition ditContentRule,
               @Nullable final List<String> invalidReasons)
  {
    final HashSet<ObjectClassDefinition> auxSet =
         new HashSet<>(StaticUtils.computeMapCapacity(20));
    for (final String s : ditContentRule.getAuxiliaryClasses())
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      if (d != null)
      {
        auxSet.add(d);
      }
    }

    boolean entryValid = true;
    for (final ObjectClassDefinition d : ocSet)
    {
      final ObjectClassType t = d.getObjectClassType(schema);
      if ((t == ObjectClassType.AUXILIARY) && (! auxSet.contains(d)))
      {
        entryValid = false;
        updateCount(d.getNameOrOID(), prohibitedObjectClasses);
        if (invalidReasons != null)
        {
          invalidReasons.add(
               ERR_ENTRY_AUX_CLASS_NOT_ALLOWED.get(d.getNameOrOID()));
        }
      }
    }

    return entryValid;
  }



  /**
   * Ensures that the provided RDN is acceptable.  It will ensure that all
   * attributes are defined in the schema and allowed for the entry, and that
   * the entry optionally conforms to the associated name form.
   *
   * @param  rdn             The RDN to examine.
   * @param  entry           The entry to examine.
   * @param  requiredAttrs   The set of attribute types which are required to be
   *                         included in the entry.
   * @param  optionalAttrs   The set of attribute types which may optionally be
   *                         included in the entry.
   * @param  nameForm        The name for to use to make the determination, if
   *                         defined.
   * @param  invalidReasons  A list to which messages may be added which provide
   *                         information about why the entry is invalid.  It may
   *                         be {@code null} if this information is not needed.
   *
   * @return  {@code true} if the entry passes all checks performed by this
   *          method, or {@code false} if not.
   */
  private boolean checkRDN(@NotNull final RDN rdn, @NotNull final Entry entry,
               @NotNull final Set<AttributeTypeDefinition> requiredAttrs,
               @NotNull final Set<AttributeTypeDefinition> optionalAttrs,
               @Nullable final NameFormDefinition nameForm,
               @Nullable final List<String> invalidReasons)
  {
    final HashSet<AttributeTypeDefinition> nfReqAttrs =
         new HashSet<>(StaticUtils.computeMapCapacity(5));
    final HashSet<AttributeTypeDefinition> nfAllowedAttrs =
         new HashSet<>(StaticUtils.computeMapCapacity(5));
    if (nameForm != null)
    {
      for (final String s : nameForm.getRequiredAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if (d != null)
        {
          nfReqAttrs.add(d);
        }
      }

      nfAllowedAttrs.addAll(nfReqAttrs);
      for (final String s : nameForm.getOptionalAttributes())
      {
        final AttributeTypeDefinition d = schema.getAttributeType(s);
        if (d != null)
        {
          nfAllowedAttrs.add(d);
        }
      }
    }

    boolean entryValid = true;
    final String[] attributeNames = rdn.getAttributeNames();
    final byte[][] attributeValues = rdn.getByteArrayAttributeValues();
    for (int i=0; i < attributeNames.length; i++)
    {
      final String name = attributeNames[i];
      if (checkEntryMissingRDNValues)
      {
        final byte[] value = attributeValues[i];
        final MatchingRule matchingRule =
             MatchingRule.selectEqualityMatchingRule(name, schema);
        if (! entry.hasAttributeValue(name, value, matchingRule))
        {
          entryValid = false;
          entriesMissingRDNValues.incrementAndGet();
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_MISSING_RDN_VALUE.get(
                 rdn.getAttributeValues()[i], name));
          }
        }
      }

      final AttributeTypeDefinition d = schema.getAttributeType(name);
      if (d == null)
      {
        if (checkUndefinedAttributes)
        {
          entryValid = false;
          updateCount(name, undefinedAttributes);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_RDN_ATTR_NOT_DEFINED.get(name));
          }
        }
      }
      else
      {
        if (checkProhibitedAttributes &&
            (! (requiredAttrs.contains(d) || optionalAttrs.contains(d) ||
                d.isOperational())))
        {
          entryValid = false;
          updateCount(d.getNameOrOID(), prohibitedAttributes);
          if (invalidReasons != null)
          {
            invalidReasons.add(ERR_ENTRY_RDN_ATTR_NOT_ALLOWED_IN_ENTRY.get(
                 d.getNameOrOID()));
          }
        }

        if (checkNameForms && (nameForm != null))
        {
          if (! nfReqAttrs.remove(d))
          {
            if (! nfAllowedAttrs.contains(d))
            {
              if (entryValid)
              {
                entryValid = false;
                nameFormViolations.incrementAndGet();
              }
              if (invalidReasons != null)
              {
                invalidReasons.add(
                     ERR_ENTRY_RDN_ATTR_NOT_ALLOWED_BY_NF.get(name));
              }
            }
          }
        }
      }
    }

    if (checkNameForms && (! nfReqAttrs.isEmpty()))
    {
      if (entryValid)
      {
        entryValid = false;
        nameFormViolations.incrementAndGet();
      }
      if (invalidReasons != null)
      {
        for (final AttributeTypeDefinition d : nfReqAttrs)
        {
          invalidReasons.add(ERR_ENTRY_RDN_MISSING_REQUIRED_ATTR.get(
               d.getNameOrOID()));
        }
      }
    }

    return entryValid;
  }



  /**
   * Updates the count for the given key in the provided map, adding a new key
   * with a count of one if necessary.
   *
   * @param  key  The key for which the count is to be updated.
   * @param  map  The map in which the update is to be made.
   */
  private static void updateCount(@NotNull final String key,
               @NotNull final ConcurrentHashMap<String,AtomicLong> map)
  {
    final String lowerKey = StaticUtils.toLowerCase(key);
    AtomicLong l = map.get(lowerKey);
    if (l == null)
    {
      l = map.putIfAbsent(lowerKey, new AtomicLong(1L));
      if (l == null)
      {
        return;
      }
    }

    l.incrementAndGet();
  }



  /**
   * Resets all counts maintained by this entry validator.
   */
  public void resetCounts()
  {
    entriesExamined.set(0L);
    entriesMissingRDNValues.set(0L);
    invalidEntries.set(0L);
    malformedDNs.set(0L);
    missingSuperiorClasses.set(0L);
    multipleStructuralClasses.set(0L);
    nameFormViolations.set(0L);
    noObjectClasses.set(0L);
    noStructuralClass.set(0L);

    attributesViolatingSyntax.clear();
    missingAttributes.clear();
    prohibitedAttributes.clear();
    prohibitedObjectClasses.clear();
    singleValueViolations.clear();
    undefinedAttributes.clear();
    undefinedObjectClasses.clear();
  }



  /**
   * Retrieves the total number of entries examined during processing.
   *
   * @return  The total number of entries examined during processing.
   */
  public long getEntriesExamined()
  {
    return entriesExamined.get();
  }



  /**
   * Retrieves the total number of invalid entries encountered during
   * processing.
   *
   * @return  The total number of invalid entries encountered during processing.
   */
  public long getInvalidEntries()
  {
    return invalidEntries.get();
  }



  /**
   * Retrieves the total number of entries examined that had malformed DNs which
   * could not be parsed.
   *
   * @return  The total number of entries examined that had malformed DNs.
   */
  public long getMalformedDNs()
  {
    return malformedDNs.get();
  }



  /**
   * Retrieves the total number of entries examined that included an attribute
   * value in the RDN that was not present in the entry attributes.
   *
   * @return  The total number of entries examined that included an attribute
   *          value in the RDN that was not present in the entry attributes.
   */
  public long getEntriesMissingRDNValues()
  {
    return entriesMissingRDNValues.get();
  }



  /**
   * Retrieves the total number of entries examined which did not contain any
   * object classes.
   *
   * @return  The total number of entries examined which did not contain any
   *          object classes.
   */
  public long getEntriesWithoutAnyObjectClasses()
  {
    return noObjectClasses.get();
  }



  /**
   * Retrieves the total number of entries examined which did not contain any
   * structural object class.
   *
   * @return  The total number of entries examined which did not contain any
   *          structural object class.
   */
  public long getEntriesMissingStructuralObjectClass()
  {
    return noStructuralClass.get();
  }



  /**
   * Retrieves the total number of entries examined which contained more than
   * one structural object class.
   *
   * @return  The total number of entries examined which contained more than one
   *          structural object class.
   */
  public long getEntriesWithMultipleStructuralObjectClasses()
  {
    return multipleStructuralClasses.get();
  }



  /**
   * Retrieves the total number of entries examined which were missing one or
   * more superior object classes.
   *
   * @return  The total number of entries examined which were missing one or
   *          more superior object classes.
   */
  public long getEntriesWithMissingSuperiorObjectClasses()
  {
    return missingSuperiorClasses.get();
  }



  /**
   * Retrieves the total number of entries examined which contained an RDN that
   * violated the constraints of the associated name form.
   *
   * @return  The total number of entries examined which contained an RDN that
   *          violated the constraints of the associated name form.
   */
  public long getNameFormViolations()
  {
    return nameFormViolations.get();
  }



  /**
   * Retrieves the total number of undefined object classes encountered while
   * examining entries.  Note that this number may be greater than the total
   * number of entries examined if entries contain multiple undefined object
   * classes.
   *
   * @return  The total number of undefined object classes encountered while
   *          examining entries.
   */
  public long getTotalUndefinedObjectClasses()
  {
    return getMapTotal(undefinedObjectClasses);
  }



  /**
   * Retrieves the undefined object classes encountered while processing
   * entries, mapped from the name of the undefined object class to the number
   * of entries in which that object class was referenced.
   *
   * @return  The undefined object classes encountered while processing entries.
   */
  @NotNull()
  public Map<String,Long> getUndefinedObjectClasses()
  {
    return convertMap(undefinedObjectClasses);
  }



  /**
   * Retrieves the total number of undefined attribute types encountered while
   * examining entries.  Note that this number may be greater than the total
   * number of entries examined if entries contain multiple undefined attribute
   * types.
   *
   * @return  The total number of undefined attribute types encountered while
   *          examining entries.
   */
  public long getTotalUndefinedAttributes()
  {
    return getMapTotal(undefinedAttributes);
  }



  /**
   * Retrieves the undefined attribute types encountered while processing
   * entries, mapped from the name of the undefined attribute to the number
   * of entries in which that attribute type was referenced.
   *
   * @return  The undefined attribute types encountered while processing
   *          entries.
   */
  @NotNull()
  public Map<String,Long> getUndefinedAttributes()
  {
    return convertMap(undefinedAttributes);
  }



  /**
   * Retrieves the total number of prohibited object classes encountered while
   * examining entries.  Note that this number may be greater than the total
   * number of entries examined if entries contain multiple prohibited object
   * classes.
   *
   * @return  The total number of prohibited object classes encountered while
   *          examining entries.
   */
  public long getTotalProhibitedObjectClasses()
  {
    return getMapTotal(prohibitedObjectClasses);
  }



  /**
   * Retrieves the prohibited object classes encountered while processing
   * entries, mapped from the name of the object class to the number of entries
   * in which that object class was referenced.
   *
   * @return  The prohibited object classes encountered while processing
   *          entries.
   */
  @NotNull()
  public Map<String,Long> getProhibitedObjectClasses()
  {
    return convertMap(prohibitedObjectClasses);
  }



  /**
   * Retrieves the total number of prohibited attributes encountered while
   * examining entries.  Note that this number may be greater than the total
   * number of entries examined if entries contain multiple prohibited
   * attributes.
   *
   * @return  The total number of prohibited attributes encountered while
   *          examining entries.
   */
  public long getTotalProhibitedAttributes()
  {
    return getMapTotal(prohibitedAttributes);
  }



  /**
   * Retrieves the prohibited attributes encountered while processing entries,
   * mapped from the name of the attribute to the number of entries in which
   * that attribute was referenced.
   *
   * @return  The prohibited attributes encountered while processing entries.
   */
  @NotNull()
  public Map<String,Long> getProhibitedAttributes()
  {
    return convertMap(prohibitedAttributes);
  }



  /**
   * Retrieves the total number of missing required attributes encountered while
   * examining entries.  Note that this number may be greater than the total
   * number of entries examined if entries are missing multiple attributes.
   *
   * @return  The total number of missing required attributes encountered while
   *          examining entries.
   */
  public long getTotalMissingAttributes()
  {
    return getMapTotal(missingAttributes);
  }



  /**
   * Retrieves the missing required encountered while processing entries, mapped
   * from the name of the attribute to the number of entries in which that
   * attribute was required but not found.
   *
   * @return  The prohibited attributes encountered while processing entries.
   */
  @NotNull()
  public Map<String,Long> getMissingAttributes()
  {
    return convertMap(missingAttributes);
  }



  /**
   * Retrieves the total number of attribute values which violate their
   * associated syntax that were encountered while examining entries.  Note that
   * this number may be greater than the total number of entries examined if
   * entries contain multiple malformed attribute values.
   *
   * @return  The total number of attribute values which violate their
   *          associated syntax that were encountered while examining entries.
   */
  public long getTotalAttributesViolatingSyntax()
  {
    return getMapTotal(attributesViolatingSyntax);
  }



  /**
   * Retrieves the attributes with values violating their associated syntax that
   * were encountered while processing entries, mapped from the name of the
   * attribute to the number of malformed values found for that attribute.
   *
   * @return  The attributes with malformed values encountered while processing
   *          entries.
   */
  @NotNull()
  public Map<String,Long> getAttributesViolatingSyntax()
  {
    return convertMap(attributesViolatingSyntax);
  }



  /**
   * Retrieves the total number of attributes defined as single-valued that
   * contained multiple values which were encountered while processing entries.
   * Note that this number may be greater than the total number of entries
   * examined if entries contain multiple such attributes.
   *
   * @return  The total number of attribute defined as single-valued that
   *          contained multiple values which were encountered while processing
   *          entries.
   */
  public long getTotalSingleValueViolations()
  {
    return getMapTotal(singleValueViolations);
  }



  /**
   * Retrieves the attributes defined as single-valued that contained multiple
   * values which were encountered while processing entries, mapped from the
   * name of the attribute to the number of entries in which that attribute had
   * multiple values.
   *
   * @return  The attributes defined as single-valued that contained multiple
   *          values which were encountered while processing entries.
   */
  @NotNull()
  public Map<String,Long> getSingleValueViolations()
  {
    return convertMap(singleValueViolations);
  }



  /**
   * Retrieves the total number of occurrences for all items in the provided
   * map.
   *
   * @param  map  The map to be processed.
   *
   * @return  The total number of occurrences for all items in the provided map.
   */
  private static long getMapTotal(@NotNull final Map<String,AtomicLong> map)
  {
    long total = 0L;

    for (final AtomicLong l : map.values())
    {
      total += l.longValue();
    }

    return total;
  }



  /**
   * Converts the provided map from strings to atomic longs to a map from
   * strings to longs.
   *
   * @param  map  The map to be processed.
   *
   * @return  The new map.
   */
  @NotNull()
  private static Map<String,Long> convertMap(
                      @NotNull final Map<String,AtomicLong> map)
  {
    final TreeMap<String,Long> m = new TreeMap<>();
    for (final Map.Entry<String,AtomicLong> e : map.entrySet())
    {
      m.put(e.getKey(), e.getValue().longValue());
    }

    return Collections.unmodifiableMap(m);
  }



  /**
   * Retrieves a list of messages providing a summary of the invalid entries
   * processed by this class.
   *
   * @param  detailedResults  Indicates whether to include detailed information
   *                          about the attributes and object classes
   *                          responsible for the violations.
   *
   * @return  A list of messages providing a summary of the invalid entries
   *          processed by this class, or an empty list if all entries examined
   *          were valid.
   */
  @NotNull()
  public List<String> getInvalidEntrySummary(final boolean detailedResults)
  {
    final long numInvalid = invalidEntries.get();
    if (numInvalid == 0)
    {
      return Collections.emptyList();
    }

    final ArrayList<String> messages = new ArrayList<>(5);
    final long numEntries = entriesExamined.get();
    long pct = 100 * numInvalid / numEntries;
    messages.add(INFO_ENTRY_INVALID_ENTRY_COUNT.get(
         numInvalid, numEntries, pct));

    final long numBadDNs = malformedDNs.get();
    if (numBadDNs > 0)
    {
      pct = 100 * numBadDNs / numEntries;
      messages.add(INFO_ENTRY_MALFORMED_DN_COUNT.get(
           numBadDNs, numEntries, pct));
    }

    final long numEntriesMissingRDNValues = entriesMissingRDNValues.get();
    if (numEntriesMissingRDNValues > 0)
    {
      pct = 100* numEntriesMissingRDNValues / numEntries;
      messages.add(INFO_ENTRY_MISSING_RDN_VALUE_COUNT.get(
           numEntriesMissingRDNValues, numEntries, pct));
    }

    final long numNoOCs = noObjectClasses.get();
    if (numNoOCs > 0)
    {
      pct = 100 * numNoOCs / numEntries;
      messages.add(INFO_ENTRY_NO_OC_COUNT.get(numNoOCs, numEntries, pct));
    }

    final long numMissingStructural = noStructuralClass.get();
    if (numMissingStructural > 0)
    {
      pct = 100 * numMissingStructural / numEntries;
      messages.add(INFO_ENTRY_NO_STRUCTURAL_OC_COUNT.get(
           numMissingStructural, numEntries, pct));
    }

    final long numMultipleStructural = multipleStructuralClasses.get();
    if (numMultipleStructural > 0)
    {
      pct = 100 * numMultipleStructural / numEntries;
      messages.add(INFO_ENTRY_MULTIPLE_STRUCTURAL_OCS_COUNT.get(
           numMultipleStructural, numEntries, pct));
    }

    final long numNFViolations = nameFormViolations.get();
    if (numNFViolations > 0)
    {
      pct = 100 * numNFViolations / numEntries;
      messages.add(INFO_ENTRY_NF_VIOLATION_COUNT.get(
           numNFViolations, numEntries, pct));
    }

    final long numUndefinedOCs = getTotalUndefinedObjectClasses();
    if (numUndefinedOCs > 0)
    {
      messages.add(INFO_ENTRY_UNDEFINED_OC_COUNT.get(numUndefinedOCs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             undefinedObjectClasses.entrySet())
        {
          messages.add(INFO_ENTRY_UNDEFINED_OC_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numProhibitedOCs = getTotalProhibitedObjectClasses();
    if (numProhibitedOCs > 0)
    {
      messages.add(INFO_ENTRY_PROHIBITED_OC_COUNT.get(numProhibitedOCs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             prohibitedObjectClasses.entrySet())
        {
          messages.add(INFO_ENTRY_PROHIBITED_OC_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numMissingSuperior =
         getEntriesWithMissingSuperiorObjectClasses();
    if (numMissingSuperior > 0)
    {
      messages.add(
           INFO_ENTRY_MISSING_SUPERIOR_OC_COUNT.get(numMissingSuperior));
    }

    final long numUndefinedAttrs = getTotalUndefinedAttributes();
    if (numUndefinedAttrs > 0)
    {
      messages.add(INFO_ENTRY_UNDEFINED_ATTR_COUNT.get(numUndefinedAttrs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             undefinedAttributes.entrySet())
        {
          messages.add(INFO_ENTRY_UNDEFINED_ATTR_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numMissingAttrs = getTotalMissingAttributes();
    if (numMissingAttrs > 0)
    {
      messages.add(INFO_ENTRY_MISSING_ATTR_COUNT.get(numMissingAttrs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             missingAttributes.entrySet())
        {
          messages.add(INFO_ENTRY_MISSING_ATTR_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numProhibitedAttrs = getTotalProhibitedAttributes();
    if (numProhibitedAttrs > 0)
    {
      messages.add(INFO_ENTRY_PROHIBITED_ATTR_COUNT.get(numProhibitedAttrs));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             prohibitedAttributes.entrySet())
        {
          messages.add(INFO_ENTRY_PROHIBITED_ATTR_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numSingleValuedViolations = getTotalSingleValueViolations();
    if (numSingleValuedViolations > 0)
    {
      messages.add(INFO_ENTRY_SINGLE_VALUE_VIOLATION_COUNT.get(
           numSingleValuedViolations));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             singleValueViolations.entrySet())
        {
          messages.add(INFO_ENTRY_SINGLE_VALUE_VIOLATION_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    final long numSyntaxViolations = getTotalAttributesViolatingSyntax();
    if (numSyntaxViolations > 0)
    {
      messages.add(INFO_ENTRY_SYNTAX_VIOLATION_COUNT.get(numSyntaxViolations));
      if (detailedResults)
      {
        for (final Map.Entry<String,AtomicLong> e :
             attributesViolatingSyntax.entrySet())
        {
          messages.add(INFO_ENTRY_SYNTAX_VIOLATION_NAME_COUNT.get(
               e.getKey(), e.getValue().longValue()));
        }
      }
    }

    return Collections.unmodifiableList(messages);
  }
}
