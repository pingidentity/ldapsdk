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



import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.schema.SchemaMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a data structure for representing a directory server
 * subschema subentry.  This includes information about the attribute syntaxes,
 * matching rules, attribute types, object classes, name forms, DIT content
 * rules, DIT structure rules, and matching rule uses defined in the server
 * schema.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Schema
       implements Serializable
{
  /**
   * The name of the attribute used to hold the attribute syntax definitions.
   */
  public static final String ATTR_ATTRIBUTE_SYNTAX = "ldapSyntaxes";



  /**
   * The name of the attribute used to hold the attribute type definitions.
   */
  public static final String ATTR_ATTRIBUTE_TYPE = "attributeTypes";



  /**
   * The name of the attribute used to hold the DIT content rule definitions.
   */
  public static final String ATTR_DIT_CONTENT_RULE = "dITContentRules";



  /**
   * The name of the attribute used to hold the DIT structure rule definitions.
   */
  public static final String ATTR_DIT_STRUCTURE_RULE = "dITStructureRules";



  /**
   * The name of the attribute used to hold the matching rule definitions.
   */
  public static final String ATTR_MATCHING_RULE = "matchingRules";



  /**
   * The name of the attribute used to hold the matching rule use definitions.
   */
  public static final String ATTR_MATCHING_RULE_USE = "matchingRuleUse";



  /**
   * The name of the attribute used to hold the name form definitions.
   */
  public static final String ATTR_NAME_FORM = "nameForms";



  /**
   * The name of the attribute used to hold the object class definitions.
   */
  public static final String ATTR_OBJECT_CLASS = "objectClasses";



  /**
   * The name of the attribute used to hold the DN of the subschema subentry
   * with the schema information that governs a specified entry.
   */
  public static final String ATTR_SUBSCHEMA_SUBENTRY = "subschemaSubentry";



  /**
   * The default standard schema available for use in the LDAP SDK.
   */
  private static final AtomicReference<Schema> DEFAULT_STANDARD_SCHEMA =
       new AtomicReference<Schema>();



  /**
   * The set of request attributes that will be used when retrieving the server
   * subschema subentry in order to retrieve all of the schema elements.
   */
  private static final String[] SCHEMA_REQUEST_ATTRS =
  {
    "*",
    ATTR_ATTRIBUTE_SYNTAX,
    ATTR_ATTRIBUTE_TYPE,
    ATTR_DIT_CONTENT_RULE,
    ATTR_DIT_STRUCTURE_RULE,
    ATTR_MATCHING_RULE,
    ATTR_MATCHING_RULE_USE,
    ATTR_NAME_FORM,
    ATTR_OBJECT_CLASS
  };



  /**
   * The set of request attributes that will be used when retrieving the
   * subschema subentry attribute from a specified entry in order to determine
   * the location of the server schema definitions.
   */
  private static final String[] SUBSCHEMA_SUBENTRY_REQUEST_ATTRS =
  {
    ATTR_SUBSCHEMA_SUBENTRY
  };



  /**
   * Retrieves the resource path that may be used to obtain a file with a number
   * of standard schema definitions.
   */
  private static final String DEFAULT_SCHEMA_RESOURCE_PATH =
       "com/unboundid/ldap/sdk/schema/standard-schema.ldif";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8081839633831517925L;



  // A map of all subordinate attribute type definitions for each attribute
  // type definition.
  private final Map<AttributeTypeDefinition,List<AttributeTypeDefinition>>
       subordinateAttributeTypes;

  // The set of attribute syntaxes mapped from lowercase name/OID to syntax.
  private final Map<String,AttributeSyntaxDefinition> asMap;

  // The set of attribute types mapped from lowercase name/OID to type.
  private final Map<String,AttributeTypeDefinition> atMap;

  // The set of DIT content rules mapped from lowercase name/OID to rule.
  private final Map<String,DITContentRuleDefinition> dcrMap;

  // The set of DIT structure rules mapped from rule ID to rule.
  private final Map<Integer,DITStructureRuleDefinition> dsrMapByID;

  // The set of DIT structure rules mapped from lowercase name to rule.
  private final Map<String,DITStructureRuleDefinition> dsrMapByName;

  // The set of DIT structure rules mapped from lowercase name to rule.
  private final Map<String,DITStructureRuleDefinition> dsrMapByNameForm;

  // The set of matching rules mapped from lowercase name/OID to rule.
  private final Map<String,MatchingRuleDefinition> mrMap;

  // The set of matching rule uses mapped from matching rule OID to use.
  private final Map<String,MatchingRuleUseDefinition> mruMap;

  // The set of name forms mapped from lowercase name/OID to name form.
  private final Map<String,NameFormDefinition> nfMapByName;

  // The set of name forms mapped from structural class OID to name form.
  private final Map<String,NameFormDefinition> nfMapByOC;

  // The set of object classes mapped from lowercase name/OID to class.
  private final Map<String,ObjectClassDefinition> ocMap;

  // The entry used to create this schema object.
  private final ReadOnlyEntry schemaEntry;

  // The set of attribute syntaxes defined in the schema.
  private final Set<AttributeSyntaxDefinition> asSet;

  // The set of attribute types defined in the schema.
  private final Set<AttributeTypeDefinition> atSet;

  // The set of operational attribute types defined in the schema.
  private final Set<AttributeTypeDefinition> operationalATSet;

  // The set of user attribute types defined in the schema.
  private final Set<AttributeTypeDefinition> userATSet;

  // The set of DIT content rules defined in the schema.
  private final Set<DITContentRuleDefinition> dcrSet;

  // The set of DIT structure rules defined in the schema.
  private final Set<DITStructureRuleDefinition> dsrSet;

  // The set of matching rules defined in the schema.
  private final Set<MatchingRuleDefinition> mrSet;

  // The set of matching rule uses defined in the schema.
  private final Set<MatchingRuleUseDefinition> mruSet;

  // The set of name forms defined in the schema.
  private final Set<NameFormDefinition> nfSet;

  // The set of object classes defined in the schema.
  private final Set<ObjectClassDefinition> ocSet;

  // The set of abstract object classes defined in the schema.
  private final Set<ObjectClassDefinition> abstractOCSet;

  // The set of auxiliary object classes defined in the schema.
  private final Set<ObjectClassDefinition> auxiliaryOCSet;

  // The set of structural object classes defined in the schema.
  private final Set<ObjectClassDefinition> structuralOCSet;



  /**
   * Creates a new schema object by decoding the information in the provided
   * entry.
   *
   * @param  schemaEntry  The schema entry to decode.
   */
  public Schema(final Entry schemaEntry)
  {
    this.schemaEntry = new ReadOnlyEntry(schemaEntry);

    // Decode the attribute syntaxes from the schema entry.
    String[] defs = schemaEntry.getAttributeValues(ATTR_ATTRIBUTE_SYNTAX);
    if (defs == null)
    {
      asMap = Collections.emptyMap();
      asSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,AttributeSyntaxDefinition> m =
           new LinkedHashMap<String,AttributeSyntaxDefinition>(defs.length);
      final LinkedHashSet<AttributeSyntaxDefinition> s =
           new LinkedHashSet<AttributeSyntaxDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final AttributeSyntaxDefinition as =
               new AttributeSyntaxDefinition(def);
          s.add(as);
          m.put(toLowerCase(as.getOID()), as);
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      asMap = Collections.unmodifiableMap(m);
      asSet = Collections.unmodifiableSet(s);
    }


    // Decode the attribute types from the schema entry.
    defs = schemaEntry.getAttributeValues(ATTR_ATTRIBUTE_TYPE);
    if (defs == null)
    {
      atMap            = Collections.emptyMap();
      atSet            = Collections.emptySet();
      operationalATSet = Collections.emptySet();
      userATSet        = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,AttributeTypeDefinition> m =
           new LinkedHashMap<String,AttributeTypeDefinition>(2*defs.length);
      final LinkedHashSet<AttributeTypeDefinition> s =
           new LinkedHashSet<AttributeTypeDefinition>(defs.length);
      final LinkedHashSet<AttributeTypeDefinition> sUser =
           new LinkedHashSet<AttributeTypeDefinition>(defs.length);
      final LinkedHashSet<AttributeTypeDefinition> sOperational =
           new LinkedHashSet<AttributeTypeDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final AttributeTypeDefinition at = new AttributeTypeDefinition(def);
          s.add(at);
          m.put(toLowerCase(at.getOID()), at);
          for (final String name : at.getNames())
          {
            m.put(toLowerCase(name), at);
          }

          if (at.isOperational())
          {
            sOperational.add(at);
          }
          else
          {
            sUser.add(at);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      atMap            = Collections.unmodifiableMap(m);
      atSet            = Collections.unmodifiableSet(s);
      operationalATSet = Collections.unmodifiableSet(sOperational);
      userATSet        = Collections.unmodifiableSet(sUser);
    }


    // Decode the DIT content rules from the schema entry.
    defs = schemaEntry.getAttributeValues(ATTR_DIT_CONTENT_RULE);
    if (defs == null)
    {
      dcrMap = Collections.emptyMap();
      dcrSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,DITContentRuleDefinition> m =
           new LinkedHashMap<String,DITContentRuleDefinition>(2*defs.length);
      final LinkedHashSet<DITContentRuleDefinition> s =
           new LinkedHashSet<DITContentRuleDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final DITContentRuleDefinition dcr =
               new DITContentRuleDefinition(def);
          s.add(dcr);
          m.put(toLowerCase(dcr.getOID()), dcr);
          for (final String name : dcr.getNames())
          {
            m.put(toLowerCase(name), dcr);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      dcrMap = Collections.unmodifiableMap(m);
      dcrSet = Collections.unmodifiableSet(s);
    }


    // Decode the DIT structure rules from the schema entry.
    defs = schemaEntry.getAttributeValues(ATTR_DIT_STRUCTURE_RULE);
    if (defs == null)
    {
      dsrMapByID       = Collections.emptyMap();
      dsrMapByName     = Collections.emptyMap();
      dsrMapByNameForm = Collections.emptyMap();
      dsrSet           = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<Integer,DITStructureRuleDefinition> mID =
           new LinkedHashMap<Integer,DITStructureRuleDefinition>(defs.length);
      final LinkedHashMap<String,DITStructureRuleDefinition> mN =
           new LinkedHashMap<String,DITStructureRuleDefinition>(defs.length);
      final LinkedHashMap<String,DITStructureRuleDefinition> mNF =
           new LinkedHashMap<String,DITStructureRuleDefinition>(defs.length);
      final LinkedHashSet<DITStructureRuleDefinition> s =
           new LinkedHashSet<DITStructureRuleDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final DITStructureRuleDefinition dsr =
               new DITStructureRuleDefinition(def);
          s.add(dsr);
          mID.put(dsr.getRuleID(), dsr);
          mNF.put(toLowerCase(dsr.getNameFormID()), dsr);
          for (final String name : dsr.getNames())
          {
            mN.put(toLowerCase(name), dsr);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      dsrMapByID       = Collections.unmodifiableMap(mID);
      dsrMapByName     = Collections.unmodifiableMap(mN);
      dsrMapByNameForm = Collections.unmodifiableMap(mNF);
      dsrSet           = Collections.unmodifiableSet(s);
    }


    // Decode the matching rules from the schema entry.
    defs = schemaEntry.getAttributeValues(ATTR_MATCHING_RULE);
    if (defs == null)
    {
      mrMap = Collections.emptyMap();
      mrSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,MatchingRuleDefinition> m =
           new LinkedHashMap<String,MatchingRuleDefinition>(2*defs.length);
      final LinkedHashSet<MatchingRuleDefinition> s =
           new LinkedHashSet<MatchingRuleDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final MatchingRuleDefinition mr = new MatchingRuleDefinition(def);
          s.add(mr);
          m.put(toLowerCase(mr.getOID()), mr);
          for (final String name : mr.getNames())
          {
            m.put(toLowerCase(name), mr);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      mrMap = Collections.unmodifiableMap(m);
      mrSet = Collections.unmodifiableSet(s);
    }


    // Decode the matching rule uses from the schema entry.
    defs = schemaEntry.getAttributeValues(ATTR_MATCHING_RULE_USE);
    if (defs == null)
    {
      mruMap = Collections.emptyMap();
      mruSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,MatchingRuleUseDefinition> m =
           new LinkedHashMap<String,MatchingRuleUseDefinition>(2*defs.length);
      final LinkedHashSet<MatchingRuleUseDefinition> s =
           new LinkedHashSet<MatchingRuleUseDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final MatchingRuleUseDefinition mru =
               new MatchingRuleUseDefinition(def);
          s.add(mru);
          m.put(toLowerCase(mru.getOID()), mru);
          for (final String name : mru.getNames())
          {
            m.put(toLowerCase(name), mru);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      mruMap = Collections.unmodifiableMap(m);
      mruSet = Collections.unmodifiableSet(s);
    }


    // Decode the name forms from the schema entry.
    defs = schemaEntry.getAttributeValues(ATTR_NAME_FORM);
    if (defs == null)
    {
      nfMapByName = Collections.emptyMap();
      nfMapByOC   = Collections.emptyMap();
      nfSet       = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,NameFormDefinition> mN =
           new LinkedHashMap<String,NameFormDefinition>(2*defs.length);
      final LinkedHashMap<String,NameFormDefinition> mOC =
           new LinkedHashMap<String,NameFormDefinition>(defs.length);
      final LinkedHashSet<NameFormDefinition> s =
           new LinkedHashSet<NameFormDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final NameFormDefinition nf = new NameFormDefinition(def);
          s.add(nf);
          mOC.put(toLowerCase(nf.getStructuralClass()), nf);
          mN.put(toLowerCase(nf.getOID()), nf);
          for (final String name : nf.getNames())
          {
            mN.put(toLowerCase(name), nf);
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      nfMapByName = Collections.unmodifiableMap(mN);
      nfMapByOC   = Collections.unmodifiableMap(mOC);
      nfSet       = Collections.unmodifiableSet(s);
    }


    // Decode the object classes from the schema entry.
    defs = schemaEntry.getAttributeValues(ATTR_OBJECT_CLASS);
    if (defs == null)
    {
      ocMap           = Collections.emptyMap();
      ocSet           = Collections.emptySet();
      abstractOCSet   = Collections.emptySet();
      auxiliaryOCSet  = Collections.emptySet();
      structuralOCSet = Collections.emptySet();
    }
    else
    {
      final LinkedHashMap<String,ObjectClassDefinition> m =
           new LinkedHashMap<String,ObjectClassDefinition>(2*defs.length);
      final LinkedHashSet<ObjectClassDefinition> s =
           new LinkedHashSet<ObjectClassDefinition>(defs.length);
      final LinkedHashSet<ObjectClassDefinition> sAbstract =
           new LinkedHashSet<ObjectClassDefinition>(defs.length);
      final LinkedHashSet<ObjectClassDefinition> sAuxiliary =
           new LinkedHashSet<ObjectClassDefinition>(defs.length);
      final LinkedHashSet<ObjectClassDefinition> sStructural =
           new LinkedHashSet<ObjectClassDefinition>(defs.length);

      for (final String def : defs)
      {
        try
        {
          final ObjectClassDefinition oc = new ObjectClassDefinition(def);
          s.add(oc);
          m.put(toLowerCase(oc.getOID()), oc);
          for (final String name : oc.getNames())
          {
            m.put(toLowerCase(name), oc);
          }

          switch (getOCType(oc, m))
          {
            case ABSTRACT:
              sAbstract.add(oc);
              break;
            case AUXILIARY:
              sAuxiliary.add(oc);
              break;
            case STRUCTURAL:
              sStructural.add(oc);
              break;
          }
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }
      }

      ocMap           = Collections.unmodifiableMap(m);
      ocSet           = Collections.unmodifiableSet(s);
      abstractOCSet   = Collections.unmodifiableSet(sAbstract);
      auxiliaryOCSet  = Collections.unmodifiableSet(sAuxiliary);
      structuralOCSet = Collections.unmodifiableSet(sStructural);
    }


    // Populate the map of subordinate attribute types.
    final LinkedHashMap<AttributeTypeDefinition,List<AttributeTypeDefinition>>
         subAttrTypes = new LinkedHashMap<AttributeTypeDefinition,
              List<AttributeTypeDefinition>>(atSet.size());
    for (final AttributeTypeDefinition d : atSet)
    {
      AttributeTypeDefinition sup = d.getSuperiorType(this);
      while (sup != null)
      {
        List<AttributeTypeDefinition> l = subAttrTypes.get(sup);
        if (l == null)
        {
          l = new ArrayList<AttributeTypeDefinition>(1);
          subAttrTypes.put(sup, l);
        }
        l.add(d);

        sup = sup.getSuperiorType(this);
      }
    }
    subordinateAttributeTypes = Collections.unmodifiableMap(subAttrTypes);
  }



  /**
   * Retrieves the directory server schema over the provided connection.  The
   * root DSE will first be retrieved in order to get its subschemaSubentry DN,
   * and then that entry will be retrieved from the server and its contents
   * decoded as schema elements.  This should be sufficient for directories that
   * only provide a single schema, but for directories with multiple schemas it
   * may be necessary to specify the DN of an entry for which to retrieve the
   * subschema subentry.
   *
   * @param  connection  The connection to use in order to retrieve the server
   *                     schema.  It must not be {@code null}.
   *
   * @return  A decoded representation of the server schema.
   *
   * @throws  LDAPException  If a problem occurs while obtaining the server
   *                         schema.
   */
  public static Schema getSchema(final LDAPConnection connection)
         throws LDAPException
  {
    return getSchema(connection, "");
  }



  /**
   * Retrieves the directory server schema that governs the specified entry.
   * In some servers, different portions of the DIT may be served by different
   * schemas, and in such cases it will be necessary to provide the DN of the
   * target entry in order to ensure that the appropriate schema which governs
   * that entry is returned.  For servers that support only a single schema,
   * any entry DN (including that of the root DSE) should be sufficient.
   *
   * @param  connection  The connection to use in order to retrieve the server
   *                     schema.  It must not be {@code null}.
   * @param  entryDN     The DN of the entry for which to retrieve the governing
   *                     schema.  It may be {@code null} or an empty string in
   *                     order to retrieve the schema that governs the server's
   *                     root DSE.
   *
   * @return  A decoded representation of the server schema, or {@code null} if
   *          it is not available for some reason (e.g., the client does not
   *          have permission to read the server schema).
   *
   * @throws  LDAPException  If a problem occurs while obtaining the server
   *                         schema.
   */
  public static Schema getSchema(final LDAPConnection connection,
                                 final String entryDN)
         throws LDAPException
  {
    ensureNotNull(connection);

    final String subschemaSubentryDN;
    if (entryDN == null)
    {
      subschemaSubentryDN = getSubschemaSubentryDN(connection, "");
    }
    else
    {
      subschemaSubentryDN = getSubschemaSubentryDN(connection, entryDN);
    }

    if (subschemaSubentryDN == null)
    {
      return null;
    }

    final Entry schemaEntry = connection.searchForEntry(subschemaSubentryDN,
         SearchScope.BASE,
         Filter.createEqualityFilter("objectClass", "subschema"),
         SCHEMA_REQUEST_ATTRS);
    if (schemaEntry == null)
    {
      return null;
    }

    return new Schema(schemaEntry);
  }



  /**
   * Reads schema information from one or more files containing the schema
   * represented in LDIF form, with the definitions represented in the form
   * described in section 4.1 of RFC 4512.  Each file should contain a single
   * entry.
   *
   * @param  schemaFiles  The paths to the LDIF files containing the schema
   *                      information to be read.  At least one file must be
   *                      specified.  If multiple files are specified, then they
   *                      will be processed in the order in which they have been
   *                      listed.
   *
   * @return  The schema read from the specified schema files, or {@code null}
   *          if none of the files contains any LDIF data to be read.
   *
   * @throws  IOException  If a problem occurs while attempting to read from
   *                       any of the specified files.
   *
   * @throws  LDIFException  If a problem occurs while attempting to parse the
   *                         contents of any of the schema files.
   */
  public static Schema getSchema(final String... schemaFiles)
         throws IOException, LDIFException
  {
    ensureNotNull(schemaFiles);
    ensureFalse(schemaFiles.length == 0);

    final ArrayList<File> files = new ArrayList<File>(schemaFiles.length);
    for (final String s : schemaFiles)
    {
      files.add(new File(s));
    }

    return getSchema(files);
  }



  /**
   * Reads schema information from one or more files containing the schema
   * represented in LDIF form, with the definitions represented in the form
   * described in section 4.1 of RFC 4512.  Each file should contain a single
   * entry.
   *
   * @param  schemaFiles  The paths to the LDIF files containing the schema
   *                      information to be read.  At least one file must be
   *                      specified.  If multiple files are specified, then they
   *                      will be processed in the order in which they have been
   *                      listed.
   *
   * @return  The schema read from the specified schema files, or {@code null}
   *          if none of the files contains any LDIF data to be read.
   *
   * @throws  IOException  If a problem occurs while attempting to read from
   *                       any of the specified files.
   *
   * @throws  LDIFException  If a problem occurs while attempting to parse the
   *                         contents of any of the schema files.
   */
  public static Schema getSchema(final File... schemaFiles)
         throws IOException, LDIFException
  {
    ensureNotNull(schemaFiles);
    ensureFalse(schemaFiles.length == 0);

    return getSchema(Arrays.asList(schemaFiles));
  }



  /**
   * Reads schema information from one or more files containing the schema
   * represented in LDIF form, with the definitions represented in the form
   * described in section 4.1 of RFC 4512.  Each file should contain a single
   * entry.
   *
   * @param  schemaFiles  The paths to the LDIF files containing the schema
   *                      information to be read.  At least one file must be
   *                      specified.  If multiple files are specified, then they
   *                      will be processed in the order in which they have been
   *                      listed.
   *
   * @return  The schema read from the specified schema files, or {@code null}
   *          if none of the files contains any LDIF data to be read.
   *
   * @throws  IOException  If a problem occurs while attempting to read from
   *                       any of the specified files.
   *
   * @throws  LDIFException  If a problem occurs while attempting to parse the
   *                         contents of any of the schema files.
   */
  public static Schema getSchema(final List<File> schemaFiles)
         throws IOException, LDIFException
  {
    ensureNotNull(schemaFiles);
    ensureFalse(schemaFiles.isEmpty());

    Entry schemaEntry = null;
    for (final File f : schemaFiles)
    {
      final LDIFReader ldifReader = new LDIFReader(f);

      try
      {
        final Entry e = ldifReader.readEntry();
        if (e == null)
        {
          continue;
        }

        e.addAttribute("objectClass", "top", "ldapSubentry", "subschema");

        if (schemaEntry == null)
        {
          schemaEntry = e;
        }
        else
        {
          for (final Attribute a : e.getAttributes())
          {
            schemaEntry.addAttribute(a);
          }
        }
      }
      finally
      {
        ldifReader.close();
      }
    }

    if (schemaEntry == null)
    {
      return null;
    }

    return new Schema(schemaEntry);
  }



  /**
   * Reads schema information from the provided input stream.  The information
   * should be in LDIF form, with the definitions represented in the form
   * described in section 4.1 of RFC 4512.  Only a single entry will be read
   * from the input stream, and it will be closed at the end of this method.
   *
   * @param  inputStream  The input stream from which the schema entry will be
   *                      read.  It must not be {@code null}, and it will be
   *                      closed when this method returns.
   *
   * @return  The schema read from the provided input stream, or {@code null} if
   *          the end of the input stream is reached without reading any data.
   *
   * @throws  IOException  If a problem is encountered while attempting to read
   *                       from the provided input stream.
   *
   * @throws  LDIFException  If a problem occurs while attempting to parse the
   *                         data read as LDIF.
   */
  public static Schema getSchema(final InputStream inputStream)
         throws IOException, LDIFException
  {
    ensureNotNull(inputStream);

    final LDIFReader ldifReader = new LDIFReader(inputStream);

    try
    {
      final Entry e = ldifReader.readEntry();
      if (e == null)
      {
        return null;
      }
      else
      {
        return new Schema(e);
      }
    }
    finally
    {
      ldifReader.close();
    }
  }



  /**
   * Retrieves a schema object that contains definitions for a number of
   * standard attribute types and object classes from LDAP-related RFCs and
   * Internet Drafts.
   *
   * @return  A schema object that contains definitions for a number of standard
   *          attribute types and object classes from LDAP-related RFCs and
   *          Internet Drafts.
   *
   * @throws  LDAPException  If a problem occurs while attempting to obtain or
   *                         parse the default standard schema definitions.
   */
  public static Schema getDefaultStandardSchema()
         throws LDAPException
  {
    final Schema s = DEFAULT_STANDARD_SCHEMA.get();
    if (s != null)
    {
      return s;
    }

    synchronized (DEFAULT_STANDARD_SCHEMA)
    {
      try
      {
        final ClassLoader classLoader = Schema.class.getClassLoader();
        final InputStream inputStream =
             classLoader.getResourceAsStream(DEFAULT_SCHEMA_RESOURCE_PATH);
        final LDIFReader ldifReader = new LDIFReader(inputStream);
        final Entry schemaEntry = ldifReader.readEntry();
        ldifReader.close();

        final Schema schema = new Schema(schemaEntry);
        DEFAULT_STANDARD_SCHEMA.set(schema);
        return schema;
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_SCHEMA_CANNOT_LOAD_DEFAULT_DEFINITIONS.get(
                  getExceptionMessage(e)),
             e);
      }
    }
  }



  /**
   * Retrieves a schema containing all of the elements of each of the provided
   * schemas.
   *
   * @param  schemas  The schemas to be merged.  It must not be {@code null} or
   *                  empty.
   *
   * @return  A merged representation of the provided schemas.
   */
  public static Schema mergeSchemas(final Schema... schemas)
  {
    if ((schemas == null) || (schemas.length == 0))
    {
      return null;
    }
    else if (schemas.length == 1)
    {
      return schemas[0];
    }

    final LinkedHashMap<String,String> asMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> atMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> dcrMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<Integer,String> dsrMap =
         new LinkedHashMap<Integer,String>();
    final LinkedHashMap<String,String> mrMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> mruMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> nfMap =
         new LinkedHashMap<String,String>();
    final LinkedHashMap<String,String> ocMap =
         new LinkedHashMap<String,String>();

    for (final Schema s : schemas)
    {
      for (final AttributeSyntaxDefinition as : s.asSet)
      {
        asMap.put(toLowerCase(as.getOID()), as.toString());
      }

      for (final AttributeTypeDefinition at : s.atSet)
      {
        atMap.put(toLowerCase(at.getOID()), at.toString());
      }

      for (final DITContentRuleDefinition dcr : s.dcrSet)
      {
        dcrMap.put(toLowerCase(dcr.getOID()), dcr.toString());
      }

      for (final DITStructureRuleDefinition dsr : s.dsrSet)
      {
        dsrMap.put(dsr.getRuleID(), dsr.toString());
      }

      for (final MatchingRuleDefinition mr : s.mrSet)
      {
        mrMap.put(toLowerCase(mr.getOID()), mr.toString());
      }

      for (final MatchingRuleUseDefinition mru : s.mruSet)
      {
        mruMap.put(toLowerCase(mru.getOID()), mru.toString());
      }

      for (final NameFormDefinition nf : s.nfSet)
      {
        nfMap.put(toLowerCase(nf.getOID()), nf.toString());
      }

      for (final ObjectClassDefinition oc : s.ocSet)
      {
        ocMap.put(toLowerCase(oc.getOID()), oc.toString());
      }
    }

    final Entry e = new Entry(schemas[0].getSchemaEntry().getDN());

    final Attribute ocAttr =
         schemas[0].getSchemaEntry().getObjectClassAttribute();
    if (ocAttr == null)
    {
      e.addAttribute("objectClass", "top", "ldapSubEntry", "subschema");
    }
    else
    {
      e.addAttribute(ocAttr);
    }

    if (! asMap.isEmpty())
    {
      final String[] values = new String[asMap.size()];
      e.addAttribute(ATTR_ATTRIBUTE_SYNTAX, asMap.values().toArray(values));
    }

    if (! mrMap.isEmpty())
    {
      final String[] values = new String[mrMap.size()];
      e.addAttribute(ATTR_MATCHING_RULE, mrMap.values().toArray(values));
    }

    if (! atMap.isEmpty())
    {
      final String[] values = new String[atMap.size()];
      e.addAttribute(ATTR_ATTRIBUTE_TYPE, atMap.values().toArray(values));
    }

    if (! ocMap.isEmpty())
    {
      final String[] values = new String[ocMap.size()];
      e.addAttribute(ATTR_OBJECT_CLASS, ocMap.values().toArray(values));
    }

    if (! dcrMap.isEmpty())
    {
      final String[] values = new String[dcrMap.size()];
      e.addAttribute(ATTR_DIT_CONTENT_RULE, dcrMap.values().toArray(values));
    }

    if (! dsrMap.isEmpty())
    {
      final String[] values = new String[dsrMap.size()];
      e.addAttribute(ATTR_DIT_STRUCTURE_RULE, dsrMap.values().toArray(values));
    }

    if (! nfMap.isEmpty())
    {
      final String[] values = new String[nfMap.size()];
      e.addAttribute(ATTR_NAME_FORM, nfMap.values().toArray(values));
    }

    if (! mruMap.isEmpty())
    {
      final String[] values = new String[mruMap.size()];
      e.addAttribute(ATTR_MATCHING_RULE_USE, mruMap.values().toArray(values));
    }

    return new Schema(e);
  }



  /**
   * Retrieves the entry used to create this schema object.
   *
   * @return  The entry used to create this schema object.
   */
  public ReadOnlyEntry getSchemaEntry()
  {
    return schemaEntry;
  }



  /**
   * Retrieves the object class type for the specified object class, recursively
   * checking its parents as needed.
   *
   * @param  oc  The object class definition for which to make the
   *             determination.
   * @param  m   The map of defined object classes.
   *
   * @return  The object class type for the object class.
   */
  private static ObjectClassType getOCType(final ObjectClassDefinition oc,
                                      final Map<String,ObjectClassDefinition> m)
  {
    ObjectClassType t = oc.getObjectClassType();
    if (t != null)
    {
      return t;
    }

    for (final String s : oc.getSuperiorClasses())
    {
      final ObjectClassDefinition d = m.get(toLowerCase(s));
      if (d != null)
      {
        t = getOCType(d, m);
        if (t != null)
        {
          return t;
        }
      }
    }

    return ObjectClassType.STRUCTURAL;
  }



  /**
   * Retrieves the value of the subschemaSubentry attribute from the specified
   * entry using the provided connection.
   *
   * @param  connection  The connection to use in order to perform the search.
   *                     It must not be {@code null}.
   * @param  entryDN     The DN of the entry from which to retrieve the
   *                     subschemaSubentry attribute.  It may be {@code null} or
   *                     an empty string in order to retrieve the value from the
   *                     server's root DSE.
   *
   * @return  The value of the subschemaSubentry attribute from the specified
   *          entry, or {@code null} if it is not available for some reason
   *          (e.g., the client does not have permission to read the target
   *          entry or the subschemaSubentry attribute).
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the specified entry.
   */
  public static String getSubschemaSubentryDN(final LDAPConnection connection,
                                              final String entryDN)
         throws LDAPException
  {
    ensureNotNull(connection);

    final Entry e;
    if (entryDN == null)
    {
      e = connection.getEntry("", SUBSCHEMA_SUBENTRY_REQUEST_ATTRS);
    }
    else
    {
      e = connection.getEntry(entryDN, SUBSCHEMA_SUBENTRY_REQUEST_ATTRS);
    }

    if (e == null)
    {
      return null;
    }

    return e.getAttributeValue(ATTR_SUBSCHEMA_SUBENTRY);
  }



  /**
   * Retrieves the set of attribute syntax definitions contained in the server
   * schema.
   *
   * @return  The set of attribute syntax definitions contained in the server
   *          schema.
   */
  public Set<AttributeSyntaxDefinition> getAttributeSyntaxes()
  {
    return asSet;
  }



  /**
   * Retrieves the attribute syntax with the specified OID from the server
   * schema.
   *
   * @param  oid  The OID of the attribute syntax to retrieve.  It must not be
   *              {@code null}.  It may optionally include a minimum upper bound
   *              (as may appear when the syntax OID is included in an attribute
   *              type definition), but if it does then that portion will be
   *              ignored when retrieving the attribute syntax.
   *
   * @return  The requested attribute syntax, or {@code null} if there is no
   *          such syntax defined in the server schema.
   */
  public AttributeSyntaxDefinition getAttributeSyntax(final String oid)
  {
    ensureNotNull(oid);

    final String lowerOID = toLowerCase(oid);
    final int    curlyPos = lowerOID.indexOf('{');

    if (curlyPos > 0)
    {
      return asMap.get(lowerOID.substring(0, curlyPos));
    }
    else
    {
      return asMap.get(lowerOID);
    }
  }



  /**
   * Retrieves the set of attribute type definitions contained in the server
   * schema.
   *
   * @return  The set of attribute type definitions contained in the server
   *          schema.
   */
  public Set<AttributeTypeDefinition> getAttributeTypes()
  {
    return atSet;
  }



  /**
   * Retrieves the set of operational attribute type definitions (i.e., those
   * definitions with a usage of directoryOperation, distributedOperation, or
   * dSAOperation) contained in the  server  schema.
   *
   * @return  The set of operational attribute type definitions contained in the
   *          server schema.
   */
  public Set<AttributeTypeDefinition> getOperationalAttributeTypes()
  {
    return operationalATSet;
  }



  /**
   * Retrieves the set of user attribute type definitions (i.e., those
   * definitions with a usage of userApplications) contained in the  server
   * schema.
   *
   * @return  The set of user attribute type definitions contained in the server
   *          schema.
   */
  public Set<AttributeTypeDefinition> getUserAttributeTypes()
  {
    return userATSet;
  }



  /**
   * Retrieves the attribute type with the specified name or OID from the server
   * schema.
   *
   * @param  name  The name or OID of the attribute type to retrieve.  It must
   *               not be {@code null}.
   *
   * @return  The requested attribute type, or {@code null} if there is no
   *          such attribute type defined in the server schema.
   */
  public AttributeTypeDefinition getAttributeType(final String name)
  {
    ensureNotNull(name);

    return atMap.get(toLowerCase(name));
  }



  /**
   * Retrieves a list of all subordinate attribute type definitions for the
   * provided attribute type definition.
   *
   * @param  d  The attribute type definition for which to retrieve all
   *            subordinate attribute types.  It must not be {@code null}.
   *
   * @return  A list of all subordinate attribute type definitions for the
   *          provided attribute type definition, or an empty list if it does
   *          not have any subordinate types or the provided attribute type is
   *          not defined in the schema.
   */
  public List<AttributeTypeDefinition> getSubordinateAttributeTypes(
                                            final AttributeTypeDefinition d)
  {
    ensureNotNull(d);

    final List<AttributeTypeDefinition> l = subordinateAttributeTypes.get(d);
    if (l == null)
    {
      return Collections.emptyList();
    }
    else
    {
      return Collections.unmodifiableList(l);
    }
  }



  /**
   * Retrieves the set of DIT content rule definitions contained in the server
   * schema.
   *
   * @return  The set of DIT content rule definitions contained in the server
   *          schema.
   */
  public Set<DITContentRuleDefinition> getDITContentRules()
  {
    return dcrSet;
  }



  /**
   * Retrieves the DIT content rule with the specified name or OID from the
   * server schema.
   *
   * @param  name  The name or OID of the DIT content rule to retrieve.  It must
   *               not be {@code null}.
   *
   * @return  The requested DIT content rule, or {@code null} if there is no
   *          such rule defined in the server schema.
   */
  public DITContentRuleDefinition getDITContentRule(final String name)
  {
    ensureNotNull(name);

    return dcrMap.get(toLowerCase(name));
  }



  /**
   * Retrieves the set of DIT structure rule definitions contained in the server
   * schema.
   *
   * @return  The set of DIT structure rule definitions contained in the server
   *          schema.
   */
  public Set<DITStructureRuleDefinition> getDITStructureRules()
  {
    return dsrSet;
  }



  /**
   * Retrieves the DIT content rule with the specified rule ID from the server
   * schema.
   *
   * @param  ruleID  The rule ID for the DIT structure rule to retrieve.
   *
   * @return  The requested DIT structure rule, or {@code null} if there is no
   *          such rule defined in the server schema.
   */
  public DITStructureRuleDefinition getDITStructureRuleByID(final int ruleID)
  {
    return dsrMapByID.get(ruleID);
  }



  /**
   * Retrieves the DIT content rule with the specified name from the server
   * schema.
   *
   * @param  ruleName  The name of the DIT structure rule to retrieve.  It must
   *                   not be {@code null}.
   *
   * @return  The requested DIT structure rule, or {@code null} if there is no
   *          such rule defined in the server schema.
   */
  public DITStructureRuleDefinition getDITStructureRuleByName(
                                         final String ruleName)
  {
    ensureNotNull(ruleName);

    return dsrMapByName.get(toLowerCase(ruleName));
  }



  /**
   * Retrieves the DIT content rule associated with the specified name form from
   * the server schema.
   *
   * @param  nameForm  The name or OID of the name form for which to retrieve
   *                   the associated DIT structure rule.
   *
   * @return  The requested DIT structure rule, or {@code null} if there is no
   *          such rule defined in the server schema.
   */
  public DITStructureRuleDefinition getDITStructureRuleByNameForm(
                                         final String nameForm)
  {
    ensureNotNull(nameForm);

    return dsrMapByNameForm.get(toLowerCase(nameForm));
  }



  /**
   * Retrieves the set of matching rule definitions contained in the server
   * schema.
   *
   * @return  The set of matching rule definitions contained in the server
   *          schema.
   */
  public Set<MatchingRuleDefinition> getMatchingRules()
  {
    return mrSet;
  }



  /**
   * Retrieves the matching rule with the specified name or OID from the server
   * schema.
   *
   * @param  name  The name or OID of the matching rule to retrieve.  It must
   *               not be {@code null}.
   *
   * @return  The requested matching rule, or {@code null} if there is no
   *          such rule defined in the server schema.
   */
  public MatchingRuleDefinition getMatchingRule(final String name)
  {
    ensureNotNull(name);

    return mrMap.get(toLowerCase(name));
  }



  /**
   * Retrieves the set of matching rule use definitions contained in the server
   * schema.
   *
   * @return  The set of matching rule use definitions contained in the server
   *          schema.
   */
  public Set<MatchingRuleUseDefinition> getMatchingRuleUses()
  {
    return mruSet;
  }



  /**
   * Retrieves the matching rule use with the specified name or OID from the
   * server schema.
   *
   * @param  name  The name or OID of the matching rule use to retrieve.  It
   *               must not be {@code null}.
   *
   * @return  The requested matching rule, or {@code null} if there is no
   *          such matching rule use defined in the server schema.
   */
  public MatchingRuleUseDefinition getMatchingRuleUse(final String name)
  {
    ensureNotNull(name);

    return mruMap.get(toLowerCase(name));
  }



  /**
   * Retrieves the set of name form definitions contained in the server schema.
   *
   * @return  The set of name form definitions contained in the server schema.
   */
  public Set<NameFormDefinition> getNameForms()
  {
    return nfSet;
  }



  /**
   * Retrieves the name form with the specified name or OID from the server
   * schema.
   *
   * @param  name  The name or OID of the name form to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The requested name form, or {@code null} if there is no
   *          such rule defined in the server schema.
   */
  public NameFormDefinition getNameFormByName(final String name)
  {
    ensureNotNull(name);

    return nfMapByName.get(toLowerCase(name));
  }



  /**
   * Retrieves the name form associated with the specified structural object
   * class from the server schema.
   *
   * @param  objectClass  The name or OID of the structural object class for
   *                      which to retrieve the associated name form.  It must
   *                      not be {@code null}.
   *
   * @return  The requested name form, or {@code null} if there is no
   *          such rule defined in the server schema.
   */
  public NameFormDefinition getNameFormByObjectClass(final String objectClass)
  {
    ensureNotNull(objectClass);

    return nfMapByOC.get(toLowerCase(objectClass));
  }



  /**
   * Retrieves the set of object class definitions contained in the server
   * schema.
   *
   * @return  The set of object class definitions contained in the server
   *          schema.
   */
  public Set<ObjectClassDefinition> getObjectClasses()
  {
    return ocSet;
  }



  /**
   * Retrieves the set of abstract object class definitions contained in the
   * server schema.
   *
   * @return  The set of abstract object class definitions contained in the
   *          server schema.
   */
  public Set<ObjectClassDefinition> getAbstractObjectClasses()
  {
    return abstractOCSet;
  }



  /**
   * Retrieves the set of auxiliary object class definitions contained in the
   * server schema.
   *
   * @return  The set of auxiliary object class definitions contained in the
   *          server schema.
   */
  public Set<ObjectClassDefinition> getAuxiliaryObjectClasses()
  {
    return auxiliaryOCSet;
  }



  /**
   * Retrieves the set of structural object class definitions contained in the
   * server schema.
   *
   * @return  The set of structural object class definitions contained in the
   *          server schema.
   */
  public Set<ObjectClassDefinition> getStructuralObjectClasses()
  {
    return structuralOCSet;
  }



  /**
   * Retrieves the object class with the specified name or OID from the server
   * schema.
   *
   * @param  name  The name or OID of the object class to retrieve.  It must
   *               not be {@code null}.
   *
   * @return  The requested object class, or {@code null} if there is no such
   *          class defined in the server schema.
   */
  public ObjectClassDefinition getObjectClass(final String name)
  {
    ensureNotNull(name);

    return ocMap.get(toLowerCase(name));
  }



  /**
   * Retrieves a hash code for this schema object.
   *
   * @return  A hash code for this schema object.
   */
  @Override()
  public int hashCode()
  {
    int hc;
    try
    {
      hc = schemaEntry.getParsedDN().hashCode();
    }
    catch (final Exception e)
    {
      debugException(e);
      hc = toLowerCase(schemaEntry.getDN()).hashCode();
    }

    Attribute a = schemaEntry.getAttribute(ATTR_ATTRIBUTE_SYNTAX);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_MATCHING_RULE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_ATTRIBUTE_TYPE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_OBJECT_CLASS);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_NAME_FORM);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_DIT_CONTENT_RULE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_DIT_STRUCTURE_RULE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    a = schemaEntry.getAttribute(ATTR_MATCHING_RULE_USE);
    if (a != null)
    {
      hc += a.hashCode();
    }

    return hc;
  }



  /**
   * Indicates whether the provided object is equal to this schema object.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this schema
   *          object, or {@code false} if not.
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

    if (! (o instanceof Schema))
    {
      return false;
    }

    final Schema s = (Schema) o;

    try
    {
      if (! schemaEntry.getParsedDN().equals(s.schemaEntry.getParsedDN()))
      {
        return false;
      }
    }
    catch (final Exception e)
    {
      debugException(e);
      if (! schemaEntry.getDN().equalsIgnoreCase(s.schemaEntry.getDN()))
      {
        return false;
      }
    }

    return (asSet.equals(s.asSet) &&
         mrSet.equals(s.mrSet) &&
         atSet.equals(s.atSet) &&
         ocSet.equals(s.ocSet) &&
         nfSet.equals(s.nfSet) &&
         dcrSet.equals(s.dcrSet) &&
         dsrSet.equals(s.dsrSet) &&
         mruSet.equals(s.mruSet));
  }



  /**
   * Retrieves a string representation of the associated schema entry.
   *
   * @return  A string representation of the associated schema entry.
   */
  @Override()
  public String toString()
  {
    return schemaEntry.toString();
  }
}
