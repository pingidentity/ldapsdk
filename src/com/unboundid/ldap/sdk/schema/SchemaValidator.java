/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.schema.SchemaMessages.*;



/**
 * This class provides a mechanism form validating definitions in an LDAP
 * schema.  Schema elements are expected to be read from one or more LDIF files
 * containing subschema subentries as described in
 * <A HREF="http://www.ietf.org/rfc/rfc4512.txt">RFC 4512</A> section 4.2, with
 * elements defined using the syntaxes described in section 4.1 of the same
 * specification.
 * <BR><BR>
 * This schema validator can perform the following checks:
 * <UL>
 *   <LI>It ensures that each schema element can be parsed.</LI>
 *   <LI>It ensures that element names and OIDs are properly formed, optionally
 *       allowing for more lax validation that some servers may permit.</LI>
 *   <LI>It ensures that each schema element does not reference any undefined
 *       schema elements.</LI>
 *   <LI>It can verify that each element is only defined once.</LI>
 *   <LI>It can optionally determine whether definitions may use functionality
 *       that some servers do not support.</LI>
 *   <LI>It can verify that schema entries are valid in accordance with the
 *       schema it contains.</LI>
 *   <LI>It can optionally ensure that schema files are named using an
 *       expected pattern.</LI>
 *   <LI>It can optionally validate extensions used in schema elements.</LI>
 * </UL>
 *
 * It ensures that all definitions can be parsed, contain valid
 * content, do not reference any undefined schema elements, etc.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class SchemaValidator
{
  /**
   * Indicates whether an instance of the Ping Identity Directory Server is
   * available.
   */
  static final boolean PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE;



  /**
   * The path to the schema directory for the available Ping Identity Directory
   * Server instance.
   */
  @Nullable static final File PING_IDENTITY_DIRECTORY_SERVER_SCHEMA_DIR;



  static
  {
    boolean pingIdentityDSAvailable = false;
    File schemaDir = null;

    try
    {
      final File instanceRoot = InternalSDKHelper.getPingIdentityServerRoot();
      if (instanceRoot != null)
      {
        final File instanceRootSchemaDir =
             StaticUtils.constructPath(instanceRoot, "config", "schema");
        if (new File(instanceRootSchemaDir, "00-core.ldif").exists())
        {
          // Try to see if we can load the server's schema class.  If so, then
          // we'll assume that we are running with access to a Ping Identity
          // Directory Server, and we'll tailor the defaults accordingly.
          // If this fails, we'll just go with the defaults.
          Class.forName("com.unboundid.directory.server.types.Schema");

          pingIdentityDSAvailable = true;
          schemaDir = instanceRootSchemaDir;
        }
      }
    }
    catch (final Throwable t)
    {
      // This is fine.  We're just not running with access to a Ping Identity
      // Directory Server.
    }

    PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE = pingIdentityDSAvailable;
    PING_IDENTITY_DIRECTORY_SERVER_SCHEMA_DIR = schemaDir;
  }



  // Indicates whether to allow attribute type definitions that do not include
  // an equality matching rule and do not include a superior type.
  private boolean allowAttributeTypesWithoutEqualityMatchingRule;

  // Indicates whether to allow attribute type definitions that do not include
  // an attribute syntax OID and do not include a superior type.
  private boolean allowAttributeTypesWithoutSyntax;

  // Indicates whether to allow attribute type definitions that are defined with
  // the COLLECTIVE indicator.
  private boolean allowCollectiveAttributes;

  // Indicates whether to allow schema elements that do not have names.
  private boolean allowElementsWithoutNames;

  // Indicates whether to allow schema elements to contain an empty DESC
  // component.
  private boolean allowEmptyDescription;

  // Indicates whether to allow invalid object class inheritance.
  private boolean allowInvalidObjectClassInheritance;

  // Indicates whether to allow a single schema file to contain multiple
  // entries.
  private boolean allowMultipleEntriesPerFile;

  // Indicates whether to allow object classes to contain multiple superior
  // classes.
  private boolean allowMultipleSuperiorObjectClasses;

  // Indicates whether to allow LDAP names to start with a digit.
  private boolean allowNamesWithInitialDigit;

  // Indicates whether to allow LDAP names to start with a hyphen.
  private boolean allowNamesWithInitialHyphen;

  // Indicates whether to allow LDAP names to contain the underscore character.
  private boolean allowNamesWithUnderscore;

  // Indicates whether to allow schema elements to contain non-numeric OIDs that
  // are not of the form "name-oid".
  private boolean allowNonNumericOIDsNotUsingName;

  // Indicates whether to allow schema elements to contain non-numeric OIDs that
  // are of the form "name-oid".
  private boolean allowNonNumericOIDsUsingName;

  // Indicates whether to allow attribute type definitions that are defined with
  // the OBSOLETE indicator.
  private boolean allowObsoleteElements;

  // Indicates whether to allow multiple definitions for the same schema
  // element.
  private boolean allowRedefiningElements;

  // Indicates whether to support a schema directory with schema files in
  // subdirectories.
  private boolean allowSchemaFilesInSubDirectories;

  // Indicates whether to allow structural object classes that do not define a
  // superior class.
  private boolean allowStructuralObjectClassWithoutSuperior;

  // Indicates whether to ensure that the entries containing schema definitions
  // are themselves valid in accordance with the schema elements that have been
  // read.
  private boolean ensureSchemaEntryIsValid;

  // Indicates whether to ignore files contained in a schema directory that do
  // not match the configured file name pattern.
  private boolean ignoreSchemaFilesNotMatchingFileNamePattern;

  // Indicates whether to use strict validation when examining numeric OIDs.
  private boolean useStrictOIDValidation;

  // A list of attribute syntax definitions to use when validating attribute
  // type definitions.
  @NotNull private List<AttributeSyntaxDefinition> attributeSyntaxList;

  // A list of matching rule definitions to use when validating attribute type
  // definitions.
  @NotNull private List<MatchingRuleDefinition> matchingRuleList;

  // A map of attribute syntax definitions to use when validating attribute type
  // definitions.
  @NotNull private Map<String,AttributeSyntaxDefinition> attributeSyntaxMap;

  // A map of matching rule definitions to use when validating attribute type
  // definitions.
  @NotNull private Map<String,MatchingRuleDefinition> matchingRuleMap;

  // The pattern that files containing schema definitions are expected to match.
  @Nullable private Pattern schemaFileNamePattern;

  // The set of schema element types that are allowed to be present in schema
  // files.
  @NotNull private final Set<SchemaElementType> allowedSchemaElementTypes;

  // The set of schema element types that other elements may be allowed to
  // reference without the referenced type being defined.
  @NotNull private final Set<SchemaElementType>
       allowReferencesToUndefinedElementTypes;



  /**
   * Creates a new schema validator with the default settings.
   */
  public SchemaValidator()
  {
    allowAttributeTypesWithoutEqualityMatchingRule = true;
    allowAttributeTypesWithoutSyntax = PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE;
    allowCollectiveAttributes = (! PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE);
    allowElementsWithoutNames = true;
    allowEmptyDescription = false;
    allowInvalidObjectClassInheritance = false;
    allowMultipleEntriesPerFile = false;
    allowMultipleSuperiorObjectClasses =
         (! PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE);
    allowNamesWithInitialDigit = false;
    allowNamesWithInitialHyphen = false;
    allowNamesWithUnderscore = false;
    allowNonNumericOIDsNotUsingName = false;
    allowNonNumericOIDsUsingName = false;
    allowObsoleteElements = true;
    allowRedefiningElements = false;
    allowSchemaFilesInSubDirectories = false;
    allowStructuralObjectClassWithoutSuperior = false;
    ensureSchemaEntryIsValid = true;
    ignoreSchemaFilesNotMatchingFileNamePattern =
         (! PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE);
    useStrictOIDValidation = true;
    attributeSyntaxMap = new LinkedHashMap<>();
    attributeSyntaxList = new ArrayList<>();
    matchingRuleMap = new LinkedHashMap<>();
    matchingRuleList = new ArrayList<>();
    schemaFileNamePattern = null;
    allowedSchemaElementTypes = EnumSet.allOf(SchemaElementType.class);
    allowReferencesToUndefinedElementTypes =
         EnumSet.noneOf(SchemaElementType.class);

    if (PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE)
    {
      configureLDAPSDKDefaultAttributeSyntaxes();
      configureLDAPSDKDefaultMatchingRules();

      schemaFileNamePattern = Pattern.compile("^\\d\\d-.+\\.ldif$");
    }
  }



  /**
   * Retrieves the pattern that schema file names are expected to match.  By
   * default, no schema file name pattern is defined, so there are no
   * restrictions on the name that a schema file may have.
   *
   * @return  The pattern that schema file names are expected to match, or
   *          {@code null} if no schema file name pattern is defined.
   */
  @Nullable()
  public Pattern getSchemaFileNamePattern()
  {
    return schemaFileNamePattern;
  }



  /**
   * Indicates whether to ignore any files in a schema directory that do not
   * match the value pattern (if one is defined).  By default, if a file name
   * pattern is defined, then any files whose names do not match that pattern
   * will be ignored.
   *
   * @return  {@code true} if files not matching the defined value pattern
   *          should be ignored, or {@code false} if they should not be ignored
   *          but a warning should be generated.
   */
  public boolean ignoreSchemaFilesNotMatchingFileNamePattern()
  {
    return ignoreSchemaFilesNotMatchingFileNamePattern;
  }



  /**
   * Specifies a pattern that may be used to indicate which files should be
   * examined if a provided path is a directory rather than a file.
   *
   * @param  schemaFileNamePattern
   *              A regular expression that may be used to specify the pattern
   *              that schema file names are expected to match.  This may be
   *              {@code null} if no pattern is defined and any identified files
   *              will be processed.
   * @param  ignoreSchemaFilesNotMatchingFileNamePattern
   *              Specifies whether to ignore any files in a schema directory
   *              that do not match the value pattern (if one is defined).  This
   *              will only have an effect when attempting to parse schema
   *              definitions from a path that references a directory rather
   *              than a file.  If this is {@code true} then any files that do
   *              not match the pattern (if it is non-{@code null} will be
   *              skipped.  If this is {@code false}, then all files will be
   *              parsed even if they do not match the value pattern, but a
   *              warning will be added to the message list for each file that
   *              does not match the pattern.  If the path provided to the
   *              {@link #validateSchema} method refers to a file rather than a
   *              directory, then the file will always be processed, but a
   *              warning message will be added to the given list if the name
   *              does not match the given pattern.
   */
  public void setSchemaFileNamePattern(
                   @Nullable final Pattern schemaFileNamePattern,
                   final boolean ignoreSchemaFilesNotMatchingFileNamePattern)
  {
    this.schemaFileNamePattern = schemaFileNamePattern;
    this.ignoreSchemaFilesNotMatchingFileNamePattern =
         ignoreSchemaFilesNotMatchingFileNamePattern;
  }



  /**
   * Indicates whether a schema file is allowed to contain multiple entries.
   * By default, each schema file is expected to have exactly one entry.
   *
   * @return  {@code true} if a schema file may have multiple entries and all
   *          entries contained in that file should be processed, or
   *          {@code false} if a schema file should only have a single entry
   *          and additional entries will be ignored and an error message
   *          reported.
   */
  public boolean allowMultipleEntriesPerFile()
  {
    return allowMultipleEntriesPerFile;
  }



  /**
   * Specifies whether a schema file is allowed to contain multiple entries.
   *
   * @param  allowMultipleEntriesPerFile
   *              Indicates whether a schema file is allowed to contain multiple
   *              entries.  If this is {@code true}, then all entries in each
   *              file will be examined.  If this is {@code false}, then only
   *              the first entry in each file will be examined and an error
   *              message will be reported for each file that contains multiple
   *              entries.  In either case, an error will be reported for each
   *              schema file that does not contain any entries or that contains
   *              a malformed entry.
   */
  public void setAllowMultipleEntriesPerFile(
                   final boolean allowMultipleEntriesPerFile)
  {
    this.allowMultipleEntriesPerFile = allowMultipleEntriesPerFile;
  }



  /**
   * Indicates whether to examine files in subdirectories when provided with a
   * schema path that is a directory.  By default, subdirectories will not be
   * examined and an error will be reported for each subdirectory that is
   * encountered.
   *
   * @return  {@code true} to examine files in subdirectories when provided with
   *          a schema path that is a directory, or {@code false} if only
   *          files directly contained in the provided directory will be
   *          examined and an error will be reported if the schema directory
   *          contains subdirectories.
   */
  public boolean allowSchemaFilesInSubDirectories()
  {
    return allowSchemaFilesInSubDirectories;
  }



  /**
   * Specifies whether to examine files in subdirectories when provided with a
   * schema path that is a directory.  This setting will be ignored if the
   * {@link #validateSchema} method is called with a schema path that is a file
   * rather than a directory.
   *
   * @param  allowSchemaFilesInSubDirectories
   *              Indicates whether to examine files in subdirectories when
   *              provided with a schema path that is a directory.  If this is
   *              {@code true}, then files in subdirectories will be examined,
   *              to any depth, with files in the directory processed first
   *              (in lexicographic order by name) and then subdirectories will
   *              be processed (also in lexicographic order by name).  if this
   *              is {@code false}, then only files contained directly in the
   *              specified schema directory will be examined and an error
   *              will be reported for each subdirectory that is encountered.
   */
  public void setAllowSchemaFilesInSubDirectories(
                   final boolean allowSchemaFilesInSubDirectories)
  {
    this.allowSchemaFilesInSubDirectories = allowSchemaFilesInSubDirectories;
  }



  /**
   * Indicates whether to validate each entry containing the schema definitions
   * using the schema that has been parsed thus far.  By default, each entry
   * will be validated to ensure that its contents conform to the schema that
   * has been parsed from that file and all previous files.
   *
   * @return  {@code true} if entries containing schema definitions should be
   *          validated according to the schema, or {@code false} if schema
   *          entries will not themselves be validated against the schema.
   */
  public boolean ensureSchemaEntryIsValid()
  {
    return ensureSchemaEntryIsValid;
  }



  /**
   * Specifies whether to validate each entry containing the schema definitions
   * using the schema that has been parsed thus far.
   *
   * @param  ensureSchemaEntryIsValid
   *              Indicates whether to validate each entry containing the schema
   *              definitions using the schema that has been parsed thus far.
   *              If this is {@code true}, then each entry will be validated
   *              to ensure that it conforms to the schema definitions read from
   *              that file and any previuos files that have already been
   *              processed and any errors identified will be reported  If this
   *              is {@code false}, then schema entries will not be validated.
   */
  public void setEnsureSchemaEntryIsValid(
                   final boolean ensureSchemaEntryIsValid)
  {
    this.ensureSchemaEntryIsValid = ensureSchemaEntryIsValid;
  }



  /**
   * Retrieves an unmodifiable set of the schema element types that may be
   * defined in schema files.  By default, all types of schema elements may be
   * defined.
   *
   * @return  An unmodifiable set set of the schema element types that may be
   *          defined in schema files.
   */
  @NotNull()
  public Set<SchemaElementType> getAllowedSchemaElementTypes()
  {
    return Collections.unmodifiableSet(allowedSchemaElementTypes);
  }



  /**
   * Specifies the set of schema element types that may be defined in schema
   * files.
   *
   * @param  allowedSchemaElementTypes
   *              The set of schema element types that may be defined in schema
   *              files.  It must not be {@code null} or empty.
   */
  public void setAllowedSchemaElementTypes(
       @NotNull final SchemaElementType... allowedSchemaElementTypes)
  {
    setAllowedSchemaElementTypes(StaticUtils.toList(allowedSchemaElementTypes));
  }



  /**
   * Specifies the set of schema element types that may be defined in schema
   * files.
   *
   * @param  allowedSchemaElementTypes
   *              The set of schema element types that may be defined in schema
   *              files.  It must not be {@code null} or empty.
   */
  public void setAllowedSchemaElementTypes(
       @NotNull final Collection<SchemaElementType> allowedSchemaElementTypes)
  {
    Validator.ensureTrue(
         ((allowedSchemaElementTypes != null) &&
              (! allowedSchemaElementTypes.isEmpty())),
         "SchemaValidator.allowedSchemaElementTypes must not be null or " +
              "empty.");

    this.allowedSchemaElementTypes.clear();
    this.allowedSchemaElementTypes.addAll(allowedSchemaElementTypes);
  }



  /**
   * Retrieves the types of schema elements that can be referenced by other
   * elements without the referenced types being known to the schema validator
   * (e.g., by having been previously defined in the schema files).  By default,
   * no types of undefined elements may be referenced.
   *
   * @return  The types of schema elements that can be referenced by other
   *          elements without the referenced types being known to the schema
   *          validator,
   */
  @NotNull()
  public Set<SchemaElementType> getAllowReferencesToUndefinedElementTypes()
  {
    return Collections.unmodifiableSet(allowReferencesToUndefinedElementTypes);
  }



  /**
   * Specifies the types of schema elements that can be referenced by other
   * elements without the referenced types being known to the schema validator
   * (e.g., by having been previously defined in the schema files).
   *
   * @param  undefinedElementTypes
   *              The types of schema elements that can be referenced by other
   *              elements without the referenced types being known to the
   *              schema validator.  It may be {@code null} or empty if no
   *              undefined schema elements will be permitted.
   */
  public void setAllowReferencesToUndefinedElementTypes(
       @Nullable final SchemaElementType... undefinedElementTypes)
  {
    setAllowReferencesToUndefinedElementTypes(
         StaticUtils.toList(undefinedElementTypes));
  }



  /**
   * Specifies the types of schema elements that can be referenced by other
   * elements without the referenced types being known to the schema validator
   * (e.g., by having been previously defined in the schema files).
   *
   * @param  undefinedElementTypes
   *              The types of schema elements that can be referenced by other
   *              elements without the referenced types being known to the
   *              schema validator.  It may be {@code null} or empty if no
   *              undefined schema elements will be permitted.
   */
  public void setAllowReferencesToUndefinedElementTypes(
       @Nullable final Collection<SchemaElementType> undefinedElementTypes)
  {
    allowReferencesToUndefinedElementTypes.clear();
    if (undefinedElementTypes != null)
    {
      allowReferencesToUndefinedElementTypes.addAll(undefinedElementTypes);
    }
  }



  /**
   * Indicates whether the same schema element may be defined multiple times.
   * By default, each schema element may be defined only once.
   *
   * @return  {@code true} if the same schema element may be defined multiple
   *          times, in which case subsequent definitions will override previous
   *          definitions, or {@code false} if an error will be reported if the
   *          same element is encountered multiple times.
   */
  public boolean allowRedefiningElements()
  {
    return allowRedefiningElements;
  }



  /**
   * Specifies whether the same schema element may be defined multiple times.
   *
   * @param  allowRedefiningElements
   *              Indicates whether the same schema element may be defined
   *              multiple times.  If this is {@code true}, then a schema
   *              element may be defined multiple times, with the most recent
   *              definition ultimately being used, as long as the redefined
   *              definition keeps the same OID and names of the former
   *              definition (although the redefined element may add additional
   *              names), but other details may be changed.  If this is
   *              {@code false}, then any attempt to define the same element
   *              multiple times will be reported as an error.
   */
  public void setAllowRedefiningElements(final boolean allowRedefiningElements)
  {
    this.allowRedefiningElements = allowRedefiningElements;
  }



  /**
   * Indicates whether to allow schema elements that do not contain names but
   * may only be identified by an OID (or by the rule ID in the case of DIT
   * structure rules).  Note that this does not apply to attribute syntaxes,
   * which cannot have names and may only be referenced by OID.  LDAP does allow
   * schema elements without names, but such elements are not as user-friendly
   * and it may not be desirable to have such definitions.  By default, the
   * schema validator will allow elements without names.
   *
   * @return  {@code true} if the schema validator will elements without names,
   *          or {@code false} if an error will be reported for each schema
   *          element (other than attribute syntaxes) without a name.
   */
  public boolean allowElementsWithoutNames()
  {
    return allowElementsWithoutNames;
  }



  /**
   * Specifies whether to allow schema elements that do not contain names but
   * may only be identified by an OID (or by the rule ID in the case of DIT
   * structure rules).  Note that this does not apply to attribute syntaxes,
   * which cannot have names and may only be referenced by OID.  LDAP does allow
   * schema elements without names, but such elements are not as user-friendly
   * and it may not be desirable to have such definitions.
   *
   * @param  allowElementsWithoutNames
   *              Indicates whether to allow schema elements that do not contain
   *              names.  If this is {@code true}, then elements without names
   *              will be allowed.  If this is {@code false}, then an error will
   *              be reported for each element (other than attribute syntaxes)
   *              that does not have a name.
   */
  public void setAllowElementsWithoutNames(
                   final boolean allowElementsWithoutNames)
  {
    this.allowElementsWithoutNames = allowElementsWithoutNames;
  }



  /**
   * Indicates whether schema elements will be permitted to include non-numeric
   * object identifiers that are comprised of the name for that element with
   * "-oid" appended to it.  For example, if an attribute is named "my-attr",
   * then "my-attr-oid" may be allowed as an alternative to a numeric OID.
   * While the official specification requires valid numeric OIDs, some servers
   * are more relaxed about this requirement and allow OIDs to use the alternate
   * form referenced above.  By default, valid numeric OIDs will be required.
   *
   * @return  {@code true} if non-numeric OIDs will be allowed if they are
   *          comprised of the schema element name followed by "-oid", or
   *          {@code false} if not.
   */
  public boolean allowNonNumericOIDsUsingName()
  {
    return allowNonNumericOIDsUsingName;
  }



  /**
   * Indicates whether schema elements will be permitted to include non-numeric
   * object identifiers that are of a form other than one of the element names
   * followed by "-oid".  By default, valid numeric OIDs will be required.
   *
   * @return  {@code true} if non-numeric OIDs will be allowed if they are not
   *          comprised of the schema element name followed by "-oid", or
   *          {@code false} if not.
   */
  public boolean allowNonNumericOIDsNotUsingName()
  {
    return allowNonNumericOIDsNotUsingName;
  }



  /**
   * Indicates whether to use strict validation for numeric object identifiers.
   * If strict validation is to be used, then each OID must contain at least two
   * components, the first component must be zero, one or, two, and the second
   * component may only be greater than 39 if the first component is two.  By
   * default, strict validation will be performed for numeric OIDs.
   *
   * @return  {@code true} if strict validation will be performed for numeric
   *          OIDs, or {@code false} if more relaxed validation will be used
   *          that only requires them to be comprised of a non-empty string
   *          comprised only of digits and periods that does not start or end
   *          with a period and does not contain consecutive periods.
   */
  public boolean useStrictOIDValidation()
  {
    return useStrictOIDValidation;
  }



  /**
   * Specifies the behavior to use when validating object identifiers.
   *
   * @param  allowNonNumericOIDsUsingName
   *              Indicates whether to allow non-numeric OIDs if they are
   *              comprised of the name for the schema element followed by
   *              "-oid".  If this is {@code true}, then non-numeric OIDs will
   *              be allowed if they use that form.  If this is {@code false},
   *              then an error will be reported for schema elements with a
   *              non-numeric OID in that form.
   * @param  allowNonNumericOIDsNotUsingName
   *              Indicates whether to allow non-numeric OIDs if they are not
   *              comprised of the name for the schema element followed by
   *              "-oid".  If this is {@code true}, then non-numeric OIDs will
   *              be allowed if they use that form.  If this is {@code false},
   *              then an error will be reported for schema elements with a
   *              non-numeric OID that does not use the element name.
   * @param  useStrictOIDValidation
   *              Indicates whether to use strict validation for numeric
   *              object identifiers.  If this is {@code false}, then numeric
   *              OIDs will be required to be comprised entirely of digits and
   *              periods, must not start or end with a period, and must not
   *              contain consecutive periods.  If this is {@code true}, then
   *              numeric OIDs must also consist of at least two components,
   *              the first component must be zero, one or two, and the second
   *              component may only be greater than 39 if the first component
   *              is two.
   */
  public void setOIDValidation(final boolean allowNonNumericOIDsUsingName,
                               final boolean allowNonNumericOIDsNotUsingName,
                               final boolean useStrictOIDValidation)
  {
    this.allowNonNumericOIDsUsingName = allowNonNumericOIDsUsingName;
    this.allowNonNumericOIDsNotUsingName = allowNonNumericOIDsNotUsingName;
    this.useStrictOIDValidation = useStrictOIDValidation;
  }



  /**
   * Indicates whether to allow schema element names that start with a digit.
   * LDAP specifications require that the first character of a schema element
   * name be a letter, but some servers allow names that start with digits.  By
   * default, schema element names will not be allowed to start with a digit.
   *
   * @return  {@code true} if schema element names will be permitted to start
   *          with digits, or {@code false} if an error will be reported for
   *          names that start with a digit.
   */
  public boolean allowNamesWithInitialDigit()
  {
    return allowNamesWithInitialDigit;
  }



  /**
   * Specifies whether to allow schema element names that start with a digit.
   * LDAP specifications require that the first character of a schema element
   * name be a letter, but some servers allow names that start with digits.
   *
   * @param  allowNamesWithInitialDigit
   *              Indicates whether to allow schema element names that start
   *              with a digit.  If this is {@code true}, then names will be
   *              permitted to start with a digit.  If this is {@code false},
   *              then an error will be reported for each name that starts with
   *              a digit.
   */
  public void setAllowNamesWithInitialDigit(
                   final boolean allowNamesWithInitialDigit)
  {
    this.allowNamesWithInitialDigit = allowNamesWithInitialDigit;
  }



  /**
   * Indicates whether to allow schema element names that start with a hyphen.
   * LDAP specifications require that the first character of a schema element
   * name be a letter, but some servers allow names that start with hyphens.  By
   * default, schema element names will not be allowed to start with a hyphen.
   *
   * @return  {@code true} if schema element names will be permitted to start
   *          with hyphens, or {@code false} if an error will be reported for
   *          names that start with a hyphen.
   */
  public boolean allowNamesWithInitialHyphen()
  {
    return allowNamesWithInitialHyphen;
  }



  /**
   * Specifies whether to allow schema element names that start with a hyphen.
   * LDAP specifications require that the first character of a schema element
   * name be a letter, but some servers allow names that start with hyphens.
   *
   * @param  allowNamesWithInitialHyphen
   *              Indicates whether to allow schema element names that start
   *              with a hyphen.  If this is {@code true}, then names will be
   *              permitted to start with a hyphen.  If this is {@code false},
   *              then an error will be reported for each name that starts with
   *              a hyphen.
   */
  public void setAllowNamesWithInitialHyphen(
                   final boolean allowNamesWithInitialHyphen)
  {
    this.allowNamesWithInitialHyphen = allowNamesWithInitialHyphen;
  }



  /**
   * Indicates whether to allow schema element names that contain the underscore
   * character.  LDAP specifications do not permit underscores in schema element
   * names, but some servers do allow it.  By default, schema element names will
   * not be allowed to contain an underscore.
   *
   * @return  {@code true} if schema element names will be permitted to contain
   *          underscores, or {@code false} if an error will be reported for
   *          names that contain an underscore.
   */
  public boolean allowNamesWithUnderscore()
  {
    return allowNamesWithUnderscore;
  }



  /**
   * Indicates whether to allow schema element names that contain the underscore
   * character.  LDAP specifications do not permit underscores in schema element
   * names, but some servers do allow it.
   *
   * @param  allowNamesWithUnderscore
   *              Indicates whether to allow schema element names that contain
   *              the underscore character.  If this is {@code true}, then names
   *              will be permitted to contain underscores.  If this is
   *              {@code false}, then an error will be reported for each name
   *              that contains an underscore.
   */
  public void setAllowNamesWithUnderscore(
                   final boolean allowNamesWithUnderscore)
  {
    this.allowNamesWithUnderscore = allowNamesWithUnderscore;
  }



  /**
   * Indicates whether to allow schema elements to have empty descriptions.
   * LDAP specifications forbid empty quoted strings in schema definitions, but
   * some servers allow it.  By default, empty descriptions will not be allowed,
   * and an error will be reported for every schema element that has an empty
   * description.
   *
   * @return  {@code true} if empty descriptions will be allowed, or
   *          {@code false} if errors will be reported for schema elements with
   *          empty descriptions.
   */
  public boolean allowEmptyDescription()
  {
    return allowEmptyDescription;
  }



  /**
   * Specifies whether to allow schema elements to have empty descriptions.
   * LDAP specifications forbid empty quoted strings in schema definitions, but
   * some servers allow it.
   *
   * @param  allowEmptyDescription
   *              Indicates whether to allow schema elements to have empty
   *              descriptions.  If this is {@code true}, then schema elements
   *              will be permitted to have empty descriptions.  If it is
   *              {@code false}, then an error will be reported for each
   *              schema element with an empty description.
   */
  public void setAllowEmptyDescription(final boolean allowEmptyDescription)
  {
    this.allowEmptyDescription = allowEmptyDescription;
  }



  /**
   * Retrieves a list of the attribute syntaxes that will be used in the course
   * of validating attribute type definitions.  By default, the schema validator
   * will be preconfigured with a default set of standard attribute syntaxes
   * (as set by the {@link #configureLDAPSDKDefaultAttributeSyntaxes} method),
   * in addition to any attribute type definitions contained in schema entries.
   *
   * @return  A list of the attribute syntaxes that will be used in the course
   *          of validating attribute type definitions, or an empty list if the
   *          list of available syntaxes will be defined in the schema files.
   */
  @NotNull()
  public List<AttributeSyntaxDefinition> getAttributeSyntaxes()
  {
    return Collections.unmodifiableList(new ArrayList<>(attributeSyntaxList));
  }



  /**
   * Specifies a set of attribute syntaxes that will be used in the course
   * of validating attribute type definitions.
   *
   * @param  attributeSyntaxes
   *              The set of attribute syntaxes that will be used in the course
   *              of validating attribute type definitions.  It may be
   *              {@code null} or empty if only syntaxes defined in the schema
   *              files will be used.
   */
  public void setAttributeSyntaxes(
       @Nullable final Collection<AttributeSyntaxDefinition> attributeSyntaxes)
  {
    attributeSyntaxList = new ArrayList<>();
    attributeSyntaxMap = new HashMap<>();

    if (attributeSyntaxes != null)
    {
      for (final AttributeSyntaxDefinition d : attributeSyntaxes)
      {
        attributeSyntaxList.add(d);
        attributeSyntaxMap.put(StaticUtils.toLowerCase(d.getOID()), d);
      }
    }
  }



  /**
   * Configures the schema validator to use a default set of attribute syntaxes
   * that are known to the LDAP SDK.  Any other syntaxes that may have been
   * defined will be cleared.
   */
  public void configureLDAPSDKDefaultAttributeSyntaxes()
  {
    try
    {
      final Set<AttributeSyntaxDefinition> defaultSyntaxes =
           new LinkedHashSet<>();
      final Schema schema = Schema.getDefaultStandardSchema();
      defaultSyntaxes.addAll(schema.getAttributeSyntaxes());

      if (PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE)
      {
        defaultSyntaxes.add(new AttributeSyntaxDefinition(
             "( 1.3.6.1.4.1.30221.1.3.1 DESC 'User Password Syntax' )"));
        defaultSyntaxes.add(new AttributeSyntaxDefinition(
             "( 1.3.6.1.4.1.30221.1.3.2 " +
                  "DESC 'Relative Subtree Specification' )"));
        defaultSyntaxes.add(new AttributeSyntaxDefinition(
             "( 1.3.6.1.4.1.30221.1.3.3 " +
                  "DESC 'Absolute Subtree Specification' )"));
        defaultSyntaxes.add(new AttributeSyntaxDefinition(
             "( 1.3.6.1.4.1.30221.1.3.4 " +
                  "DESC 'Sun-defined Access Control Information' )"));
        defaultSyntaxes.add(new AttributeSyntaxDefinition(
             "( 1.3.6.1.4.1.30221.2.3.1 DESC 'Compact Timestamp' )"));
        defaultSyntaxes.add(new AttributeSyntaxDefinition(
             "( 1.3.6.1.4.1.30221.2.3.2 DESC 'LDAP URL' )"));
        defaultSyntaxes.add(new AttributeSyntaxDefinition(
             "( 1.3.6.1.4.1.30221.2.3.3 DESC 'Hex String' )"));
        defaultSyntaxes.add(new AttributeSyntaxDefinition(
             "( 1.3.6.1.4.1.30221.2.3.4 DESC 'JSON Object' )"));
      }

      setAttributeSyntaxes(defaultSyntaxes);
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
    }
  }



  /**
   * Indicates whether to allow attribute type definitions to be missing an
   * attribute syntax definition, by neither directly specifying the attribute
   * syntax OID nor referencing a superior attribute type from which the syntax
   * will be inherited.  The LDAP specification requires that each attribute
   * type specify its syntax or inherit it from a superior type, but some
   * directory servers will assume a default syntax (e.g., Directory String) for
   * attribute types that do not specify it and are not configured with a
   * superior type.  By default, any attribute type that does not specify a
   * syntax and cannot inherit it from a superior type will be flagged as an
   * error.
   *
   * @return  {@code true} if attribute type definitions will be permitted to
   *          omit both an attribute syntax and a superior type, or
   *          {@code false} if an error will be reported for each such attribute
   *          type.
   */
  public boolean allowAttributeTypesWithoutSyntax()
  {
    return allowAttributeTypesWithoutSyntax;
  }



  /**
   * Specifies whether to allow attribute type definitions to be missing an
   * attribute syntax definition, by neither directly specifying the attribute
   * syntax OID nor referencing a superior attribute type from which the syntax
   * will be inherited.  The LDAP specification requires that each attribute
   * type specify its syntax or inherit it from a superior type, but some
   * directory servers will assume a default syntax (e.g., Directory String) for
   * attribute types that do not specify it and are not configured with a
   * superior type.
   *
   * @param  allowAttributeTypesWithoutSyntax
   *              Indicates whether to allow attribute type definitions to be
   *              missing an attribute syntax definition, by neither directly
   *              specifying the attribute syntax OID nor referencing a superior
   *              attribute type from which the syntax will be inherited.  If
   *              this is {@code true}, then attribute types that do not specify
   *              either a syntax OID or a superior type will be permitted.  If
   *              this is {@code false}, then an error will be reported for
   *              each such attribute type.
   */
  public void setAllowAttributeTypesWithoutSyntax(
                   final boolean allowAttributeTypesWithoutSyntax)
  {
    this.allowAttributeTypesWithoutSyntax = allowAttributeTypesWithoutSyntax;
  }



  /**
   * Retrieves a list of the matching rules that will be used in the course of
   * of validating attribute type definitions.  By default, the schema validator
   * will be preconfigured with a default set of standard matching rules (as set
   * by the {@link #configureLDAPSDKDefaultMatchingRules()} method), in addition
   * to any matching rule definitions contained in schema entries.
   *
   * @return  A list of the matching rules  that will be used in the course of
   *          validating attribute type definitions, or an empty list if the
   *          list of matching rules will be defined in the schema files.
   */
  @NotNull()
  public List<MatchingRuleDefinition> getMatchingRuleDefinitions()
  {
    return Collections.unmodifiableList(new ArrayList<>(matchingRuleList));
  }



  /**
   * Specifies a set of matching rules that will be used in the course of
   * validating attribute type definitions.
   *
   * @param  matchingRules
   *              The set of attribute syntaxes that will be used in the course
   *              of validating attribute type definitions.  It may be
   *              {@code null} or empty if only syntaxes defined in the schema
   *              files will be used.
   */
  public void setMatchingRules(
       @Nullable final Collection<MatchingRuleDefinition> matchingRules)
  {
    matchingRuleList = new ArrayList<>();
    matchingRuleMap = new HashMap<>();

    if (matchingRules != null)
    {
      for (final MatchingRuleDefinition d : matchingRules)
      {
        matchingRuleList.add(d);
        matchingRuleMap.put(StaticUtils.toLowerCase(d.getOID()), d);
        for (final String name : d.getNames())
        {
          matchingRuleMap.put(StaticUtils.toLowerCase(name), d);
        }
      }
    }
  }



  /**
   * Configures the schema validator to use a default set of matching rules that
   * that are known to the LDAP SDK.  Any other syntaxes that may have been
   * defined will be cleared.
   */
  public void configureLDAPSDKDefaultMatchingRules()
  {
    try
    {
      final Set<MatchingRuleDefinition> defaultMatchingRules =
           new LinkedHashSet<>();
      final Schema schema = Schema.getDefaultStandardSchema();
      defaultMatchingRules.addAll(schema.getMatchingRules());

      if (PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE)
      {
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.1.4.1 NAME 'ds-mr-double-metaphone-approx' " +
                  "DESC 'Double Metaphone Approximate Match' " +
                  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.1.4.2 NAME 'ds-mr-user-password-exact' " +
                  "DESC 'user password exact matching rule' " +
                  "SYNTAX 1.3.6.1.4.1.30221.1.3.1 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.1.4.3 NAME 'ds-mr-user-password-equality' " +
                  "DESC 'user password matching rule' " +
                  "SYNTAX 1.3.6.1.4.1.30221.1.3.1 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.1.4.4 NAME 'historicalCsnOrderingMatch' " +
                  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.1.4.902 NAME 'caseExactIA5SubstringsMatch' " +
                  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.1 NAME 'compactTimestampMatch' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.1 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.2 NAME 'compactTimestampOrderingMatch' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.1 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.3 NAME 'ldapURLMatch' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.2 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.4 NAME 'hexStringMatch' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.3 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.5 NAME 'hexStringOrderingMatch' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.3 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.12 NAME 'jsonObjectExactMatch' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.4 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.13 " +
                  "NAME 'jsonObjectFilterExtensibleMatch' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.4 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.14 NAME 'relativeTimeExtensibleMatch' " +
                  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.15 " +
                  "NAME 'jsonObjectCaseSensitiveNamesCaseSensitiveValues' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.4 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.16 " +
                  "NAME 'jsonObjectCaseInsensitiveNamesCaseSensitiveValues' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.4 )"));
        defaultMatchingRules.add(new MatchingRuleDefinition(
             "( 1.3.6.1.4.1.30221.2.4.17 NAME " +
                  "'jsonObjectCaseInsensitiveNamesCaseInsensitiveValues' " +
                  "SYNTAX 1.3.6.1.4.1.30221.2.3.4 )"));
      }

      setMatchingRules(defaultMatchingRules);
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
    }
  }



  /**
   * Indicates whether to allow attribute type definitions to be missing an
   * equality matching definition, by neither directly specifying the matching
   * rule name or OID nor referencing a superior attribute type from which the
   * matching rule will be inherited.  It is technically legal to have an
   * attribute type definition that does not include an equality matching rule
   * and does not inherit an equality matching rule from a superior type, this
   * may not be desirable, as the server should fall back to byte-for-byte
   * matching (although some servers may assume a default matching rule based on
   * the syntax).  By default, attribute types that do not specify an equality
   * matching rule will be permitted.
   *
   * @return  {@code true} if attribute type definitions will be permitted to
   *          omit both an attribute syntax and a superior type, or
   *          {@code false} if an error will be reported for each such attribute
   *          type.
   */
  public boolean allowAttributeTypesWithoutEqualityMatchingRule()
  {
    return allowAttributeTypesWithoutEqualityMatchingRule;
  }



  /**
   * Indicates whether to allow attribute type definitions to be missing an
   * equality matching definition, by neither directly specifying the matching
   * rule name or OID nor referencing a superior attribute type from which the
   * matching rule will be inherited.  It is technically legal to have an
   * attribute type definition that does not include an equality matching rule
   * and does not inherit an equality matching rule from a superior type, this
   * may not be desirable, as the server should fall back to byte-for-byte
   * matching (although some servers may assume a default matching rule based on
   * the syntax).
   *
   * @param  allowAttributeTypesWithoutEqualityMatchingRule
   *              Specifies whether to allow attribute type definitions to be
   *              missing an equality matching definition, by neither directly
   *              specifying the matching rule name or OID nor referencing a
   *              superior attribute type from which the matching rule will be
   *              inherited.  If this is {@code true}, then attribute types that
   *              do not specify either an equality matching rule or a superior
   *              type will be permitted.  If this is {@code false}, then an
   *              error will be reported for each such attribute type.
   */
  public void setAllowAttributeTypesWithoutEqualityMatchingRule(
                   final boolean allowAttributeTypesWithoutEqualityMatchingRule)
  {
    this.allowAttributeTypesWithoutEqualityMatchingRule =
         allowAttributeTypesWithoutEqualityMatchingRule;
  }



  /**
   * Indicates whether to allow object classes with multiple superior classes.
   * This is allowed by LDAP specifications, but some servers do not support it.
   * By default, object classes with multiple superior classes will be
   * permitted.
   *
   * @return  {@code true} if object classes will be allowed to have multiple
   *          superior classes, or {@code false} if an error will be reported
   *          for each object class with multiple superiors.
   */
  public boolean allowMultipleSuperiorObjectClasses()
  {
    return allowMultipleSuperiorObjectClasses;
  }



  /**
   * Specifies whether to allow object classes with multiple superior classes.
   * This is allowed by LDAP specifications, but some servers do not support it.
   *
   * @param  allowMultipleSuperiorObjectClasses
   *              Indicates whether to allow object classes with multiple
   *              superior classes.  If this is {@code true}, then object
   *              classes with multiple superiors will be allowed.  If this is
   *              {@code false}, then an error will be reported for each
   *              object class with more than one superior class.
   */
  public void setAllowMultipleSuperiorObjectClasses(
                   final boolean allowMultipleSuperiorObjectClasses)
  {
    this.allowMultipleSuperiorObjectClasses =
         allowMultipleSuperiorObjectClasses;
  }



  /**
   * Indicates whether to allow structural object classes that do not declare a
   * superior class.  Technically, structural object classes must inherit
   * from structural or abstract classes, although some servers may assume a
   * default superior class of "top" for a structural class that does not
   * declare any superiors.  By default, an error will be reported for each
   * structural object class that does not explicitly declare any superior
   * class.
   *
   * @return  {@code true} if object classes that do not declare their superiors
   *          will be permitted, ro {@code false} if an error will be reported
   *          for each structural class that does not declare any superiors.
   */
  public boolean allowStructuralObjectClassWithoutSuperior()
  {
    return allowStructuralObjectClassWithoutSuperior;
  }



  /**
   * Specifies whether to allow structural object classes that do not declare a
   * superior class.  Technically, structural object classes must inherit
   * from structural or abstract classes, although some servers may assume a
   * default superior class of "top" for a structural class that does not
   * declare any superiors.
   *
   * @param  allowStructuralObjectClassWithoutSuperior
   *              Indicates whether to allow structural object classes that do
   *              not declare a superior class.  If this is {@code true}, then
   *              structural object classes that do not declare any superior
   *              class will be assumed to subclass "top".  if this is
   *              {@code false}, then an error will be reported for each
   *              structural object class that does not define any superior
   *              class.
   */
  public void setAllowStructuralObjectClassWithoutSuperior(
                   final boolean allowStructuralObjectClassWithoutSuperior)
  {
    this.allowStructuralObjectClassWithoutSuperior =
         allowStructuralObjectClassWithoutSuperior;
  }



  /**
   * Indicates whether to allow object classes with an invalid inheritance
   * relationship.  As per LDAP specifications, structural object classes can
   * only inherit from structural or abstract classes, auxiliary classes can
   * only inherit from auxiliary or abstract classes, and abstract classes can
   * only inherit from other abstract classes.  By default, the schema validator
   * will report an error for any object class that violates this constraint.
   *
   * @return  {@code true} if the schema validator will allow object classes
   *          with invalid inheritance relationships, or {@code false} if an
   *          error will be reported for each object class with an invalid
   *          superior class.
   */
  public boolean allowInvalidObjectClassInheritance()
  {
    return allowInvalidObjectClassInheritance;
  }



  /**
   * Specifies whether to allow object classes with an invalid inheritance
   * relationship.  As per LDAP specifications, structural object classes can
   * only inherit from structural or abstract classes, auxiliary classes can
   * only inherit from auxiliary or abstract classes, and abstract classes can
   * only inherit from other abstract classes.
   *
   * @param  allowInvalidObjectClassInheritance
   *              Indicates whether to allow object classes with an invalid
   *              inheritance relationship.  If this is {@code true}, then
   *              invalid inheritance relationships will be allowed.  If this is
   *              {@code false}, then an error will be reported for each
   *              object class with an invalid superior class reference.
   */
  public void setAllowInvalidObjectClassInheritance(
                   final boolean allowInvalidObjectClassInheritance)
  {
    this.allowInvalidObjectClassInheritance =
         allowInvalidObjectClassInheritance;
  }



  /**
   * Indicates whether to allow collective attribute type definitions.
   * Collective attributes (as described in RFC 3671) have read-only values that
   * are generated by the server rather than provided by clients.  Although they
   * are part of the LDAP specification, some servers do not support them or
   * provide alternate virtual attribute mechanisms.  By default, collective
   * attribute definitions will be allowed.
   *
   * @return  {@code true} if collective attributes will be allowed, or
   *          {@code false} if the schema validator will report an error for
   *          each collective attribute type definition.
   */
  public boolean allowCollectiveAttributes()
  {
    return allowCollectiveAttributes;
  }



  /**
   * Specifies whether to allow collective attribute type definitions.
   * Collective attributes (as described in RFC 3671) have read-only values that
   * are generated by the server rather than provided by clients.  Although they
   * are part of the LDAP specification, some servers do not support them or
   * provide alternate virtual attribute mechanisms.
   *
   * @param  allowCollectiveAttributes
   *              Indicates whether to allow collective attribute type
   *              definitions.  If this is {@code true}, then collective
   *              attribute type definitions will be allowed.  If this is
   *              {@code false}, then an error will be reported for each
   *              collective attribute type definition.
   */
  public void setAllowCollectiveAttributes(
                   final boolean allowCollectiveAttributes)
  {
    this.allowCollectiveAttributes = allowCollectiveAttributes;
  }



  /**
   * Indicates whether to allow schema elements declared with the OBSOLETE
   * modifier.  Obsolete schema elements are those that are no longer active
   * and cannot be used in updates, although some servers may not support
   * obsolete schema elements.  By default, obsolete elements will be allowed.
   *
   * @return  {@code true} if schema elements declared with the OBSOLETE
   *          modifier will be allowed, or {@code false} if an error will be
   *          reported for each schema element declared as OBSOLETE.
   */
  public boolean allowObsoleteElements()
  {
    return allowObsoleteElements;
  }



  /**
   * Specifies whether to allow schema elements declared with the OBSOLETE
   * modifier.  Obsolete schema elements are those that are no longer active
   * and cannot be used in updates, although some servers may not support
   * obsolete schema elements.
   *
   * @param  allowObsoleteElements
   *              Indicates whether to allow schema elements declared with the
   *              OBSOLETE modifier.  If this is {@code true}, then obsolete
   *              elements will be allowed.  If this is {@code false}, then
   *              an error will be reported for each OBSOLETE schema element.
   */
  public void setAllowObsoleteElements(final boolean allowObsoleteElements)
  {
    this.allowObsoleteElements = allowObsoleteElements;
  }



  /**
   * Validates the schema definitions in the file or set of files at the given
   * path.
   *
   * @param  schemaPath
   *              The file or directory containing the schema definitions to
   *              validate.  It must not be {@code null}, and the target file
   *              or directory must exist.  If it is a directory, then files in
   *              the directory will be processed in lexicographic order by
   *              filename, optionally restricted to files matching the schema
   *              file name pattern.
   * @param  existingSchema
   *              An existing schema to use in the course of validating
   *              definitions.  It may be {@code null} if there is no existing
   *              schema and only the definitions read from the provided path
   *              should be used.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   *
   * @return  A {@code Schema} object that contains the definitions that were
   *          loaded.  This may include schema elements that were flagged as
   *          invalid (if they could be parsed).  If an existing schema was
   *          already available, the schema that is returned will be a merged
   *          representation of the existing schema and the newly loaded schema.
   *          This may be {@code null} if an error prevented any schema files
   *          from being processed and no existing schema was provided.
   */
  @Nullable()
  public Schema validateSchema(@NotNull final File schemaPath,
                               @Nullable final Schema existingSchema,
                               @NotNull final List<String> errorMessages)
  {
    final boolean originalAllowEmptyDescription =
         SchemaElement.allowEmptyDescription();

    try
    {
      SchemaElement.setAllowEmptyDescription(true);

      final int originalErrorMessagesSize = errorMessages.size();
      final AtomicInteger schemaFilesProcessed = new AtomicInteger(0);
      final List<File> nonSchemaFilesIgnored = new ArrayList<>();
      final Schema schema = validateSchema(schemaPath, errorMessages,
           existingSchema, schemaFilesProcessed, nonSchemaFilesIgnored);

      // If no error messages were written, and if no schema files were
      // processed, then add an error message to indicate that.
      if ((schemaFilesProcessed.get() == 0) &&
           (errorMessages.size() == originalErrorMessagesSize))
      {
        switch (nonSchemaFilesIgnored.size())
        {
          case 0:
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_NO_SCHEMA_FILES_NONE_IGNORED.get(
                      schemaPath.getAbsolutePath()));
            break;

          case 1:
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_NO_SCHEMA_FILES_ONE_IGNORED.get(
                      schemaPath.getAbsolutePath(),
                      nonSchemaFilesIgnored.get(0).getAbsolutePath()));
            break;

          default:
            final StringBuilder buffer = new StringBuilder();
            final Iterator<File> fileIterator =
                 nonSchemaFilesIgnored.iterator();
            while (fileIterator.hasNext())
            {
              buffer.append('\'');
              buffer.append(fileIterator.next().getAbsolutePath());
              buffer.append('\'');

              if (fileIterator.hasNext())
              {
                buffer.append(", ");
              }
            }

            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_NO_SCHEMA_FILES_MULTIPLE_IGNORED.get(
                      schemaPath.getAbsolutePath(), buffer.toString()));
            break;
        }
      }

      return schema;
    }
    finally
    {
      SchemaElement.setAllowEmptyDescription(originalAllowEmptyDescription);
    }
  }



  /**
   * Validates the schema definitions in the file or set of files at the given
   * path.
   *
   * @param  schemaPath
   *              The file or directory containing the schema definitions to
   *              validate.  It must not be {@code null}, and the target file
   *              or directory must exist.  If it is a directory, then files in
   *              the directory will be processed in lexicographic order by
   *              filename, optionally restricted to files matching the schema
   *              file name pattern.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   * @param  existingSchema
   *              The existing schema to use in the course of validating
   *              definitions.  It may be {@code null} if there is no
   *              existing schema and only the definitions read from the
   *              provided path should be used.
   * @param  schemaFilesProcessed
   *              A counter that will be incremented for each schema file that
   *              is processed.
   * @param  nonSchemaFilesIgnored
   *              A list that should be updated with any files that are ignored
   *              because they do not match the configured schema file name
   *              pattern.
   *
   * @return  A {@code Schema} object that contains the definitions that were
   *          loaded.  If an existing schema was already available, the schema
   *          that is returned will be a merged representation of the existing
   *          schema and the newly loaded schema.  This may be {@code null} if
   *          an error prevented any schema files from being processed and no
   *          existing schema was provided.
   */
  @Nullable()
  private Schema validateSchema(@NotNull final File schemaPath,
                      @NotNull final List<String> errorMessages,
                      @Nullable final Schema existingSchema,
                      @NotNull final AtomicInteger schemaFilesProcessed,
                      @NotNull final List<File> nonSchemaFilesIgnored)
  {
    // Make sure the schema path represents a file or directory that exists.
    if (! schemaPath.exists())
    {
      errorMessages.add(ERR_SCHEMA_VALIDATOR_NO_SUCH_PATH.get(
           schemaPath.getAbsolutePath()));
      return existingSchema;
    }
    else if (schemaPath.isDirectory())
    {
      return validateSchemaDirectory(schemaPath, errorMessages, existingSchema,
           schemaFilesProcessed, nonSchemaFilesIgnored);
    }
    else
    {
      return validateSchemaFile(schemaPath, errorMessages, existingSchema,
           schemaFilesProcessed, nonSchemaFilesIgnored);
    }
  }



  /**
   * Identifies and validates all schema files in the provided directory.
   *
   * @param  schemaDirectory
   *              The directory containing the schema files to examine.  It must
   *              must not be {@code null}, it must exist, and it must be a
   *              directory.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   * @param  existingSchema
   *              The existing schema to use in the course of validating
   *              definitions.  It may be {@code null} if there is no
   *              existing schema and only the definitions read from the
   *              provided path should be used.
   * @param  schemaFilesProcessed
   *              A counter that will be incremented for each schema file that
   *              is processed.
   * @param  nonSchemaFilesIgnored
   *              A list that should be updated with any files that are ignored
   *              because they do not match the configured schema file name
   *              pattern.
   *
   * @return  A {@code Schema} object that contains the definitions that were
   *          loaded.  If an existing schema was already available, the schema
   *          that is returned will be a merged representation of the existing
   *          schema and the newly loaded schema.  This may be {@code null} if
   *          an error prevented any schema files from being processed and no
   *          existing schema was provided.
   */
  @Nullable()
  private Schema validateSchemaDirectory(@NotNull final File schemaDirectory,
                      @NotNull final List<String> errorMessages,
                      @Nullable final Schema existingSchema,
                      @NotNull final AtomicInteger schemaFilesProcessed,
                      @NotNull final List<File> nonSchemaFilesIgnored)
  {
    final TreeMap<String,File> schemaFiles = new TreeMap<>();
    final TreeMap<String,File> subDirectories = new TreeMap<>();

    for (final File f : schemaDirectory.listFiles())
    {
      final String name = f.getName();
      if (f.isFile())
      {
        schemaFiles.put(name, f);
      }
      else
      {
        if (allowSchemaFilesInSubDirectories)
        {
          subDirectories.put(name, f);
        }
        else
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_DIR_CONTAINS_SUBDIR.get(
               schemaDirectory.getAbsolutePath(), name));
        }
      }
    }


    Schema schema = existingSchema;
    for (final File f : schemaFiles.values())
    {
      final Schema newSchema = validateSchemaFile(f, errorMessages,
           schema, schemaFilesProcessed, nonSchemaFilesIgnored);
      if (schema == null)
      {
        schema = newSchema;
      }
      else
      {
        schema = Schema.mergeSchemas(schema, newSchema);
      }
    }

    for (final File f : subDirectories.values())
    {
      final Schema newSchema =
           validateSchemaDirectory(f, errorMessages, schema,
                schemaFilesProcessed, nonSchemaFilesIgnored);
      if (schema == null)
      {
        schema = newSchema;
      }
      else
      {
        schema = Schema.mergeSchemas(schema, newSchema);
      }
    }

    return schema;
  }



  /**
   * Validates the schema definitions in the specified file.
   *
   * @param  schemaFile
   *              The file containing the schema definitions to validate.  It
   *              must not be {@code null}, it must exist, and it must be a
   *              file.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   * @param  existingSchema
   *              The existing schema to use in the course of validating
   *              definitions.  It may be {@code null} if there is no
   *              existing schema and only the definitions read from the
   *              provided path should be used.
   * @param  schemaFilesProcessed
   *              A counter that will be incremented for each schema file that
   *              is processed.
   * @param  nonSchemaFilesIgnored
   *              A list that should be updated with any files that are ignored
   *              because they do not match the configured schema file name
   *              pattern.
   *
   * @return  A {@code Schema} object that contains the definitions that were
   *          loaded.  If an existing schema was already available, the schema
   *          that is returned will be a merged representation of the existing
   *          schema and the newly loaded schema.  This may be {@code null} if
   *          an error prevented any schema files from being processed and no
   *          existing schema was provided.
   */
  @Nullable()
  private Schema validateSchemaFile(@NotNull final File schemaFile,
                      @NotNull final List<String> errorMessages,
                      @Nullable final Schema existingSchema,
                      @NotNull final AtomicInteger schemaFilesProcessed,
                      @NotNull final List<File> nonSchemaFilesIgnored)
  {
    if (schemaFileNamePattern != null)
    {
      final String name = schemaFile.getName();
      if (! schemaFileNamePattern.matcher(name).matches())
      {
        if (ignoreSchemaFilesNotMatchingFileNamePattern)
        {
          nonSchemaFilesIgnored.add(schemaFile);
        }
        else
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_FILE_NAME_DOES_NOT_MATCH_PATTERN.get(
                    schemaFile.getAbsoluteFile().getParentFile().
                         getAbsolutePath(),
                    name));
        }

        return existingSchema;
      }
    }

    schemaFilesProcessed.incrementAndGet();

    Schema newSchema = existingSchema;
    try (LDIFReader ldifReader = new LDIFReader(schemaFile))
    {
      Entry schemaEntry = ldifReader.readEntry();
      if (schemaEntry == null)
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_NO_ENTRY_IN_FILE.get(
             schemaFile.getAbsolutePath()));
        return existingSchema;
      }

      newSchema = validateSchemaEntry(schemaEntry, schemaFile, errorMessages,
           newSchema);

      while (true)
      {
        schemaEntry = ldifReader.readEntry();
        if (schemaEntry == null)
        {
          break;
        }

        if (! allowMultipleEntriesPerFile)
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_MULTIPLE_ENTRIES_IN_FILE.get(
               schemaFile.getAbsolutePath()));
          return newSchema;
        }

        newSchema = validateSchemaEntry(schemaEntry, schemaFile, errorMessages,
             newSchema);
      }
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      errorMessages.add(ERR_SCHEMA_VALIDATOR_ERROR_READING_FILE.get(
           schemaFile.getAbsolutePath(), StaticUtils.getExceptionMessage(e)));
    }
    catch (final LDIFException e)
    {
      Debug.debugException(e);
      errorMessages.add(ERR_SCHEMA_VALIDATOR_MALFORMED_LDIF_ENTRY.get(
           schemaFile.getAbsolutePath(), e.getMessage()));
    }

    return newSchema;
  }



  /**
   * Validates the schema definitions in the provided entry.
   *
   * @param  schemaEntry
   *              The entry containing the schema definitions to validate.  It
   *              must not be {@code null}.
   * @param  schemaFile
   *              The file from which the schema entry was read.  It must not be
   *              {@code null}.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   * @param  existingSchema
   *              The existing schema to use in the course of validating
   *              definitions.  It may be {@code null} if there is no
   *              existing schema and only the definitions read from the
   *              provided path should be used.
   *
   * @return  A {@code Schema} object that contains the definitions that were
   *          validated.  If an existing schema was already available, the
   *          schema that is returned will be a merged representation of the
   *          existing schema and the newly loaded schema.
   */
  @NotNull()
  private Schema validateSchemaEntry(@NotNull final Entry schemaEntry,
                      @NotNull final File schemaFile,
                      @NotNull final List<String> errorMessages,
                      @Nullable final Schema existingSchema)
  {
    if (schemaEntry.hasAttribute(Schema.ATTR_ATTRIBUTE_SYNTAX))
    {
      validateAttributeSyntaxes(schemaEntry, schemaFile, errorMessages);
    }

    if (schemaEntry.hasAttribute(Schema.ATTR_MATCHING_RULE))
    {
      if (attributeSyntaxMap.isEmpty())
      {
        configureLDAPSDKDefaultAttributeSyntaxes();
      }

      validateMatchingRules(schemaEntry, schemaFile, existingSchema,
           errorMessages);
    }

    if (schemaEntry.hasAttribute(Schema.ATTR_ATTRIBUTE_TYPE))
    {
      if (attributeSyntaxMap.isEmpty())
      {
        configureLDAPSDKDefaultAttributeSyntaxes();
      }

      if (matchingRuleMap.isEmpty())
      {
        configureLDAPSDKDefaultMatchingRules();
      }

      final Map<String,AttributeTypeDefinition> attributeTypeMap =
           new HashMap<>();
      validateAttributeTypes(schemaEntry, schemaFile, attributeTypeMap,
           existingSchema, errorMessages);
    }

    if (schemaEntry.hasAttribute(Schema.ATTR_OBJECT_CLASS))
    {
      final Entry schemaEntryWithoutObjectClasses = schemaEntry.duplicate();
      schemaEntryWithoutObjectClasses.removeAttribute(Schema.ATTR_OBJECT_CLASS);
      Schema s = new Schema(schemaEntryWithoutObjectClasses);
      if (existingSchema != null)
      {
        s = Schema.mergeSchemas(existingSchema, s);
      }

      final Map<String,ObjectClassDefinition> objectClassMap = new HashMap<>();
      validateObjectClasses(schemaEntry, schemaFile, objectClassMap, s,
           errorMessages);
    }

    if (schemaEntry.hasAttribute(Schema.ATTR_NAME_FORM))
    {
      final Entry schemaEntryWithoutNameForms = schemaEntry.duplicate();
      schemaEntryWithoutNameForms.removeAttribute(Schema.ATTR_NAME_FORM);
      Schema s = new Schema(schemaEntryWithoutNameForms);
      if (existingSchema != null)
      {
        s = Schema.mergeSchemas(existingSchema, s);
      }

      final Map<String,NameFormDefinition> nameFormsByNameOrOID =
           new HashMap<>();
      final Map<ObjectClassDefinition,NameFormDefinition> nameFormsByOC =
           new HashMap<>();
      validateNameForms(schemaEntry, schemaFile, nameFormsByNameOrOID,
           nameFormsByOC, s, errorMessages);
    }

    if (schemaEntry.hasAttribute(Schema.ATTR_DIT_CONTENT_RULE))
    {
      final Entry schemaEntryWithoutDITContentRules = schemaEntry.duplicate();
      schemaEntryWithoutDITContentRules.removeAttribute(
           Schema.ATTR_DIT_CONTENT_RULE);
      Schema s = new Schema(schemaEntryWithoutDITContentRules);
      if (existingSchema != null)
      {
        s = Schema.mergeSchemas(existingSchema, s);
      }

      final Map<String,DITContentRuleDefinition> dcrMap = new HashMap<>();
      validateDITContentRules(schemaEntry, schemaFile, dcrMap, s,
           errorMessages);
    }

    if (schemaEntry.hasAttribute(Schema.ATTR_DIT_STRUCTURE_RULE))
    {
      final Entry schemaEntryWithoutDITStructureRules = schemaEntry.duplicate();
      schemaEntryWithoutDITStructureRules.removeAttribute(
           Schema.ATTR_DIT_STRUCTURE_RULE);
      Schema s = new Schema(schemaEntryWithoutDITStructureRules);
      if (existingSchema != null)
      {
        s = Schema.mergeSchemas(existingSchema, s);
      }

      final Map<String,DITStructureRuleDefinition> dsrIDAndNameMap =
           new HashMap<>();
      final Map<NameFormDefinition,DITStructureRuleDefinition> dsrNFMap =
           new HashMap<>();
      validateDITStructureRules(schemaEntry, schemaFile, dsrIDAndNameMap,
           dsrNFMap, s, errorMessages);
    }

    if (schemaEntry.hasAttribute(Schema.ATTR_MATCHING_RULE_USE))
    {
      final Entry schemaEntryWithoutMatchingRuleUses = schemaEntry.duplicate();
      schemaEntryWithoutMatchingRuleUses.removeAttribute(
           Schema.ATTR_MATCHING_RULE_USE);
      Schema s = new Schema(schemaEntryWithoutMatchingRuleUses);
      if (existingSchema != null)
      {
        s = Schema.mergeSchemas(existingSchema, s);
      }

      final Map<String,MatchingRuleUseDefinition> mruMap = new HashMap<>();
      validateMatchingRuleUses(schemaEntry, schemaFile, mruMap, s,
           errorMessages);
    }

    Schema s = new Schema(schemaEntry);
    if (existingSchema != null)
    {
      s = Schema.mergeSchemas(existingSchema, s);
    }


    if (ensureSchemaEntryIsValid)
    {
      final List<String> schemaEntryInvalidReasons = new ArrayList<>();

      final EntryValidator entryValidator = new EntryValidator(s);
      if (! entryValidator.entryIsValid(schemaEntry, schemaEntryInvalidReasons))
      {
        for (final String invalidReason : schemaEntryInvalidReasons)
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_ENTRY_NOT_VALID.get(
               schemaEntry.getDN(), schemaFile.getAbsolutePath(),
               invalidReason));
        }
      }
    }

    return s;
  }



  /**
   * Validates any attribute syntax definitions contained in the provided
   * schema entry.
   *
   * @param  schemaEntry
   *              The entry containing the schema definitions to validate.  It
   *              must not be {@code null}.
   * @param  schemaFile
   *              The file from which the schema entry was read.  It must not be
   *              {@code null}.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   */
  private void validateAttributeSyntaxes(@NotNull final Entry schemaEntry,
                    @NotNull final File schemaFile,
                    @NotNull final List<String> errorMessages)
  {
    for (final String syntaxString :
         schemaEntry.getAttributeValues(Schema.ATTR_ATTRIBUTE_SYNTAX))
    {
      // If attribute syntaxes aren't allowed, then report an error without
      // doing anything else.
      if (! allowedSchemaElementTypes.contains(
           SchemaElementType.ATTRIBUTE_SYNTAX))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_SYNTAX_NOT_ALLOWED.get(
             schemaFile.getAbsolutePath(), syntaxString));
        continue;
      }


      // Make sure that we can parse the syntax definition.
      final AttributeSyntaxDefinition syntax;
      try
      {
        syntax = new AttributeSyntaxDefinition(syntaxString);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_CANNOT_PARSE_SYNTAX.get(
             syntaxString, schemaFile.getAbsolutePath(), e.getMessage()));
        continue;
      }


      // Make sure that the syntax has a valid numeric OID.
      try
      {
        validateOID(syntax.getOID(), StaticUtils.NO_STRINGS);
      }
      catch (final ParseException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_SYNTAX_INVALID_OID.get(
             syntaxString, schemaFile.getAbsolutePath(), e.getMessage()));
      }


      // If the syntax has a description, then make sure it's not empty.
      if (! allowEmptyDescription)
      {
        final String description = syntax.getDescription();
        if ((description != null) && description.isEmpty())
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_SYNTAX_EMPTY_DESCRIPTION.get(
               syntaxString, schemaFile.getAbsolutePath()));
        }
      }



      // Make sure that the syntax isn't already defined.
      final String lowerOID = StaticUtils.toLowerCase(syntax.getOID());
      final AttributeSyntaxDefinition existingSyntax =
           attributeSyntaxMap.get(lowerOID);
      if ((existingSyntax != null) && (! allowRedefiningElements))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_SYNTAX_ALREADY_DEFINED.get(
             syntaxString, schemaFile.getAbsolutePath(),
             existingSyntax.toString()));
      }

      attributeSyntaxMap.put(lowerOID, syntax);
    }
 }



  /**
   * Validates any matching rule definitions contained in the provided schema
   * entry.
   *
   * @param  schemaEntry
   *              The entry containing the schema definitions to validate.  It
   *              must not be {@code null}.
   * @param  schemaFile
   *              The file from which the schema entry was read.  It must not be
   *              {@code null}.
   * @param  existingSchema
   *              An existing schema that has already been read (e.g., from
   *              earlier schema files).  It may be {@code null} if only the
   *              elements from the current file should be used.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   */
  private void validateMatchingRules(@NotNull final Entry schemaEntry,
                    @NotNull final File schemaFile,
                    @Nullable final Schema existingSchema,
                    @NotNull final List<String> errorMessages)
  {
    for (final String matchingRuleString :
         schemaEntry.getAttributeValues(Schema.ATTR_MATCHING_RULE))
    {
      // If matching rules aren't allowed, then report an error without doing
      // anything else.
      if (! allowedSchemaElementTypes.contains(
           SchemaElementType.MATCHING_RULE))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MR_NOT_ALLOWED.get(
             schemaFile.getAbsolutePath(), matchingRuleString));
        continue;
      }


      // Make sure that we can parse the matching rule definition.
      final MatchingRuleDefinition matchingRule;
      try
      {
        matchingRule = new MatchingRuleDefinition(matchingRuleString);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_CANNOT_PARSE_MR.get(
             matchingRuleString, schemaFile.getAbsolutePath(), e.getMessage()));
        continue;
      }


      // Make sure that the matching rule has a valid numeric OID.
      try
      {
        validateOID(matchingRule.getOID(), matchingRule.getNames());
      }
      catch (final ParseException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MR_INVALID_OID.get(
             matchingRuleString, schemaFile.getAbsolutePath(), e.getMessage()));
      }


      // Make sure that all of the names are valid.
      if ((matchingRule.getNames().length == 0) &&
           (! allowElementsWithoutNames))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MR_NO_NAME.get(
             matchingRuleString, schemaFile.getAbsolutePath()));
      }

      for (final String name : matchingRule.getNames())
      {
        try
        {
          validateName(name);
        }
        catch (final ParseException e)
        {
          Debug.debugException(e);
          errorMessages.add(ERR_SCHEMA_VALIDATOR_MR_INVALID_NAME.get(
               matchingRuleString, schemaFile.getAbsolutePath(), name,
               e.getMessage()));
        }
      }


      // If the matching rule has a description, then make sure it's not empty.
      if (! allowEmptyDescription)
      {
        final String description = matchingRule.getDescription();
        if ((description != null) && description.isEmpty())
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_MR_EMPTY_DESCRIPTION.get(
               matchingRuleString, schemaFile.getAbsolutePath()));
        }
      }


      // If the matching rule is declared obsolete, then make sure that's
      // allowed.
      if (matchingRule.isObsolete() && (! allowObsoleteElements))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MR_OBSOLETE.get(
             matchingRuleString, schemaFile.getAbsolutePath()));
      }


      // Make sure that the syntax OID is valid.
      final String syntaxOID = matchingRule.getSyntaxOID();
      try
      {
        validateOID(syntaxOID, StaticUtils.NO_STRINGS);
      }
      catch (final ParseException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MR_INVALID_SYNTAX_OID.get(
             matchingRuleString, schemaFile.getAbsolutePath(), syntaxOID,
             e.getMessage()));
      }


      // Make sure that the syntax OID is one that we know about.
      if (! allowReferencesToUndefinedElementTypes.contains(
           SchemaElementType.ATTRIBUTE_SYNTAX))
      {
        final String lowerSyntaxOID = StaticUtils.toLowerCase(syntaxOID);
        if (! attributeSyntaxMap.containsKey(lowerSyntaxOID))
        {
          if ((existingSchema == null) ||
               existingSchema.getAttributeSyntax(lowerSyntaxOID) == null)
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_MR_UNDEFINED_SYNTAX.get(
                 matchingRuleString, schemaFile.getAbsolutePath(), syntaxOID));
          }
        }
      }


      // Make sure that the matching rule isn't already defined.
      boolean isDuplicate = false;
      final String lowerOID = StaticUtils.toLowerCase(matchingRule.getOID());
      if (matchingRuleMap.containsKey(lowerOID) && (! allowRedefiningElements))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MR_ALREADY_DEFINED_WITH_OID.get(
             matchingRuleString, schemaFile.getAbsolutePath(),
             matchingRuleMap.get(lowerOID).toString()));
        isDuplicate = true;
      }

      if (! isDuplicate)
      {
        for (final String name : matchingRule.getNames())
        {
          final String lowerName = StaticUtils.toLowerCase(name);
          if (matchingRuleMap.containsKey(lowerName) &&
               (! allowRedefiningElements))
          {
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_MR_ALREADY_DEFINED_WITH_NAME.get(
                      matchingRuleString, schemaFile.getAbsolutePath(),
                      name, matchingRuleMap.get(lowerName).toString()));
            isDuplicate = true;
            break;
          }
        }
      }

      if (! isDuplicate)
      {
        matchingRuleMap.put(lowerOID, matchingRule);
        for (final String name : matchingRule.getNames())
        {
          matchingRuleMap.put(StaticUtils.toLowerCase(name), matchingRule);
        }
      }
    }
  }



  /**
   * Validates any attribute type definitions contained in the provided schema
   * entry.
   *
   * @param  schemaEntry
   *              The entry containing the schema definitions to validate.  It
   *              must not be {@code null}.
   * @param  schemaFile
   *              The file from which the schema entry was read.  It must not be
   *              {@code null}.
   * @param  attributeTypeMap
   *              A map of the attribute type definitions that have already been
   *              parsed from the same file.  It must not be {@code null} (but
   *              may be empty), and it must be updatable.
   * @param  existingSchema
   *              An existing schema that has already been read (e.g., from
   *              earlier schema files).  It may be {@code null} if only the
   *              elements from the current file should be used.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   */
  private void validateAttributeTypes(@NotNull final Entry schemaEntry,
       @NotNull final File schemaFile,
       @NotNull final Map<String,AttributeTypeDefinition> attributeTypeMap,
       @Nullable final Schema existingSchema,
       @NotNull final List<String> errorMessages)
  {
    for (final String attributeTypeString :
         schemaEntry.getAttributeValues(Schema.ATTR_ATTRIBUTE_TYPE))
    {
      // If attribute types aren't allowed, then report an error without doing
      // anything else.
      if (! allowedSchemaElementTypes.contains(
           SchemaElementType.ATTRIBUTE_TYPE))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_NOT_ALLOWED.get(
             schemaFile.getAbsolutePath(), attributeTypeString));
        continue;
      }


      // Make sure that we can parse the attribute type definition.
      final AttributeTypeDefinition attributeType;
      try
      {
        attributeType = new AttributeTypeDefinition(attributeTypeString);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_CANNOT_PARSE_AT.get(
             attributeTypeString, schemaFile.getAbsolutePath(),
             e.getMessage()));
        continue;
      }


      // Make sure that the attribute type has a valid numeric OID.
      try
      {
        validateOID(attributeType.getOID(), attributeType.getNames());
      }
      catch (final ParseException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_INVALID_OID.get(
             attributeTypeString, schemaFile.getAbsolutePath(),
             e.getMessage()));
      }


      // Make sure that all of the names are valid.
      if ((attributeType.getNames().length == 0) &&
           (! allowElementsWithoutNames))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_NO_NAME.get(
             attributeTypeString, schemaFile.getAbsolutePath()));
      }

      for (final String name : attributeType.getNames())
      {
        try
        {
          validateName(name);
        }
        catch (final ParseException e)
        {
          Debug.debugException(e);
          errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_INVALID_NAME.get(
               attributeTypeString, schemaFile.getAbsolutePath(), name,
               e.getMessage()));
        }
      }


      // If the attribute type has a description, then make sure it's not empty.
      if (! allowEmptyDescription)
      {
        final String description = attributeType.getDescription();
        if ((description != null) && description.isEmpty())
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_EMPTY_DESCRIPTION.get(
               attributeTypeString, schemaFile.getAbsolutePath()));
        }
      }


      // If the attribute type is declared obsolete, then make sure that's
      // allowed.
      if (attributeType.isObsolete() && (! allowObsoleteElements))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_OBSOLETE.get(
             attributeTypeString, schemaFile.getAbsolutePath()));
      }


      // Check to see if there is a superior type, and if so, whether it's
      // defined.
      AttributeTypeDefinition superiorType;
      final String superiorTypeNameOrOID = attributeType.getSuperiorType();
      if (superiorTypeNameOrOID == null)
      {
        superiorType = null;
      }
      else
      {
        final String lowerSuperiorTypeNameOrOID =
             StaticUtils.toLowerCase(superiorTypeNameOrOID);
        superiorType = attributeTypeMap.get(lowerSuperiorTypeNameOrOID);
        if ((superiorType == null) && (existingSchema != null))
        {
          superiorType =
               existingSchema.getAttributeType(lowerSuperiorTypeNameOrOID);
        }

        if ((superiorType == null) &&
             (! allowReferencesToUndefinedElementTypes.contains(
                  SchemaElementType.ATTRIBUTE_TYPE)))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_UNDEFINED_SUPERIOR.get(
               attributeTypeString, schemaFile.getAbsolutePath(),
               superiorTypeNameOrOID));
        }
      }


      // Check to see if there is an equality matching rule.  If not, then we
      // may want to check to make sure that there is a superior type because
      // an attribute type without an equality matching rule can be problematic.
      final String equalityMRNameOrOID =
           attributeType.getEqualityMatchingRule();
      if (equalityMRNameOrOID == null)
      {
        if ((superiorTypeNameOrOID == null) &&
             (! allowAttributeTypesWithoutEqualityMatchingRule))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_NO_EQ_MR.get(
               attributeTypeString, schemaFile.getAbsolutePath()));
        }
      }


      // Check to make sure that any declared matching rules are defined in the
      // schema.
      if (! allowReferencesToUndefinedElementTypes.contains(
           SchemaElementType.MATCHING_RULE))
      {
        if (equalityMRNameOrOID != null)
        {
          if (! matchingRuleMap.containsKey(
               StaticUtils.toLowerCase(equalityMRNameOrOID)))
          {
            if ((existingSchema == null) ||
                 (existingSchema.getMatchingRule(equalityMRNameOrOID) == null))
            {
              errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_UNDEFINED_EQ_MR.get(
                   attributeTypeString, schemaFile.getAbsolutePath(),
                   equalityMRNameOrOID));
            }
          }
        }

        final String orderingMRNameOrOID =
             attributeType.getOrderingMatchingRule();
        if (orderingMRNameOrOID != null)
        {
          if (! matchingRuleMap.containsKey(
               StaticUtils.toLowerCase(orderingMRNameOrOID)))
          {
            if ((existingSchema == null) ||
                 (existingSchema.getMatchingRule(orderingMRNameOrOID) == null))
            {
              errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_UNDEFINED_ORD_MR.get(
                   attributeTypeString, schemaFile.getAbsolutePath(),
                   orderingMRNameOrOID));
            }
          }
        }

        final String substringMRNameOrOID =
             attributeType.getSubstringMatchingRule();
        if (substringMRNameOrOID != null)
        {
          if (! matchingRuleMap.containsKey(
               StaticUtils.toLowerCase(substringMRNameOrOID)))
          {
            if ((existingSchema == null) ||
                 (existingSchema.getMatchingRule(substringMRNameOrOID) == null))
            {
              errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_UNDEFINED_SUB_MR.get(
                   attributeTypeString, schemaFile.getAbsolutePath(),
                   substringMRNameOrOID));
            }
          }
        }
      }


      // Check to see if there's a syntax.  If not, make sure there's a
      // superior type.  Otherwise, make sure the syntax OID is valid and
      // references a known syntax.
      final String syntaxOID = attributeType.getSyntaxOID();
      if (syntaxOID == null)
      {
        if ((superiorTypeNameOrOID == null) &&
             (! allowAttributeTypesWithoutSyntax))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_NO_SYNTAX.get(
               attributeTypeString, schemaFile.getAbsolutePath()));
        }
      }
      else if (! allowReferencesToUndefinedElementTypes.contains(
           SchemaElementType.ATTRIBUTE_SYNTAX))
      {
        final String baseOID =
             AttributeTypeDefinition.getBaseSyntaxOID(syntaxOID);
        try
        {
          validateOID(baseOID, StaticUtils.NO_STRINGS);
        }
        catch (final ParseException e)
        {
          Debug.debugException(e);
          errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_INVALID_SYNTAX_OID.get(
               attributeTypeString, schemaFile.getAbsolutePath(), baseOID,
               e.getMessage()));
        }

        final String lowerSyntaxOID = StaticUtils.toLowerCase(baseOID);
        if (! attributeSyntaxMap.containsKey(lowerSyntaxOID))
        {
          if ((existingSchema == null) ||
               (existingSchema.getAttributeSyntax(lowerSyntaxOID) == null))
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_UNDEFINED_SYNTAX.get(
                 attributeTypeString, schemaFile.getAbsolutePath(), baseOID));
          }
        }
      }


      // Check to see if the attribute type is collective, and if so whether
      // that is allowed.
      if (attributeType.isCollective() && (! allowCollectiveAttributes))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_AT_COLLECTIVE.get(
             attributeTypeString, schemaFile.getAbsolutePath()));
      }


      // Check to see if the attribute type is declared as NO-USER-MODIFICATION,
      // and if so, then make sure it has an operational usage.
      if (attributeType.isNoUserModification() &&
           (! attributeType.isOperational()))
      {
        errorMessages.add(
             ERR_SCHEMA_VALIDATOR_AT_NO_USER_MOD_WITHOUT_OP_USAGE.get(
                  attributeTypeString, schemaFile.getAbsolutePath()));
      }


      // Make sure that the attribute type isn't already defined.
      boolean isDuplicate = false;
      if (! allowRedefiningElements)
      {
        final String lowerOID = StaticUtils.toLowerCase(attributeType.getOID());
        AttributeTypeDefinition existingDefinition =
             attributeTypeMap.get(lowerOID);
        if ((existingDefinition == null) && (existingSchema != null))
        {
          existingDefinition = existingSchema.getAttributeType(lowerOID);
        }

        if (existingDefinition != null)
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_AT_ALREADY_DEFINED_WITH_OID.get(
                    attributeTypeString, schemaFile.getAbsolutePath(),
                    existingDefinition.toString()));
          isDuplicate = true;
        }

        if (! isDuplicate)
        {
          for (final String name : attributeType.getNames())
          {
            final String lowerName = StaticUtils.toLowerCase(name);
            existingDefinition = attributeTypeMap.get(lowerName);
            if ((existingDefinition == null) && (existingSchema != null))
            {
              existingDefinition = existingSchema.getAttributeType(lowerName);
            }

            if (existingDefinition != null)
            {
              errorMessages.add(
                   ERR_SCHEMA_VALIDATOR_AT_ALREADY_DEFINED_WITH_NAME.get(
                        attributeTypeString, schemaFile.getAbsolutePath(),
                        name, existingDefinition.toString()));
              isDuplicate = true;
              break;
            }
          }
        }
      }


      // Add the attribute type to the map so it can be referenced by
      // subordinate types.
      if (! isDuplicate)
      {
        attributeTypeMap.put(StaticUtils.toLowerCase(attributeType.getOID()),
             attributeType);
        for (final String name : attributeType.getNames())
        {
          attributeTypeMap.put(StaticUtils.toLowerCase(name), attributeType);
        }
      }
    }
  }



  /**
   * Validates any object class definitions contained in the provided schema
   * entry.
   *
   * @param  schemaEntry
   *              The entry containing the schema definitions to validate.  It
   *              must not be {@code null}.
   * @param  schemaFile
   *              The file from which the schema entry was read.  It must not be
   *              {@code null}.
   * @param  objectClassMap
   *              A map of the object class definitions that have already been
   *              parsed from the same file.  It must not be {@code null} (but
   *              may be empty), and it must be updatable.
   * @param  existingSchema
   *              An existing schema that has already been read (e.g., from
   *              earlier schema files).  It must not be {@code null}.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   */
  private void validateObjectClasses(@NotNull final Entry schemaEntry,
       @NotNull final File schemaFile,
       @NotNull final Map<String,ObjectClassDefinition> objectClassMap,
       @Nullable final Schema existingSchema,
       @NotNull final List<String> errorMessages)
  {
    for (final String objectClassString :
         schemaEntry.getAttributeValues(Schema.ATTR_OBJECT_CLASS))
    {
      // If object classes aren't allowed, then report an error without doing
      // anything else.
      if (! allowedSchemaElementTypes.contains(SchemaElementType.OBJECT_CLASS))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_NOT_ALLOWED.get(
             schemaFile.getAbsolutePath(), objectClassString));
        continue;
      }


      // Make sure that we can parse the object class definition.
      final ObjectClassDefinition objectClass;
      try
      {
        objectClass = new ObjectClassDefinition(objectClassString);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_CANNOT_PARSE_OC.get(
             objectClassString, schemaFile.getAbsolutePath(), e.getMessage()));
        continue;
      }


      // Make sure that the object class has a valid numeric OID.
      try
      {
        validateOID(objectClass.getOID(), objectClass.getNames());
      }
      catch (final ParseException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_INVALID_OID.get(
             objectClassString, schemaFile.getAbsolutePath(), e.getMessage()));
      }


      // Make sure that all of the names are valid.
      if ((objectClass.getNames().length == 0) &&
           (! allowElementsWithoutNames))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_NO_NAME.get(
             objectClassString, schemaFile.getAbsolutePath()));
      }

      for (final String name : objectClass.getNames())
      {
        try
        {
          validateName(name);
        }
        catch (final ParseException e)
        {
          Debug.debugException(e);
          errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_INVALID_NAME.get(
               objectClassString, schemaFile.getAbsolutePath(), name,
               e.getMessage()));
        }
      }


      // If the object class has a description, then make sure it's not empty.
      if (! allowEmptyDescription)
      {
        final String description = objectClass.getDescription();
        if ((description != null) && description.isEmpty())
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_EMPTY_DESCRIPTION.get(
               objectClassString, schemaFile.getAbsolutePath()));
        }
      }


      // If the object class is declared obsolete, then make sure that's
      // allowed.
      if (objectClass.isObsolete() && (! allowObsoleteElements))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_OBSOLETE.get(
             objectClassString, schemaFile.getAbsolutePath()));
      }


      // Validate all of the superior object classes.
      validateSuperiorObjectClasses(schemaFile, objectClass, objectClassMap,
           existingSchema, errorMessages);


      // Validate all of the required and optional attribute types.
      final Set<String> requiredAttrNamesAndOIDs = new HashSet<>();
      for (final String attrNameOrOID : objectClass.getRequiredAttributes())
      {
        requiredAttrNamesAndOIDs.add(StaticUtils.toLowerCase(attrNameOrOID));
        final AttributeTypeDefinition at =
             existingSchema.getAttributeType(attrNameOrOID);
        if (at == null)
        {
          if (! allowReferencesToUndefinedElementTypes.contains(
               SchemaElementType.ATTRIBUTE_TYPE))
          {
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_OC_UNDEFINED_REQUIRED_ATTR.get(
                      objectClassString, schemaFile.getAbsolutePath(),
                      attrNameOrOID));
          }
        }
        else
        {
          requiredAttrNamesAndOIDs.add(StaticUtils.toLowerCase(at.getOID()));
          for (final String name : at.getNames())
          {
            requiredAttrNamesAndOIDs.add(StaticUtils.toLowerCase(name));
          }
        }
      }

      for (final String attrNameOrOID : objectClass.getOptionalAttributes())
      {
        if (requiredAttrNamesAndOIDs.contains(
             StaticUtils.toLowerCase(attrNameOrOID)))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_AT_REQ_AND_OPT.get(
               objectClassString, schemaFile.getAbsolutePath(),
               attrNameOrOID));
        }

        final AttributeTypeDefinition at =
             existingSchema.getAttributeType(attrNameOrOID);
        if ((at == null) &&
             (! allowReferencesToUndefinedElementTypes.contains(
                  SchemaElementType.ATTRIBUTE_TYPE)))
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_OC_UNDEFINED_OPTIONAL_ATTR.get(
                    objectClassString, schemaFile.getAbsolutePath(),
                    attrNameOrOID));
        }
      }


      // Make sure that the object class isn't already defined.
      boolean isDuplicate = false;
      if (! allowRedefiningElements)
      {
        final String lowerOID = StaticUtils.toLowerCase(objectClass.getOID());
        ObjectClassDefinition existingDefinition =
             objectClassMap.get(lowerOID);
        if (existingDefinition == null)
        {
          existingDefinition = existingSchema.getObjectClass(lowerOID);
        }

        if (existingDefinition != null)
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_OC_ALREADY_DEFINED_WITH_OID.get(
                    objectClassString, schemaFile.getAbsolutePath(),
                    existingDefinition.toString()));
          isDuplicate = true;
        }

        if (! isDuplicate)
        {
          for (final String name : objectClass.getNames())
          {
            final String lowerName = StaticUtils.toLowerCase(name);
            existingDefinition = objectClassMap.get(lowerName);
            if (existingDefinition == null)
            {
              existingDefinition = existingSchema.getObjectClass(lowerName);
            }

            if (existingDefinition != null)
            {
              errorMessages.add(
                   ERR_SCHEMA_VALIDATOR_OC_ALREADY_DEFINED_WITH_NAME.get(
                        objectClassString, schemaFile.getAbsolutePath(),
                        name, existingDefinition.toString()));
              isDuplicate = true;
              break;
            }
          }
        }
      }


      // Add the object class to the map so it can be referenced by subordinate
      // classes.
      if (! isDuplicate)
      {
        objectClassMap.put(StaticUtils.toLowerCase(objectClass.getOID()),
             objectClass);
        for (final String name : objectClass.getNames())
        {
          objectClassMap.put(StaticUtils.toLowerCase(name), objectClass);
        }
      }
    }
  }



  /**
   * Retrieves the definitions for the superior object classes for the provided
   * object class.
   *
   * @param  schemaFile
   *              The file from which the object class was read.  It must not be
   *              {@code null}.
   * @param  objectClass
   *              The object class for which to retrieve the superior classes.
   *              It must not be {@code null}.
   * @param  objectClassMap
   *              A map of the object class definitions that have already been
   *              parsed from the same file.  It must not be {@code null} (but
   *              may be empty), and it must be updatable.
   * @param  existingSchema
   *              An existing schema that has already been read (e.g., from
   *              earlier schema files).  It must not be {@code null} .
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   */
  private void validateSuperiorObjectClasses(@NotNull final File schemaFile,
       @NotNull final ObjectClassDefinition objectClass,
       @NotNull final Map<String,ObjectClassDefinition> objectClassMap,
       @NotNull final Schema existingSchema,
       @NotNull final List<String> errorMessages)
  {
    // If the object class does not define any superior classes, then determine
    // if that's okay.
    final String[] superiorClassNamesOrOIDs =
         objectClass.getSuperiorClasses();
    if (superiorClassNamesOrOIDs.length == 0)
    {
      if (! allowStructuralObjectClassWithoutSuperior)
      {
        final ObjectClassType type = objectClass.getObjectClassType();
        if (type == null)
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_NO_SUP_NULL_TYPE.get(
               objectClass.toString(), schemaFile.getAbsolutePath()));
        }
        else if (type == ObjectClassType.STRUCTURAL)
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_NO_SUP_STRUCTURAL_TYPE.get(
               objectClass.toString(), schemaFile.getAbsolutePath()));
        }
      }

      return;
    }


    // If the object class has multiple superior classes, then determine if
    // that's okay.
    if ((superiorClassNamesOrOIDs.length > 1) &&
         (! allowMultipleSuperiorObjectClasses))
    {
      errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_MULTIPLE_SUP.get(
           objectClass.toString(), schemaFile.getAbsolutePath()));
    }


    // Make sure that we can retrieve all of the superior classes.
    final Map<String,ObjectClassDefinition> superiorClasses =
         new LinkedHashMap<>();
    for (final String nameOrOID : superiorClassNamesOrOIDs)
    {
      final String lowerNameOrOID = StaticUtils.toLowerCase(nameOrOID);
      ObjectClassDefinition superiorClass = objectClassMap.get(lowerNameOrOID);
      if (superiorClass == null)
      {
        superiorClass = existingSchema.getObjectClass(lowerNameOrOID);
      }

      if (superiorClass == null)
      {
        if (! allowReferencesToUndefinedElementTypes.contains(
             SchemaElementType.OBJECT_CLASS))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_OC_UNDEFINED_SUP.get(
               objectClass.toString(), schemaFile.getAbsolutePath(),
               nameOrOID));
        }
      }
      else
      {
        superiorClasses.put(nameOrOID, superiorClass);
      }
    }

    // If we should verify the superior relationships, then do that now.
    if ((! allowInvalidObjectClassInheritance) && (! superiorClasses.isEmpty()))
    {
      if (objectClass.getObjectClassType() == null)
      {
        for (final Map.Entry<String,ObjectClassDefinition> e :
             superiorClasses.entrySet())
        {
          if (e.getValue().getObjectClassType() == ObjectClassType.AUXILIARY)
          {
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_OC_IMPLIED_STRUCTURAL_SUP_OF_AUXILIARY.
                      get(objectClass.toString(), schemaFile.getAbsolutePath(),
                           e.getKey()));
            break;
          }
        }
      }
      else
      {
        switch (objectClass.getObjectClassType())
        {
          case STRUCTURAL:
            for (final Map.Entry<String,ObjectClassDefinition>  e :
                 superiorClasses.entrySet())
            {
              if (e.getValue().getObjectClassType() ==
                   ObjectClassType.AUXILIARY)
              {
                errorMessages.add(
                     ERR_SCHEMA_VALIDATOR_OC_STRUCTURAL_SUP_OF_AUXILIARY.get(
                          objectClass.toString(), schemaFile.getAbsolutePath(),
                          e.getKey()));
                break;
              }
            }
            break;

          case AUXILIARY:
            for (final Map.Entry<String,ObjectClassDefinition>  e :
                 superiorClasses.entrySet())
            {
              if (e.getValue().getObjectClassType() ==
                   ObjectClassType.STRUCTURAL)
              {
                errorMessages.add(
                     ERR_SCHEMA_VALIDATOR_OC_AUXILIARY_SUP_OF_STRUCTURAL.get(
                          objectClass.toString(), schemaFile.getAbsolutePath(),
                          e.getKey()));
                break;
              }
            }
            break;

          case ABSTRACT:
            for (final Map.Entry<String,ObjectClassDefinition>  e :
                 superiorClasses.entrySet())
            {
              if (e.getValue().getObjectClassType() ==
                   ObjectClassType.STRUCTURAL)
              {
                errorMessages.add(
                     ERR_SCHEMA_VALIDATOR_OC_ABSTRACT_SUP_OF_STRUCTURAL.get(
                          objectClass.toString(), schemaFile.getAbsolutePath(),
                          e.getKey()));
                break;
              }
              else if (e.getValue().getObjectClassType() ==
                   ObjectClassType.AUXILIARY)
              {
                errorMessages.add(
                     ERR_SCHEMA_VALIDATOR_OC_ABSTRACT_SUP_OF_AUXILIARY.get(
                          objectClass.toString(), schemaFile.getAbsolutePath(),
                          e.getKey()));
                break;
              }
            }
            break;
        }
      }
    }
  }



  /**
   * Validates any name form definitions contained in the provided schema entry.
   *
   * @param  schemaEntry
   *              The entry containing the schema definitions to validate.  It
   *              must not be {@code null}.
   * @param  schemaFile
   *              The file from which the schema entry was read.  It must not be
   *              {@code null}.
   * @param  nameFormsByNameOrOID
   *              A map of the name form definitions that have already
   *              been parsed from the same file, indexed by OID and names.  It
   *              must not be {@code null} (but may be empty), and it must be
   *              updatable.
   * @param  nameFormsByOC
   *              A map of the name form definitions that have already
   *              been parsed from the same file, indexed by structural object
   *              class.  It must not be {@code null} (but may be empty), and it
   *              must be updatable.
   * @param  existingSchema
   *              An existing schema that has already been read (e.g., from
   *              earlier schema files).  It must not be {@code null}.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   */
  private void validateNameForms(@NotNull final Entry schemaEntry,
       @NotNull final File schemaFile,
       @NotNull final Map<String,NameFormDefinition> nameFormsByNameOrOID,
       @NotNull final Map<ObjectClassDefinition,NameFormDefinition>
            nameFormsByOC,
       @NotNull final Schema existingSchema,
       @NotNull final List<String> errorMessages)
  {
    for (final String nameFormString :
         schemaEntry.getAttributeValues(Schema.ATTR_NAME_FORM))
    {
      // If name forms aren't allowed, then report an error without doing
      // anything else.
      if (! allowedSchemaElementTypes.contains(SchemaElementType.NAME_FORM))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_NOT_ALLOWED.get(
             schemaFile.getAbsolutePath(), nameFormString));
        continue;
      }


      // Make sure that we can parse the name form definition.
      final NameFormDefinition nameForm;
      try
      {
        nameForm = new NameFormDefinition(nameFormString);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_CANNOT_PARSE_NF.get(
             nameFormString, schemaFile.getAbsolutePath(), e.getMessage()));
        continue;
      }


      // Make sure that the name form has a valid numeric OID.
      try
      {
        validateOID(nameForm.getOID(), nameForm.getNames());
      }
      catch (final ParseException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_INVALID_OID.get(
             nameFormString, schemaFile.getAbsolutePath(), e.getMessage()));
      }


      // Make sure that all of the names are valid.
      if ((nameForm.getNames().length == 0) && (! allowElementsWithoutNames))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_NO_NAME.get(nameFormString,
             schemaFile.getAbsolutePath()));
      }

      for (final String name : nameForm.getNames())
      {
        try
        {
          validateName(name);
        }
        catch (final ParseException e)
        {
          Debug.debugException(e);
          errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_INVALID_NAME.get(
               nameFormString, schemaFile.getAbsolutePath(), name,
               e.getMessage()));
        }
      }


      // If the name form has a description, then make sure it's not empty.
      if (! allowEmptyDescription)
      {
        final String description = nameForm.getDescription();
        if ((description != null) && description.isEmpty())
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_EMPTY_DESCRIPTION.get(
               nameFormString, schemaFile.getAbsolutePath()));
        }
      }


      // If the name form is declared obsolete, then make sure that's
      // allowed.
      if (nameForm.isObsolete() && (! allowObsoleteElements))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_OBSOLETE.get(
             nameFormString, schemaFile.getAbsolutePath()));
      }


      // Make sure that the structural object class is defined and is defined as
      // structural.
      final String structuralClassNameOrOID = nameForm.getStructuralClass();
      final ObjectClassDefinition structuralClass =
           existingSchema.getObjectClass(structuralClassNameOrOID);
      if (structuralClass == null)
      {
        if (! allowReferencesToUndefinedElementTypes.contains(
             SchemaElementType.OBJECT_CLASS))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_UNDEFINED_OC.get(
               nameFormString, schemaFile.getAbsolutePath(),
               structuralClassNameOrOID));
        }
      }
      else
      {
        if ((structuralClass.getObjectClassType() != null) &&
             (structuralClass.getObjectClassType() !=
                  ObjectClassType.STRUCTURAL))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_OC_NOT_STRUCTURAL.get(
               nameFormString, schemaFile.getAbsolutePath(),
               structuralClassNameOrOID));
        }
      }


      // Make sure that all of the required attribute types are defined and
      // permitted by the structural class.
      final Set<String> requiredAttrNamesAndOIDs = new HashSet<>();
      for (final String attrNameOrOID : nameForm.getRequiredAttributes())
      {
        requiredAttrNamesAndOIDs.add(StaticUtils.toLowerCase(attrNameOrOID));
        final AttributeTypeDefinition attrType =
             existingSchema.getAttributeType(attrNameOrOID);
        if (attrType == null)
        {
          if (! allowReferencesToUndefinedElementTypes.contains(
               SchemaElementType.ATTRIBUTE_TYPE))
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_UNDEFINED_REQ_ATTR.get(
                 nameFormString, schemaFile.getAbsolutePath(),
                 attrNameOrOID));
          }
        }
        else
        {
          requiredAttrNamesAndOIDs.add(
               StaticUtils.toLowerCase(attrType.getOID()));
          for (final String name : attrType.getNames())
          {
            requiredAttrNamesAndOIDs.add(StaticUtils.toLowerCase(name));
          }

          if ((structuralClass != null) &&
               (! (structuralClass.getRequiredAttributes(existingSchema, true).
                    contains(attrType) ||
                    structuralClass.getOptionalAttributes(existingSchema, true).
                         contains(attrType))))
          {
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_NF_REQ_ATTR_NOT_PERMITTED.get(
                      nameFormString, schemaFile.getAbsolutePath(),
                      attrNameOrOID, structuralClassNameOrOID));
          }
        }
      }


      // Make sure that all of the optional attribute types are defined and
      // permitted by the structural class.  Also, make sure that none of them
      // also appear in the set of required attributes.
      for (final String attrNameOrOID : nameForm.getOptionalAttributes())
      {
        if (requiredAttrNamesAndOIDs.contains(
             StaticUtils.toLowerCase(attrNameOrOID)))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_ATTR_REQ_AND_OPT.get(
               nameFormString, schemaFile.getAbsolutePath(), attrNameOrOID));
        }

        final AttributeTypeDefinition attrType =
             existingSchema.getAttributeType(attrNameOrOID);
        if (attrType == null)
        {
          if (! allowReferencesToUndefinedElementTypes.contains(
               SchemaElementType.ATTRIBUTE_TYPE))
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_NF_UNDEFINED_OPT_ATTR.get(
                 nameFormString, schemaFile.getAbsolutePath(),
                 attrNameOrOID));
          }
        }
      }


      // Make sure that the name form isn't already defined by OID, name, or
      // structural class.
      boolean isDuplicate = false;
      if (! allowRedefiningElements)
      {
        final String lowerOID = StaticUtils.toLowerCase(nameForm.getOID());
        NameFormDefinition existingDefinition =
             nameFormsByNameOrOID.get(lowerOID);
        if (existingDefinition == null)
        {
          existingDefinition = existingSchema.getNameFormByName(lowerOID);
        }

        if (existingDefinition != null)
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_NF_ALREADY_DEFINED_WITH_OID.get(
                    nameFormString, schemaFile.getAbsolutePath(),
                    existingDefinition.toString()));
          isDuplicate = true;
        }

        if (! isDuplicate)
        {
          for (final String name : nameForm.getNames())
          {
            final String lowerName = StaticUtils.toLowerCase(name);
            existingDefinition = nameFormsByNameOrOID.get(lowerName);
            if (existingDefinition == null)
            {
              existingDefinition = existingSchema.getNameFormByName(lowerName);
            }

            if (existingDefinition != null)
            {
              errorMessages.add(
                   ERR_SCHEMA_VALIDATOR_NF_ALREADY_DEFINED_WITH_NAME.get(
                        nameFormString, schemaFile.getAbsolutePath(),
                        name, existingDefinition.toString()));
              isDuplicate = true;
              break;
            }
          }
        }

        if ((! isDuplicate) && (structuralClass != null))
        {
          existingDefinition = nameFormsByOC.get(structuralClass);
          if (existingDefinition == null)
          {
            existingDefinition = existingSchema.getNameFormByObjectClass(
                 structuralClassNameOrOID);
          }

          if (existingDefinition != null)
          {
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_NF_ALREADY_DEFINED_WITH_OC.get(
                      nameFormString, schemaFile.getAbsolutePath(),
                      structuralClassNameOrOID, existingDefinition.toString()));
            isDuplicate = true;
          }
        }
      }


      // Add the name form to the maps so we can detect conflicts with later
      // name forms.
      if (! isDuplicate)
      {
        nameFormsByNameOrOID.put(StaticUtils.toLowerCase(nameForm.getOID()),
             nameForm);
        for (final String name : nameForm.getNames())
        {
          nameFormsByNameOrOID.put(StaticUtils.toLowerCase(name), nameForm);
        }

        if (structuralClass != null)
        {
          nameFormsByOC.put(structuralClass, nameForm);
        }
      }
    }
  }



  /**
   * Validates any DIT content rule definitions contained in the provided schema
   * entry.
   *
   * @param  schemaEntry
   *              The entry containing the schema definitions to validate.  It
   *              must not be {@code null}.
   * @param  schemaFile
   *              The file from which the schema entry was read.  It must not be
   *              {@code null}.
   * @param  dcrMap
   *              A map of the DIT content rule definitions that have already
   *              been parsed from the same file.  It must not be {@code null}
   *              (but may be empty), and it must be updatable.
   * @param  existingSchema
   *              An existing schema that has already been read (e.g., from
   *              earlier schema files).  It must not be {@code null}.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   */
  private void validateDITContentRules(@NotNull final Entry schemaEntry,
                    @NotNull final File schemaFile,
                    @NotNull final Map<String,DITContentRuleDefinition> dcrMap,
                    @NotNull final Schema existingSchema,
                    @NotNull final List<String> errorMessages)
  {
    for (final String dcrString :
         schemaEntry.getAttributeValues(Schema.ATTR_DIT_CONTENT_RULE))
    {
      // If DIT content rules aren't allowed, then report an error without
      // doing anything else.
      if (! allowedSchemaElementTypes.contains(
           SchemaElementType.DIT_CONTENT_RULE))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_NOT_ALLOWED.get(
             schemaFile.getAbsolutePath(), dcrString));
        continue;
      }


      // Make sure that we can parse the DIT content rule definition.
      final DITContentRuleDefinition dcr;
      try
      {
        dcr = new DITContentRuleDefinition(dcrString);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_CANNOT_PARSE_DCR.get(
             dcrString, schemaFile.getAbsolutePath(), e.getMessage()));
        continue;
      }


      // Make sure that the DIT content rule has a valid numeric OID.
      try
      {
        validateOID(dcr.getOID(), dcr.getNames());
      }
      catch (final ParseException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_INVALID_OID.get(
             dcrString, schemaFile.getAbsolutePath(), e.getMessage()));
      }


      // The DIT content rule's numeric OID must reference a structural
      // object class.
      final ObjectClassDefinition structuralObjectClass =
           existingSchema.getObjectClass(dcr.getOID());
      if (structuralObjectClass == null)
      {
        if (! allowReferencesToUndefinedElementTypes.contains(
             SchemaElementType.OBJECT_CLASS))
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_DCR_UNKNOWN_STRUCTURAL_CLASS.get(dcrString,
                    schemaFile.getAbsolutePath(), dcr.getOID()));
        }
      }
      else
      {
        if ((structuralObjectClass.getObjectClassType() != null) &&
             (structuralObjectClass.getObjectClassType() !=
                  ObjectClassType.STRUCTURAL))
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_DCR_STRUCTURAL_CLASS_NOT_STRUCTURAL.get(
                    dcrString, schemaFile.getAbsolutePath(), dcr.getOID(),
                    structuralObjectClass.toString()));
        }
      }


      // Make sure that all of the names are valid.
      if ((dcr.getNames().length == 0) &&
           (! allowElementsWithoutNames))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_NO_NAME.get(
             dcrString, schemaFile.getAbsolutePath()));
      }

      for (final String name : dcr.getNames())
      {
        try
        {
          validateName(name);
        }
        catch (final ParseException e)
        {
          Debug.debugException(e);
          errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_INVALID_NAME.get(
               dcrString, schemaFile.getAbsolutePath(), name,
               e.getMessage()));
        }
      }


      // If the DIT content rule has a description, then make sure it's not
      // empty.
      if (! allowEmptyDescription)
      {
        final String description = dcr.getDescription();
        if ((description != null) && description.isEmpty())
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_EMPTY_DESCRIPTION.get(
               dcrString, schemaFile.getAbsolutePath()));
        }
      }


      // If the DIT content rule is declared obsolete, then make sure that's
      // allowed.
      if (dcr.isObsolete() && (! allowObsoleteElements))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_OBSOLETE.get(
             dcrString, schemaFile.getAbsolutePath()));
      }


      //  If there are any auxiliary classes, make sure they are defined and
      // are auxiliary.
      for (final String auxClassNameOrOID : dcr.getAuxiliaryClasses())
      {
        final ObjectClassDefinition auxClass =
             existingSchema.getObjectClass(auxClassNameOrOID);
        if (auxClass == null)
        {
          if (! allowReferencesToUndefinedElementTypes.contains(
               SchemaElementType.OBJECT_CLASS))
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_UNDEFINED_AUX_CLASS.get(
                 dcrString, schemaFile.getAbsolutePath(), auxClassNameOrOID));
          }
        }
        else if (auxClass.getObjectClassType() != ObjectClassType.AUXILIARY)
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_AUX_CLASS_NOT_AUX.get(
               dcrString, schemaFile.getAbsolutePath(),
               auxClass.toString()));
        }
      }


      // If there are any required attribute types, then make sure they are
      // defined.
      final Set<String> requiredAttrNamesAndOIDs = new HashSet<>();
      for (final String attrNameOrOID : dcr.getRequiredAttributes())
      {
        requiredAttrNamesAndOIDs.add(StaticUtils.toLowerCase(attrNameOrOID));

        final AttributeTypeDefinition at =
             existingSchema.getAttributeType(attrNameOrOID);
        if (at == null)
        {
          if (! allowReferencesToUndefinedElementTypes.contains(
               SchemaElementType.ATTRIBUTE_TYPE))
          {
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_DCR_UNDEFINED_REQUIRED_ATTR.get(
                      dcrString, schemaFile.getAbsolutePath(), attrNameOrOID));
          }
        }
        else
        {
          requiredAttrNamesAndOIDs.add(StaticUtils.toLowerCase(at.getOID()));
          for (final String name : at.getNames())
          {
            requiredAttrNamesAndOIDs.add(StaticUtils.toLowerCase(name));
          }
        }
      }


      // If there are any optional attribute types, then make sure they are
      // defined.  Also, make sure they are also not listed as required.
      final Set<String> optionalAttrNamesAndOIDs = new HashSet<>();
      for (final String attrNameOrOID : dcr.getOptionalAttributes())
      {
        final String lowerNameOrOID = StaticUtils.toLowerCase(attrNameOrOID);
        optionalAttrNamesAndOIDs.add(lowerNameOrOID);

        if (requiredAttrNamesAndOIDs.contains(lowerNameOrOID))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_ATTR_REQ_AND_OPT.get(
               dcrString, schemaFile.getAbsolutePath(), attrNameOrOID));
        }

        final AttributeTypeDefinition at =
             existingSchema.getAttributeType(lowerNameOrOID);
        if (at == null)
        {
          if (! allowReferencesToUndefinedElementTypes.contains(
               SchemaElementType.ATTRIBUTE_TYPE))
          {
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_DCR_UNDEFINED_OPTIONAL_ATTR.get(
                      dcrString, schemaFile.getAbsolutePath(), attrNameOrOID));
          }
        }
        else
        {
          optionalAttrNamesAndOIDs.add(StaticUtils.toLowerCase(at.getOID()));
          for (final String name : at.getNames())
          {
            optionalAttrNamesAndOIDs.add(StaticUtils.toLowerCase(name));
          }
        }
      }


      // If there are any prohibited attribute types, then make sure they are
      // defined.  Also, make sure they are not listed as required or optional,
      // and make sure they are not required by the structural or any of the
      // auxiliary classes.
      for (final String attrNameOrOID : dcr.getProhibitedAttributes())
      {
        final String lowerNameOrOID = StaticUtils.toLowerCase(attrNameOrOID);
        if (requiredAttrNamesAndOIDs.contains(lowerNameOrOID))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_ATTR_REQ_AND_NOT.get(
               dcrString, schemaFile.getAbsolutePath(), attrNameOrOID));
        }

        if (optionalAttrNamesAndOIDs.contains(lowerNameOrOID))
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_DCR_ATTR_OPT_AND_NOT.get(
               dcrString, schemaFile.getAbsolutePath(), attrNameOrOID));
        }

        final AttributeTypeDefinition at =
             existingSchema.getAttributeType(lowerNameOrOID);
        if (at == null)
        {
          if (! allowReferencesToUndefinedElementTypes.contains(
               SchemaElementType.ATTRIBUTE_TYPE))
          {
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_DCR_UNDEFINED_PROHIBITED_ATTR.get(
                      dcrString, schemaFile.getAbsolutePath(), attrNameOrOID));
          }
        }
        else
        {
          if (structuralObjectClass != null)
          {
            if (structuralObjectClass.getRequiredAttributes(existingSchema,
                 true).contains(at))
            {
              errorMessages.add(
                   ERR_SCHEMA_VALIDATOR_DCR_PROHIBITED_ATTR_REQUIRED_BY_STRUCT.
                        get(dcrString, schemaFile.getAbsolutePath(),
                             attrNameOrOID));
            }
          }

          for (final String auxClassNameOrOID : dcr.getAuxiliaryClasses())
          {
            final ObjectClassDefinition auxClass =
                 existingSchema.getObjectClass(auxClassNameOrOID);
            if ((auxClass != null) &&
                 auxClass.getRequiredAttributes(existingSchema, true).contains(
                      at))
            {
              errorMessages.add(
                   ERR_SCHEMA_VALIDATOR_DCR_PROHIBITED_ATTR_REQUIRED_BY_AUX.
                        get(dcrString, schemaFile.getAbsolutePath(),
                             attrNameOrOID, auxClassNameOrOID));
            }
          }
        }
      }


      // Make sure that the DIT content rule isn't already defined.
      boolean isDuplicate = false;
      if (! allowRedefiningElements)
      {
        final String lowerOID = StaticUtils.toLowerCase(dcr.getOID());
        DITContentRuleDefinition existingDefinition = dcrMap.get(lowerOID);
        if (existingDefinition == null)
        {
          existingDefinition = existingSchema.getDITContentRule(lowerOID);
        }

        if (existingDefinition != null)
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_DCR_ALREADY_DEFINED_WITH_OID.get(
                    dcrString, schemaFile.getAbsolutePath(),
                    existingDefinition.toString()));
          isDuplicate = true;
        }

        if (! isDuplicate)
        {
          for (final String name : dcr.getNames())
          {
            final String lowerName = StaticUtils.toLowerCase(name);
            existingDefinition = dcrMap.get(lowerName);
            if (existingDefinition == null)
            {
              existingDefinition = existingSchema.getDITContentRule(lowerName);
            }

            if (existingDefinition != null)
            {
              errorMessages.add(
                   ERR_SCHEMA_VALIDATOR_DCR_ALREADY_DEFINED_WITH_NAME.get(
                        dcrString, schemaFile.getAbsolutePath(),
                        name, existingDefinition.toString()));
              isDuplicate = true;
              break;
            }
          }
        }
      }


      // Add the DIT content rule to the map so it can be used to detect
      // duplicates.
      if (! isDuplicate)
      {
        dcrMap.put(StaticUtils.toLowerCase(dcr.getOID()), dcr);
        for (final String name : dcr.getNames())
        {
          dcrMap.put(StaticUtils.toLowerCase(name), dcr);
        }
      }
    }
  }



  /**
   * Validates any DIT structure rule definitions contained in the provided
   * schema entry.
   *
   * @param  schemaEntry
   *              The entry containing the schema definitions to validate.  It
   *              must not be {@code null}.
   * @param  schemaFile
   *              The file from which the schema entry was read.  It must not be
   *              {@code null}.
   * @param  dsrIDAndNameMap
   *              A map of the DIT structure rule definitions that have already
   *              been parsed from the same file, indexed by rule ID and name.
   *              It must not be {@code null} (but may be empty), and it must be
   *              updatable.
   * @param  dsrNFMap
   *              A map of the DIT structure rule definitions that have already
   *              been parsed from the same file, indexed by name form
   *              definition.  It must not be {@code null} (but may be empty),
   *              and it must be updatable.
   * @param  existingSchema
   *              An existing schema that has already been read (e.g., from
   *              earlier schema files).  It must not be {@code null}.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   */
  private void validateDITStructureRules(@NotNull final Entry schemaEntry,
       @NotNull final File schemaFile,
       @NotNull final Map<String,DITStructureRuleDefinition> dsrIDAndNameMap,
       @NotNull final Map<NameFormDefinition,DITStructureRuleDefinition>
            dsrNFMap,
       @NotNull final Schema existingSchema,
       @NotNull final List<String> errorMessages)
  {
    for (final String dsrString :
         schemaEntry.getAttributeValues(Schema.ATTR_DIT_STRUCTURE_RULE))
    {
      // If DIT structure rules aren't allowed, then report an error without
      // doing anything else.
      if (! allowedSchemaElementTypes.contains(
           SchemaElementType.DIT_STRUCTURE_RULE))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_DSR_NOT_ALLOWED.get(
             schemaFile.getAbsolutePath(), dsrString));
        continue;
      }


      // Make sure that we can parse the DIT structure rule definition.
      final DITStructureRuleDefinition dsr;
      try
      {
        dsr = new DITStructureRuleDefinition(dsrString);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_CANNOT_PARSE_DSR.get(
             dsrString, schemaFile.getAbsolutePath(), e.getMessage()));
        continue;
      }


      // Make sure that all of the names are valid.
      if ((dsr.getNames().length == 0) &&
           (! allowElementsWithoutNames))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_DSR_NO_NAME.get(
             dsrString, schemaFile.getAbsolutePath()));
      }

      for (final String name : dsr.getNames())
      {
        try
        {
          validateName(name);
        }
        catch (final ParseException e)
        {
          Debug.debugException(e);
          errorMessages.add(ERR_SCHEMA_VALIDATOR_DSR_INVALID_NAME.get(
               dsrString, schemaFile.getAbsolutePath(), name,
               e.getMessage()));
        }
      }


      // If the DIT structure rule has a description, then make sure it's not
      // empty.
      if (! allowEmptyDescription)
      {
        final String description = dsr.getDescription();
        if ((description != null) && description.isEmpty())
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_DSR_EMPTY_DESCRIPTION.get(
               dsrString, schemaFile.getAbsolutePath()));
        }
      }


      // If the DIT content rule is declared obsolete, then make sure that's
      // allowed.
      if (dsr.isObsolete() && (! allowObsoleteElements))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_DSR_OBSOLETE.get(
             dsrString, schemaFile.getAbsolutePath()));
      }


      // Make sure that the name form is defined.
      final String nameFormNameOrOID = dsr.getNameFormID();
      final NameFormDefinition nameForm =
           existingSchema.getNameFormByName(nameFormNameOrOID);
      if ((nameForm == null) &&
           (! allowReferencesToUndefinedElementTypes.contains(
                SchemaElementType.NAME_FORM)))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_DSR_UNDEFINED_NF.get(dsrString,
             schemaFile.getAbsolutePath(), nameFormNameOrOID));
      }


      // If there are any superior rule IDs, then make sure they are defined.
      if (! allowReferencesToUndefinedElementTypes.contains(
           SchemaElementType.DIT_STRUCTURE_RULE))
      {
        for (final int superiorRuleID : dsr.getSuperiorRuleIDs())
        {
          final DITStructureRuleDefinition superiorDSR =
               dsrIDAndNameMap.get(String.valueOf(superiorRuleID));
          if (superiorDSR == null)
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_DSR_UNDEFINED_SUP.get(
                 dsrString, schemaFile.getAbsolutePath(), superiorRuleID));
          }
        }
      }


      // Make sure that the DIT structure rule isn't already defined.
      boolean isDuplicate = false;
      if (! allowRedefiningElements)
      {
        DITStructureRuleDefinition existingDefinition =
             dsrIDAndNameMap.get(String.valueOf(dsr.getRuleID()));
        if (existingDefinition == null)
        {
          existingDefinition =
               existingSchema.getDITStructureRuleByID(dsr.getRuleID());
        }

        if (existingDefinition != null)
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_DSR_ALREADY_DEFINED_WITH_ID.get(
                    dsrString, schemaFile.getAbsolutePath(),
                    existingDefinition.toString()));
          isDuplicate = true;
        }

        if (! isDuplicate)
        {
          for (final String name : dsr.getNames())
          {
            final String lowerName = StaticUtils.toLowerCase(name);
            existingDefinition = dsrIDAndNameMap.get(lowerName);
            if (existingDefinition == null)
            {
              existingDefinition =
                   existingSchema.getDITStructureRuleByName(lowerName);
            }

            if (existingDefinition != null)
            {
              errorMessages.add(
                   ERR_SCHEMA_VALIDATOR_DSR_ALREADY_DEFINED_WITH_NAME.get(
                        dsrString, schemaFile.getAbsolutePath(),
                        name, existingDefinition.toString()));
              isDuplicate = true;
              break;
            }
          }
        }

        if ((! isDuplicate) && (nameForm != null))
        {
          existingDefinition = dsrNFMap.get(nameForm);
          if (existingDefinition == null)
          {
            existingDefinition = existingSchema.getDITStructureRuleByNameForm(
                 nameFormNameOrOID);
          }

          if (existingDefinition != null)
          {
            errorMessages.add(
                 ERR_SCHEMA_VALIDATOR_DSR_ALREADY_DEFINED_WITH_NF.get(
                      dsrString, schemaFile.getAbsolutePath(),
                      nameFormNameOrOID, existingDefinition.toString()));
            isDuplicate = true;
          }
        }
      }


      // Add the DIT content rule to the map so it can be used to detect
      // duplicates.
      if (! isDuplicate)
      {
        dsrIDAndNameMap.put(String.valueOf(dsr.getRuleID()), dsr);
        for (final String name : dsr.getNames())
        {
          dsrIDAndNameMap.put(StaticUtils.toLowerCase(name), dsr);
        }

        if (nameForm != null)
        {
          dsrNFMap.put(nameForm, dsr);
        }
      }
    }
  }



  /**
   * Validates any matching rule use definitions contained in the provided
   * schema entry.
   *
   * @param  schemaEntry
   *              The entry containing the schema definitions to validate.  It
   *              must not be {@code null}.
   * @param  schemaFile
   *              The file from which the schema entry was read.  It must not be
   *              {@code null}.
   * @param  mruMap
   *              A map of the matching rule use definitions that have already
   *              been parsed from the same file.  It must not be {@code null}
   *              (but may be empty), and it must be updatable.
   * @param  existingSchema
   *              An existing schema that has already been read (e.g., from
   *              earlier schema files).  It must not be {@code null}.
   * @param  errorMessages
   *              A list that will be updated with error messages about any
   *              problems identified during processing.  It must not be
   *              {@code null}, and it must be updatable.
   */
  private void validateMatchingRuleUses(@NotNull final Entry schemaEntry,
                    @NotNull final File schemaFile,
                    @NotNull final Map<String,MatchingRuleUseDefinition> mruMap,
                    @NotNull final Schema existingSchema,
                    @NotNull final List<String> errorMessages)
  {
    for (final String mruString :
         schemaEntry.getAttributeValues(Schema.ATTR_MATCHING_RULE_USE))
    {
      // If matching rule uses aren't allowed, then report an error without
      // doing anything else.
      if (! allowedSchemaElementTypes.contains(
           SchemaElementType.MATCHING_RULE_USE))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_NOT_ALLOWED.get(
             schemaFile.getAbsolutePath(), mruString));
        continue;
      }


      // Make sure that we can parse the matching rule use definition.
      final MatchingRuleUseDefinition mru;
      try
      {
        mru = new MatchingRuleUseDefinition(mruString);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_CANNOT_PARSE_MRU.get(
             mruString, schemaFile.getAbsolutePath(), e.getMessage()));
        continue;
      }


      // Make sure that the matching rule use has a valid numeric OID.
      try
      {
        validateOID(mru.getOID(), mru.getNames());
      }
      catch (final ParseException e)
      {
        Debug.debugException(e);
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_INVALID_OID.get(
             mruString, schemaFile.getAbsolutePath(), e.getMessage()));
      }


      // Make sure that the matching rule use OID references a defined matching
      // rule.
      MatchingRuleDefinition matchingRule =
           matchingRuleMap.get( StaticUtils.toLowerCase(mru.getOID()));
      if (matchingRule == null)
      {
        matchingRule = existingSchema.getMatchingRule(mru.getOID());
      }

      if ((matchingRule == null) &&
           (! allowReferencesToUndefinedElementTypes.contains(
                SchemaElementType.MATCHING_RULE)))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_UNDEFINED_MR.get(
             mruString, schemaFile.getAbsolutePath(), mru.getOID()));
      }


      // Make sure that all of the names are valid.
      if ((mru.getNames().length == 0) &&
           (! allowElementsWithoutNames))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_NO_NAME.get(
             mruString, schemaFile.getAbsolutePath()));
      }

      for (final String name : mru.getNames())
      {
        try
        {
          validateName(name);
        }
        catch (final ParseException e)
        {
          Debug.debugException(e);
          errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_INVALID_NAME.get(
               mruString, schemaFile.getAbsolutePath(), name,
               e.getMessage()));
        }
      }


      // If the matching rule use has a description, then make sure it's not
      // empty.
      if (! allowEmptyDescription)
      {
        final String description = mru.getDescription();
        if ((description != null) && description.isEmpty())
        {
          errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_EMPTY_DESCRIPTION.get(
               mruString, schemaFile.getAbsolutePath()));
        }
      }


      // If the matching rule use is declared obsolete, then make sure that's
      // allowed.
      if (mru.isObsolete() && (! allowObsoleteElements))
      {
        errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_OBSOLETE.get(
             mruString, schemaFile.getAbsolutePath()));
      }


      // Make sure that all of the referenced attribute types are defined in the
      // schema.
      final Set<AttributeTypeDefinition> applicableTypes = new HashSet<>();
      for (final String attrNameOrOID : mru.getApplicableAttributeTypes())
      {
        final AttributeTypeDefinition at =
             existingSchema.getAttributeType(attrNameOrOID);
        if (at == null)
        {
          if (! allowReferencesToUndefinedElementTypes.contains(
               SchemaElementType.ATTRIBUTE_TYPE))
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_UNDEFINED_AT.get(
                 mruString, schemaFile.getAbsolutePath(), attrNameOrOID));
          }
        }
        else
        {
          applicableTypes.add(at);
        }
      }


      // Examine the schema to determine whether there are any attribute types
      // that use the associated matching rule but aren't in the list of
      // applicable types.
      if (matchingRule != null)
      {
        for (final AttributeTypeDefinition at :
             existingSchema.getAttributeTypes())
        {
          if (applicableTypes.contains(at))
          {
            continue;
          }

          final String eqMR = at.getEqualityMatchingRule();
          if ((eqMR != null) && matchingRule.hasNameOrOID(eqMR))
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_PROHIBITS_AT_EQ.get(
                 at.toString(), eqMR, mruString, schemaFile.getAbsolutePath()));
          }

          final String ordMR = at.getOrderingMatchingRule();
          if ((ordMR != null) && matchingRule.hasNameOrOID(ordMR))
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_PROHIBITS_AT_ORD.get(
                 at.toString(), ordMR, mruString,
                 schemaFile.getAbsolutePath()));
          }

          final String subMR = at.getSubstringMatchingRule();
          if ((subMR != null) && matchingRule.hasNameOrOID(subMR))
          {
            errorMessages.add(ERR_SCHEMA_VALIDATOR_MRU_PROHIBITS_AT_SUB.get(
                 at.toString(), subMR, mruString,
                 schemaFile.getAbsolutePath()));
          }
        }
      }


      // Make sure that the matching rule use isn't already defined.
      boolean isDuplicate = false;
      if (! allowRedefiningElements)
      {
        final String lowerOID = StaticUtils.toLowerCase(mru.getOID());
        MatchingRuleUseDefinition existingDefinition = mruMap.get(lowerOID);
        if (existingDefinition == null)
        {
          existingDefinition = existingSchema.getMatchingRuleUse(lowerOID);
        }

        if (existingDefinition != null)
        {
          errorMessages.add(
               ERR_SCHEMA_VALIDATOR_MRU_ALREADY_DEFINED_WITH_OID.get(
                    mruString, schemaFile.getAbsolutePath(),
                    existingDefinition.toString()));
          isDuplicate = true;
        }

        if (! isDuplicate)
        {
          for (final String name : mru.getNames())
          {
            final String lowerName = StaticUtils.toLowerCase(name);
            existingDefinition = mruMap.get(lowerName);
            if (existingDefinition == null)
            {
              existingDefinition = existingSchema.getMatchingRuleUse(lowerName);
            }

            if (existingDefinition != null)
            {
              errorMessages.add(
                   ERR_SCHEMA_VALIDATOR_MRU_ALREADY_DEFINED_WITH_NAME.get(
                        mruString, schemaFile.getAbsolutePath(),
                        name, existingDefinition.toString()));
              isDuplicate = true;
              break;
            }
          }
        }
      }


      // Add the matching rule use to the map so it can be used to detect
      // duplicates.
      if (! isDuplicate)
      {
        mruMap.put(StaticUtils.toLowerCase(mru.getOID()), mru);
        for (final String name : mru.getNames())
        {
          mruMap.put(StaticUtils.toLowerCase(name), mru);
        }
      }
    }
  }



  /**
   * Ensures that the provided object identifier is valid, within the
   * constraints of the schema validator.
   *
   * @param  oid    The object identifier to validate.  It must not be
   *                {@code null}.
   * @param  names  The set of names for the schema element.  It may be
   *                {@code null} or empty if the element does not have any
   *                names.
   *
   * @throws  ParseException  If the provided OID is not valid.
   */
  private void validateOID(@NotNull final String oid,
                           @Nullable final String[] names)
       throws ParseException
  {
    try
    {
      OID.parseNumericOID(oid, useStrictOIDValidation);
    }
    catch (final ParseException e)
    {
      Debug.debugException(e);

      boolean acceptable = false;
      if (allowNonNumericOIDsUsingName && (names != null))
      {
        for (final String name : names)
        {
          if (oid.equalsIgnoreCase(name + "-oid"))
          {
            acceptable = true;
            break;
          }
        }
      }

      if ((! acceptable ) && allowNonNumericOIDsNotUsingName)
      {
        acceptable = true;
      }

      if (! acceptable)
      {
        throw e;
      }
    }
  }



  /**
   * Ensures that the provided name is valid for a schema element, within the
   * constraints of the schema validator.
   *
   * @param  name  The name to validate.  It must not be {@code null}.
   *
   * @throws  ParseException  If the provided name is not valid.
   */
  void validateName(@NotNull final String name)
       throws ParseException
  {
    if (name.isEmpty())
    {
      throw new ParseException(ERR_SCHEMA_VALIDATOR_ELEMENT_NAME_EMPTY.get(),
           0);
    }

    final char firstChar = name.charAt(0);
    if (((firstChar >= 'a') && (firstChar <= 'z')) ||
         ((firstChar >= 'A') && (firstChar <= 'Z')))
    {
      // This is always okay.
    }
    else if ((firstChar >= '0') && (firstChar <= '9'))
    {
      if (allowNamesWithInitialDigit)
      {
        // This is technically illegal, but we'll allow it.
      }
      else
      {
        throw new ParseException(
             ERR_SCHEMA_VALIDATOR_ELEMENT_NAME_DOES_NOT_START_WITH_LETTER.get(),
             0);
      }
    }
    else if (firstChar == '-')
    {
      if (allowNamesWithInitialHyphen)
      {
        // This is technically illegal, but we'll allow it.
      }
      else
      {
        throw new ParseException(
             ERR_SCHEMA_VALIDATOR_ELEMENT_NAME_DOES_NOT_START_WITH_LETTER.get(),
             0);
      }
    }
    else if (firstChar == '_')
    {
      if (allowNamesWithUnderscore)
      {
        // This is technically illegal, but we'll allow it.
      }
      else
      {
        throw new ParseException(
             ERR_SCHEMA_VALIDATOR_ELEMENT_NAME_DOES_NOT_START_WITH_LETTER.get(),
             0);
      }
    }
    else
    {
      throw new ParseException(
           ERR_SCHEMA_VALIDATOR_ELEMENT_NAME_DOES_NOT_START_WITH_LETTER.get(),
           0);
    }

    for (int i = 1; i < name.length(); i++)
    {
      final char subsequentChar = name.charAt(i);
      if (((subsequentChar >= 'a') && (subsequentChar <= 'z')) ||
           ((subsequentChar >= 'A') && (subsequentChar <= 'Z')) ||
           ((subsequentChar >= '0') && (subsequentChar <= '9')) ||
           (subsequentChar == '-'))
      {
        // This is always okay.
      }
      else if ((subsequentChar == '_') && allowNamesWithUnderscore)
      {
        // This is technically illegal, but we'll allow it.
      }
      else
      {
        throw new ParseException(
             ERR_SCHEMA_VALIDATOR_ELEMENT_NAME_ILLEGAL_CHARACTER.get(
                  subsequentChar, i),
             i);
      }
    }
  }
}
