/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.AttributeSyntaxDefinition;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.AttributeUsage;
import com.unboundid.ldap.sdk.schema.DITContentRuleDefinition;
import com.unboundid.ldap.sdk.schema.DITStructureRuleDefinition;
import com.unboundid.ldap.sdk.schema.MatchingRuleDefinition;
import com.unboundid.ldap.sdk.schema.MatchingRuleUseDefinition;
import com.unboundid.ldap.sdk.schema.NameFormDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassType;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code compare-ldap-schemas}
 * tool.
 */
public final class CompareLDAPSchemasTestCase
       extends LDAPSDKTestCase
{
  /**
   * A precomputed entry with the default content for custom schema.
   */
  private static final ReadOnlyEntry DEFAULT_CUSTOM_SCHEMA_ENTRY;
  static
  {
    ReadOnlyEntry schemaEntry = null;
    try
    {
      final Entry e =
           Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
      e.setDN(new DN(e.getRDN(), new DN("dc=example,dc=com")));
      schemaEntry = new ReadOnlyEntry(e);
    }
    catch (final Exception e)
    {
      throw new RuntimeException(e);
    }
    finally
    {
      DEFAULT_CUSTOM_SCHEMA_ENTRY = schemaEntry;
    }
  }



  /**
   * Tests the behavior when comparing two servers with identical schemas when
   * that schema is discovered rather than explicitly specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoDifferencesDiscoveringSchema()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(dsConfig);
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(dsConfig);
    try
    {
      ds1.startListening();
      ds2.startListening();

      assertToolResultCodeIs(ds1, ds2, false, ResultCode.SUCCESS);
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers with identical schemas when
   * that schema entry is explicitly specified.
   * <BR><BR>
   * Also, to get a little additional coverage, use the getExtendedSchemaInfo
   * argument in one of the requests.  The in-memory directory server doesn't
   * support the associated control, but the request makes it non-critical, so
   * the server should ignore it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoDifferencesSpecifiedSchemaEntry()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema();
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--getExtendedSchemaInfo");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * malformed attribute syntax definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxMalformed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, "malformed"));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX);

      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has an
   * attribute syntax definition that the other doesn't have.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxMissing()
         throws Exception
  {
    final AttributeSyntaxDefinition def1 =
         new AttributeSyntaxDefinition("1.2.3.4", "Test", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which an attribute syntax
   * exists in both servers, but has a description in one server and is missing
   * a description in the other.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxMissingDescription()
         throws Exception
  {
    final AttributeSyntaxDefinition def1 =
         new AttributeSyntaxDefinition("1.2.3.4", "Has Description", null);
    final AttributeSyntaxDefinition def2 =
         new AttributeSyntaxDefinition("1.2.3.4", null, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which an attribute syntax
   * exists in both servers, but has a different description in each server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxDifferentDescriptions()
         throws Exception
  {
    final AttributeSyntaxDefinition def1 =
         new AttributeSyntaxDefinition("1.2.3.4", "Description 1", null);
    final AttributeSyntaxDefinition def2 =
         new AttributeSyntaxDefinition("1.2.3.4", "Description 2", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which an attribute syntax
   * exists in both servers, but has an extension in one server and does not
   * have any extensions in the other server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxMissingAnyExtension()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final AttributeSyntaxDefinition def1 =
         new AttributeSyntaxDefinition("1.2.3.4", "Test", ext1);
    final AttributeSyntaxDefinition def2 =
         new AttributeSyntaxDefinition("1.2.3.4", "Test", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which an attribute syntax
   * exists in both servers, but has two extensions in one server, but only one
   * of them in the second.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxMissingSomeExtension()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" },
         "X-TEST-2", new String[] { "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" });

    final AttributeSyntaxDefinition def1 =
         new AttributeSyntaxDefinition("1.2.3.4", "Test", ext1);
    final AttributeSyntaxDefinition def2 =
         new AttributeSyntaxDefinition("1.2.3.4", "Test", ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which an attribute syntax
   * exists in both servers, but has an extension in each server, but when one
   * server has two values for that extension, while the other only has one of
   * those values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeSyntaxMissingSomeExtensionValues()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1", "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final AttributeSyntaxDefinition def1 =
         new AttributeSyntaxDefinition("1.2.3.4", "Test", ext1);
    final AttributeSyntaxDefinition def2 =
         new AttributeSyntaxDefinition("1.2.3.4", "Test", ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_SYNTAX, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * malformed matching rule definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleMalformed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, "malformed"));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX);

      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * matching rule definition that the other doesn't have.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleMissing()
         throws Exception
  {
    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule, but one of them has a name while the other doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleOnlyOneHasName()
         throws Exception
  {
    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", null);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         null, "test-description", "1.2.3.5", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule, but they have different names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleDifferentNames()
         throws Exception
  {
    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         "test-name-1", "test-description", "1.2.3.5", null);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         "test-name-2", "test-description", "1.2.3.5", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule, but one of them has multiple names, while the other only has
   * one of those names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleMissingOneOfMultipleNames()
         throws Exception
  {
    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "1.2.3.5", null);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         new String[] { "test-name-1" }, "test-description", false, "1.2.3.5",
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule, but they have different syntax OIDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleDifferentSyntaxOIDs()
         throws Exception
  {
    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", null);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.6", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule, but one is obsolete while the other is not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleDifferentObsolete()
         throws Exception
  {
    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "1.2.3.5", null);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         true, "1.2.3.5", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which a matching rule
   * exists in both servers, but has a description in one server and is missing
   * a description in the other.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleMissingDescription()
         throws Exception
  {
    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", null);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", null, "1.2.3.5", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which a matching rule
   * exists in both servers, but has a different description in each server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleDifferentDescriptions()
         throws Exception
  {
    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description-1", "1.2.3.5", null);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description-2", "1.2.3.5", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which a matching rule
   * exists in both servers, but has an extension in one server and does not
   * have any extensions in the other server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleMissingAnyExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", ext1);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which a matching rule
   * exists in both servers, but has two extensions in one server, but only one
   * of them in the second.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleMissingSomeExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" },
         "X-TEST-2", new String[] { "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" });

    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", ext1);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which a matching rule
   * exists in both servers, but has an extension in each server, but when one
   * server has two values for that extension, while the other only has one of
   * those values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleMissingSomeExtensionValues()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1", "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final MatchingRuleDefinition def1 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", ext1);
    final MatchingRuleDefinition def2 = new MatchingRuleDefinition("1.2.3.4",
         "test-name", "test-description", "1.2.3.5", ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * malformed attribute type definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMalformed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, "malformed"));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX);

      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has an
   * attribute type definition that the other doesn't have.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissing()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         "test-name", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but one of them has a name while the other doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeOnlyOneHasName()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         "test-name", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         null, "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentNames()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-2", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but one of them has multiple names, while the other only
   * has one of those names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingOneOfMultipleNames()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, null, "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1" }, "test-description",
         false, null, "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but one of them has a superior type, while the other does
   * not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingSuperiorType()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, null, "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different superior types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentSuperiorTypes()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior-1", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior-2", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but one of them has a syntax OID, while the other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingSyntaxOID()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", null, true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different syntax OIDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentSyntaxOIDs()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.26", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but one of them has an equality matching rule, while the
   * other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingEqualityMatchingRule()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", null, "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different equality matching rules.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentEqualityMatchingRules()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseExactMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but one of them has an ordering matching rule, while the
   * other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingOrderingMatchingRule()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", null,
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different ordering matching rules.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentOrderingMatchingRules()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseExactOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but one of them has a substring matching rule, while the
   * other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingSubstringMatchingRule()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         null, "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different substring matching rules.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentSubstringMatchingRules()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseExactSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different single-value settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentSingleValue()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", false,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different usages.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentUsages()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.DIRECTORY_OPERATION, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different NO-USER-MODIFICATION settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentNoUserModification()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, true, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different obsolete settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentCollective()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         true, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but they have different obsolete settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentObsolete()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         true, "test-superior", "caseIgnoreMatch", "caseIgnoreOrderingMatch",
         "caseIgnoreSubstringsMatch", "1.3.6.1.4.1.1466.115.121.1.15", true,
         false, false, AttributeUsage.USER_APPLICATIONS, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but has a description in one server and is missing a
   * description in the other.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingDescription()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", null, "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but has a different description in each server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeDifferentDescriptions()
         throws Exception
  {
    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description-1", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description-2", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but has an extension in one server and does not have any
   * extensions in the other server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingAnyExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, ext1);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but has two extensions in one server, but only one of them
   * in the second.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingSomeExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" },
         "X-TEST-2", new String[] { "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" });

    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, ext1);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * attribute type, but has an extension in each server, but when one server
   * has two values for that extension, while hte other has only one of those
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeTypeMissingSomeExtensionValues()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1", "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final AttributeTypeDefinition def1 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, ext1);
    final AttributeTypeDefinition def2 = new AttributeTypeDefinition("1.2.3.4",
         "test-name-1", "test-description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch",
         "1.3.6.1.4.1.1466.115.121.1.15", true, ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * malformed object class definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMalformed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, "malformed"));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX);

      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has an
   * object class definition that the other doesn't have.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissing()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         "test-name", "test-description", "top", ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, but one of them has a name while the other doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassOnlyOneHasName()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         "test-name", "test-description", "top", ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         null, "test-description", "top", ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, but they have different names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassDifferentNames()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         "test-name-1", "test-description", "top", ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         "test-name-2", "test-description", "top", ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, but one of them has multiple names, while the other only has
   * one of those names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingOneOfMultipleNames()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, but one of them has a superior class while the other does
   * not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingSuperiorClass()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, null, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where each has a single superior class, but those classes are
   * different.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassDifferentSuperiorClass()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "untypedObject" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where the first has two superior object classes while the
   * second only has one of them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassOneMissingSuperiorClassValue()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top", "untypedObject" },
         ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where the first server has a required attribute while the
   * second does not have any.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingRequiredAttribute()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         null,
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where the first server has a required attribute while the
   * second does not have one of those values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingRequiredAttributeValue()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where the first server has an optional attribute while the
   * second does not have any.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingOptionalAttribute()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where the first server has an optional attribute while the
   * second does not have one of those values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingOptionalAttributeValue()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where the first server has an object class type while the
   * second does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingObjectClassType()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, null,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where they have different object class types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassDifferentObjectClassType()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.AUXILIARY,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where the servers have different obsolete values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassDifferentObsolete()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         true, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where one of the servers has a description while the other
   * does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingDescription()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, null,
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, where one of the servers has a description while the other
   * does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassDifferentDescriptions()
         throws Exception
  {
    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description-1",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description-2",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, but has an extension in one server and does not have any
   * extensions in the other server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingAnyExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         ext1);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, but has two extensions in one server, but only one of them in
   * the second.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingSomeExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" },
         "X-TEST-2", new String[] { "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" });

    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         ext1);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have an
   * object class, but has an extension in each server, but when one server has
   * two values for that extension, while hte other has only one of those
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectClassMissingSomeExtensionValues()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1", "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final ObjectClassDefinition def1 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2" }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         ext1);
    final ObjectClassDefinition def2 = new ObjectClassDefinition("1.2.3.4",
         new String[] { "test-name-1", "test-name-2"  }, "test-description",
         false, new String[] { "top" }, ObjectClassType.STRUCTURAL,
         new String[] { "required-1", "required-2" },
         new String[] { "optional-1", "optional-2" },
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_OBJECT_CLASS, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * malformed DIT content rule definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMalformed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, "malformed"));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX);

      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a DIT
   * content rule definition that the other doesn't have.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissing()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of the has a name while the other
   * doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleOnlyOneHasName()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         null,
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but they have different names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleDifferentNames()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr-1" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr-2" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has multiple names, while the
   * other only has one of those names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingOneOfMultipleNames()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr-1", "test-dcr-2" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr-1" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has required attributes while
   * the other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingAnyRequiredAttributes()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         null,
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has multiple required
   * attributes while the other only has one of them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingOneOfMultipleRequiredAttributes()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has optional attributes while
   * the other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingAnyOptionalAttributes()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         null,
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has multiple optional
   * attributes while the other is missing one of them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingOneOfMultipleOptionalAttributes()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has prohibited attributes
   * while the other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingAnyProhibitedAttributes()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has multiple prohibited
   * attributes while the other is missing one of them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingOneOfMultipleProhibitedAttributes()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has allowed auxiliary object
   * classes while the other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingAnyAuxiliaryClasses()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         null,
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has multiple allowed auxiliary
   * object classes while the other is missing one of them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingOneOfMultipleAuxiliaryClasses()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but one of them has a description while the
   * other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingDescription()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         null,
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but they have different descriptions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleDifferentDescriptions()
         throws Exception
  {
    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description-1",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description-2",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but has an extension in one server and does
   * not have any extensions in the other server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingAnyExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         ext1);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule definition, but has two extensions in one server, but only
   * one of those extensions in the other.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingSomeExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" },
         "X-TEST-2", new String[] { "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" });

    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         ext1);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT content rule, but has an extension in each server, but when one server
   * has two values for that extension, while the other has only one of those
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITContentRuleMissingSomeExtensionValues()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1", "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final DITContentRuleDefinition def1 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         ext1);
    final DITContentRuleDefinition def2 = new DITContentRuleDefinition(
         "1.2.3.4",
         new String[] { "test-dcr" },
         "test-description",
         false,
         new String[] { "test-auxiliary-class-1", "test-auxiliary-class-2" },
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         new String[] { "prohibited-attribute-1", "prohibited-attribute-2" },
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_CONTENT_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * malformed DIT structure rule definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMalformed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, "malformed"));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX);

      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a DIT
   * structure rule definition that the other doesn't have.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMissing()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but one of them has a name while the other
   * doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleOnlyOneHasName()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         null,
         "test-description",
         false,
         "test-name-form",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but they have different names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleDifferentNames()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr-1" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr-2" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but one of them has multiple names, while
   * the other only has one of those names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMissingOneOfMultipleNames()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr-1", "test-dsr-2" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr-1" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but they have different name form IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleDifferentNameFormID()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form-1",
         null,
         null);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form-2",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but one of them has a superior rule ID
   * while the other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMissingAnySuperiorRuleIDs()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         2,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         new int[] { 1 },
         null);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         2,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but one of them has multiple superior rule
   * IDs while the other only has one of them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMissingSomeSuperiorRuleIDs()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         3,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         new int[] { 1, 2 },
         null);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         3,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         new int[] { 1 },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but they have different obsolete values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleDifferentObsolete()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         true,
         "test-name-form",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but one of them has a description while the
   * other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMissingDescription()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         null,
         false,
         "test-name-form",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but they have different descriptions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleDifferentDescriptions()
         throws Exception
  {
    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description-1",
         false,
         "test-name-form",
         null,
         null);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description-2",
         false,
         "test-name-form",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but one of them has an extension and the
   * other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMissingAnyExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         ext1);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }


  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but has two extensions in one server, but
   * only one of those extensions in the other.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMissingSomeExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" },
         "X-TEST-2", new String[] { "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" });

    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         ext1);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }


  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * DIT structure rule definition, but one server has two values for a given
   * extension while the other only has one of those values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDITStructureRuleMissingSomeExtensionValues()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1", "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final DITStructureRuleDefinition def1 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         ext1);
    final DITStructureRuleDefinition def2 = new DITStructureRuleDefinition(
         1,
         new String[] { "test-dsr" },
         "test-description",
         false,
         "test-name-form",
         null,
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_DIT_STRUCTURE_RULE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * malformed name form definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMalformed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, "malformed"));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX);

      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * name form definition that the other doesn't have.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMissing()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but one of them has a name while the other doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormOnlyOneHasName()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         null,
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but they have different names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormDifferentNames()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form-1" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form-2" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but one of them has multiple names, while the other
   * only has one of those names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMissingOneOfMultipleNames()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form-1", "test-name-form-2" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form-1" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but they have different structural object classes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormDifferentStructuralClass()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class-1",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class-2",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, where both of them have required attributes, but one
   * of them has one that the other doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMissingOneOfMultipleRequiredAttributes()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but one of them has a set of optional attributes
   * while the other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMissingAnyOptionalAttributes()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         null,
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, where both of them have optional attributes, but one
   * of them has one that the other doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMissingOneOfMultipleOptionalAttributes()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but they have different obsolete values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormDifferentObsolete()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         true,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but where one of them has a description while the
   * other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMissingDescription()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         null,
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but where they have different descriptions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormDifferentDescriptions()
         throws Exception
  {
    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description-1",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description-2",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but one of them has an extension and the other does
   * not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMissingAnyExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         ext1);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but has two extensions in one server, but only one of
   * those extensions in the other.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMissingSomeExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" },
         "X-TEST-2", new String[] { "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" });

    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         ext1);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * name form definition, but one server has two values for a given extension
   * while the other only has one of those values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameFormMissingSomeExtensionValues()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1", "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final NameFormDefinition def1 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         ext1);
    final NameFormDefinition def2 = new NameFormDefinition(
         "1.2.3.4",
         new String[] { "test-name-form" },
         "test-description",
         false,
         "test-structural-class",
         new String[] { "required-attribute-1", "required-attribute-2" },
         new String[] { "optional-attribute-1", "optional-attribute-2" },
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_NAME_FORM, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * malformed matching rule use definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseMalformed()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, "malformed"));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX);

      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which one server has a
   * matching rule use definition that the other doesn't have.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseMissing()
         throws Exception
  {
    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but one of them has a name while the other
   * doesn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseOnlyOneHasName()
         throws Exception
  {
    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         null,
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but they have different names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseDifferentNames()
         throws Exception
  {
    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use-1" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use-2" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but one of them has multiple names, while the
   * other only has one of those names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseMissingOneOfMultipleNames()
         throws Exception
  {
    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-mru-1", "test-mru-2" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-mru-1" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but one of them has an applicable attribute
   * type that the other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseMissingOneOfMultipleApplicableTypes()
         throws Exception
  {
    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but they have different obsolete values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseDifferentObsolete()
         throws Exception
  {
    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         true,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but one of them has a description that the
   * other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseMissingDescription()
         throws Exception
  {
    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         null,
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but they have different descriptions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseDifferentDescription()
         throws Exception
  {
    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description-1",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description-2",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreDescriptions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but one of them has an extension and the
   * other does not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseMissingAnyExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         ext1);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but has two extensions in one server, but
   * only one of those extensions in the other.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseMissingSomeExtensions()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" },
         "X-TEST-2", new String[] { "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST-1", new String[] { "value-1" });

    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         ext1);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which both servers have a
   * matching rule use definition, but one server has two values for a given
   * extension while the other only has one of those values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchingRuleUseMissingSomeExtensionValues()
         throws Exception
  {
    final Map<String,String[]> ext1 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1", "value-2" });
    final Map<String,String[]> ext2 = StaticUtils.mapOf(
         "X-TEST", new String[] { "value-1" });

    final MatchingRuleUseDefinition def1 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         ext1);
    final MatchingRuleUseDefinition def2 = new MatchingRuleUseDefinition(
         "1.2.3.4",
         new String[] { "test-matching-rule-use" },
         "test-description",
         false,
         new String[] { "test-applicable-type-1", "test-applicable-type-2" },
         ext2);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def1.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_MATCHING_RULE_USE, def2.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--ignoreExtensions");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when attempting to run the tool with an invalid
   * schemaElementType argument value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidSchemaElementType()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema();
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema();

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.PARAM_ERROR,
           "--schemaElementType", "attribute-syntaxes",
           "--schemaElementType", "matching-rules",
           "--schemaElementType", "attribute-types",
           "--schemaElementType", "object-classes",
           "--schemaElementType", "dit-content-rules",
           "--schemaElementType", "dit-structure-rules",
           "--schemaElementType", "name-forms",
           "--schemaElementType", "matching-rule-uses",
           "--schemaElementType", "invalid");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when including or excluding schema elements based on
   * name prefixes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeOrExcludeBasedOnNamePrefix()
         throws Exception
  {
    final AttributeTypeDefinition at1 = new AttributeTypeDefinition(
         "1.2.3.4", "p1-name", null, null, null, null, null, false, null);
    final AttributeTypeDefinition at2a = new AttributeTypeDefinition(
         "1.2.3.5", "p2-name-a", null, null, null, null, null, false, null);
    final AttributeTypeDefinition at2b = new AttributeTypeDefinition(
         "1.2.3.5", "p2-name-b", null, null, null, null, null, false, null);
    final AttributeTypeDefinition at3a = new AttributeTypeDefinition(
         "1.2.3.6", "p3-name-a", null, null, null, null, null, false, null);
    final AttributeTypeDefinition at3b = new AttributeTypeDefinition(
         "1.2.3.6", "p3-name-b", null, null, null, null, null, false, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE,
              at1.toString(),
              at2a.toString(),
              at3a.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE,
              at1.toString(),
              at2b.toString(),
              at3b.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--includeElementsWithNameMatchingPrefix", "p1-");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--includeElementsWithNameMatchingPrefix", "p2-");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--includeElementsWithNameMatchingPrefix", "p1-",
           "--includeElementsWithNameMatchingPrefix", "p2-");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--excludeElementsWithNameMatchingPrefix", "p1-",
           "--excludeElementsWithNameMatchingPrefix", "p2-",
           "--excludeElementsWithNameMatchingPrefix", "p3-");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--excludeElementsWithNameMatchingPrefix", "p2-",
           "--excludeElementsWithNameMatchingPrefix", "p3-");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--excludeElementsWithNameMatchingPrefix", "p2-");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--excludeElementsWithNameMatchingPrefix", "p3-");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when including schema elements based on extension
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeBasedOnExtensionValue()
         throws Exception
  {
    final Map<String,String[]> includeWithoutConflictsMap = StaticUtils.mapOf(
         "X-INCLUDE", new String[] { "include-without-conflicts" });
    final Map<String,String[]> includeWithConflictsMap = StaticUtils.mapOf(
         "X-INCLUDE", new String[] { "include-with-conflicts" });

    final AttributeTypeDefinition at1 = new AttributeTypeDefinition(
         "1.2.3.4", "test-name-1", null, null, null, null, null, false,
         includeWithoutConflictsMap);

    final AttributeTypeDefinition at2a = new AttributeTypeDefinition(
         "1.2.3.5", "test-name-2a", null, null, null, null, null, false,
         includeWithConflictsMap);
    final AttributeTypeDefinition at2b = new AttributeTypeDefinition(
         "1.2.3.5", "test-name-2b", null, null, null, null, null, false,
         includeWithConflictsMap);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE,
              at1.toString(),
              at2a.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE,
              at1.toString(),
              at2b.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--includeElementsWithExtensionValue",
           "X-INCLUDE=include-without-conflicts");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--includeElementsWithExtensionValue",
           "X-INCLUDE=include-with-conflicts");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--includeElementsWithExtensionValue",
           "X-INCLUDE=include-with-conflicts",
           "--includeElementsWithExtensionValue",
           "X-INCLUDE=include-without-conflicts");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.PARAM_ERROR,
           "--includeElementsWithExtensionValue",
           "X-MISSING-EQUALS");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.PARAM_ERROR,
           "--includeElementsWithExtensionValue",
           "=empty-extension-name");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.PARAM_ERROR,
           "--includeElementsWithExtensionValue",
           "X-EMPTY-EXTENSION-VALUE=");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when excluding schema elements based on extension
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeBasedOnExtensionValue()
         throws Exception
  {
    final Map<String,String[]> excludeWithoutConflictsMap = StaticUtils.mapOf(
         "X-EXCLUDE", new String[] { "exclude-without-conflicts" });
    final Map<String,String[]> excludeWithConflictsMap = StaticUtils.mapOf(
         "X-EXCLUDE", new String[] { "exclude-with-conflicts" });

    final AttributeTypeDefinition at1 = new AttributeTypeDefinition(
         "1.2.3.4", "test-name-1", null, null, null, null, null, false,
         excludeWithoutConflictsMap);

    final AttributeTypeDefinition at2a = new AttributeTypeDefinition(
         "1.2.3.5", "test-name-2a", null, null, null, null, null, false,
         excludeWithConflictsMap);
    final AttributeTypeDefinition at2b = new AttributeTypeDefinition(
         "1.2.3.5", "test-name-2b", null, null, null, null, null, false,
         excludeWithConflictsMap);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE,
              at1.toString(),
              at2a.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE,
              at1.toString(),
              at2b.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE);

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.COMPARE_FALSE,
           "--excludeElementsWithExtensionValue",
           "X-EXCLUDE=exclude-without-conflicts");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--excludeElementsWithExtensionValue",
           "X-EXCLUDE=exclude-with-conflicts");

      assertToolResultCodeIs(ds1, ds2, true, ResultCode.SUCCESS,
           "--excludeElementsWithExtensionValue",
           "X-EXCLUDE=exclude-with-conflicts",
           "--excludeElementsWithExtensionValue",
           "X-EXCLUDE=exclude-without-conflicts");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when comparing two servers in which there are a
   * combination of malformed schema elements and other schema elements that
   * differ between servers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMalformedElementsAndDifferences()
         throws Exception
  {
    final AttributeTypeDefinition at1a = new AttributeTypeDefinition(
         "1.2.3.4", "test-name-1a", null, null, null, null, null, false, null);
    final AttributeTypeDefinition at1b = new AttributeTypeDefinition(
         "1.2.3.4", null, null, null, null, null, null, false, null);
    final AttributeTypeDefinition at2a = new AttributeTypeDefinition(
         "1.2.3.5", "test-name-2a", null, null, null, null, null, false, null);
    final AttributeTypeDefinition at2b = new AttributeTypeDefinition(
         "1.2.3.5", "test-name-2b", null, null, null, null, null, false, null);

    final InMemoryDirectoryServer ds1 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE,
              "malformed",
              at1a.toString(),
              at2a.toString()));
    final InMemoryDirectoryServer ds2 = getTestDSInstanceWithAdditionalSchema(
         new Attribute(Schema.ATTR_ATTRIBUTE_TYPE,
              at1b.toString(),
              at2b.toString()));

    try
    {
      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX);

      assertToolResultCodeIs(ds1, ds2, true,
           ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           "--excludeElementsWithNameMatchingPrefix", "test-name-2");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when trying to compare schema between two servers when
   * once of those servers isn't online.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareSchemaOneServerOffline()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(dsConfig);
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(dsConfig);
    try
    {
      ds1.startListening();
      ds2.startListening();

      final int ds1Port = ds1.getListenPort();
      final int ds2Port = ds2.getListenPort();

      ds2.shutDown(true);

      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final CompareLDAPSchemas tool = new CompareLDAPSchemas(out, out);
      final ResultCode resultCode = tool.runTool(
           "--firstHostname", "127.0.0.1",
           "--firstPort", String.valueOf(ds1Port),
           "--firstBindDN", "cn=Directory Manager",
           "--firstBindPassword", "password",
           "--secondHostname", "127.0.0.1",
           "--secondPort", String.valueOf(ds2Port),
           "--secondBindDN", "cn=Directory Manager",
           "--secondBindPassword", "password");

      assertEquals(resultCode, ResultCode.CONNECT_ERROR,
           StaticUtils.toUTF8String(out.toByteArray()));

      assertNotNull(tool.getToolCompletionMessage());
      assertNotNull(tool.getExampleUsages());
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when trying to compare schema between two servers when
   * an error occurs while trying to authenticate to the server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareSchemaAuthenticationError()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.addAdditionalBindCredentials("cn=Directory Manager",
         "not-the-expected-password");

    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(dsConfig);
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(dsConfig);
    try
    {
      ds1.startListening();
      ds2.startListening();

      assertToolResultCodeIs(ds1, ds2, false, ResultCode.INVALID_CREDENTIALS);
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when trying to compare schema between two servers when
   * an error occurs while attempting to retrieve the root DSE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareSchemaCannotRetrieveRootDSE()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsConfig.setAllowedOperationTypes(OperationType.BIND);


    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(dsConfig);
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(dsConfig);
    try
    {
      ds1.startListening();
      ds2.startListening();

      assertToolResultCodeIs(ds1, ds2, false, ResultCode.UNWILLING_TO_PERFORM);
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when trying to compare schema between two servers when
   * the root DSE does not include a subschemaSubentry attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareSchemaRootDSEMissingSubschemaSubentryAttribute()
         throws Exception
  {
    final InMemoryDirectoryServer testDS = getTestDS();
    final Entry rootDSEEntry = testDS.getRootDSE().duplicate();
    rootDSEEntry.removeAttribute("subschemaSubentry");


    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsConfig.setRootDSEEntry(rootDSEEntry);


    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(dsConfig);
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(dsConfig);
    try
    {
      ds1.startListening();
      ds2.startListening();

      assertToolResultCodeIs(ds1, ds2, false, ResultCode.LOCAL_ERROR);
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when trying to compare schema between two servers when
   * an error occurs while attempting to retrieve the subschema subentry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareSchemaCannotRetrieveSchemaEntry()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsConfig.setAllowedOperationTypes(OperationType.BIND);


    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(dsConfig);
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(dsConfig);
    try
    {
      ds1.startListening();
      ds2.startListening();

      assertToolResultCodeIs(ds1, ds2, false, ResultCode.UNWILLING_TO_PERFORM,
           "--firstSchemaEntryDN", "cn=schema",
           "--secondSchemaEntryDN", "cn=schema");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior when trying to compare schema between two servers when
   * the specified schema entry does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareSchemaNoSuchSchemaEntry()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(dsConfig);
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(dsConfig);
    try
    {
      ds1.startListening();
      ds2.startListening();

      assertToolResultCodeIs(ds1, ds2, false, ResultCode.NO_SUCH_OBJECT,
           "--firstSchemaEntryDN", "cn=nonexistent,dc=example,dc=com");

      assertToolResultCodeIs(ds1, ds2, false, ResultCode.NO_SUCH_OBJECT,
           "--secondSchemaEntryDN", "cn=nonexistent,dc=example,dc=com");
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  // getToolCompletionMessage
  // getExampleUses



  /**
   * Retrieves an in-memory directory server instance that contains a custom
   * entry with a representation of a default schema, which may also include
   * additional schema attributes.
   *
   * @param  extraSchemaAttributes  A set of additional attributes to include in
   *                                the schema.  It must not be {@code null},
   *                                but may be empty.
   *
   * @return  The in-memory directory server instance that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static InMemoryDirectoryServer getTestDSInstanceWithAdditionalSchema(
               final Attribute... extraSchemaAttributes)
          throws Exception
  {
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsConfig);
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final Entry customSchemaEntry = DEFAULT_CUSTOM_SCHEMA_ENTRY.duplicate();
    for (final Attribute a : extraSchemaAttributes)
    {
      customSchemaEntry.addAttribute(a);
    }
    ds.add(customSchemaEntry);

    ds.startListening();
    return ds;
  }



  /**
   * Ensures that invoking the tool against the provided two servers yields the
   * expected result.
   *
   * @param  ds1                   The first server to compare.  It must not be
   *                               {@code null}.
   * @param  ds2                   The second server to compare.  It must not be
   *                               {@code null}.
   * @param  useCustomSchemaEntry  Indicates whether to read the schema from a
   *                               custom entry rather than having the tool
   *                               discover the server's default schema.
   * @param  expectedResultCode    The result code that is expected when
   *                               invoking the tool.  It must not be
   *                               {@code null}.
   * @param  extraArgs             The extra arguments to provide when invoking
   *                               the {@code compare-ldap-schemas} tool
   *                               (excluding those used to connect,
   *                               authenticate, or specify the schema entry
   *                               DN).  It must not be {@code null}, but may be
   *                               empty.
   */
  private void assertToolResultCodeIs(final InMemoryDirectoryServer ds1,
                                      final InMemoryDirectoryServer ds2,
                                      final boolean useCustomSchemaEntry,
                                      final ResultCode expectedResultCode,
                                      final String... extraArgs)
  {
    final List<String> extraArgList = new ArrayList<>();
    if (useCustomSchemaEntry)
    {
      extraArgList.add("--firstSchemaEntryDN");
      extraArgList.add(DEFAULT_CUSTOM_SCHEMA_ENTRY.getDN());
      extraArgList.add("--secondSchemaEntryDN");
      extraArgList.add(DEFAULT_CUSTOM_SCHEMA_ENTRY.getDN());
    }

    if (extraArgs.length > 0)
    {
      extraArgList.addAll(Arrays.asList(extraArgs));
    }

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode rc1 = runTool(ds1, ds2, out, extraArgList);
    if (rc1 != expectedResultCode)
    {
      fail("Got result code " + rc1 + " instead of expected result code " +
           expectedResultCode + " when invoking the tool with extra args " +
           extraArgList + " against the servers in the provided order.  The " +
           "tool output is:" + StaticUtils.EOL + StaticUtils.EOL +
           StaticUtils.toUTF8String(out.toByteArray()));
    }

    out.reset();
    final ResultCode rc2 = runTool(ds2, ds1, out, extraArgList);
    if (rc2 != expectedResultCode)
    {
      fail("Got result code " + rc2 + " instead of expected result code " +
           expectedResultCode + " when invoking the tool with extra args " +
           extraArgList + " against the servers in the reverse order.  The " +
           "tool output is:" + StaticUtils.EOL + StaticUtils.EOL +
           StaticUtils.toUTF8String(out.toByteArray()));
    }
  }



  /**
   * Runs the {@code compare-ldap-schemas} tool against the provided servers
   * with the given arguments.
   *
   * @param  ds1   The first server instance to use.  It must not be
   *               {@code null}.
   * @param  ds2   The second server instance to use.  It must not be
   *               {@code null}.
   * @param  out   The output stream to use for both standard output and
   *               standard error.
   * @param  extraArgs  The extra arguments to provide when invoking the
   *                    {@code compare-ldap-schemas} tool (excluding those used
   *                    to connect and authenticate).  It must not be
   *                    {@code null}, but may be empty.
   *
   * @return  The result code obtained when running the tool.
   */
  private static ResultCode runTool(final InMemoryDirectoryServer ds1,
                                    final InMemoryDirectoryServer ds2,
                                    final OutputStream out,
                                    final List<String> extraArgs)
  {
    final List<String> argList = new ArrayList<>(Arrays.asList(
         "--firstHostname", "127.0.0.1",
         "--firstPort", String.valueOf(ds1.getListenPort()),
         "--firstBindDN", "cn=Directory Manager",
         "--firstBindPassword", "password",
         "--secondHostname", "127.0.0.1",
         "--secondPort", String.valueOf(ds2.getListenPort()),
         "--secondBindDN", "cn=Directory Manager",
         "--secondBindPassword", "password"));
    argList.addAll(extraArgs);

    final String[] argArray = StaticUtils.toArray(argList, String.class);

    return CompareLDAPSchemas.main(out, out, argArray);
  }
}
