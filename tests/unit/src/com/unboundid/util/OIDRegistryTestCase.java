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
package com.unboundid.util;



import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;



/**
 * This class provides a set of test cases for the {@code OIdRegistry} class.
 */
public final class OIDRegistryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when using the default registry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultRegistry()
         throws Exception
  {
    final OIDRegistry registry = OIDRegistry.getDefault();
    assertNotNull(registry);

    assertNotNull(registry.getItems());
    assertFalse(registry.getItems().isEmpty());

    assertNotNull(registry.get("2.5.4.3"));
    assertEquals(registry.get("2.5.4.3").getOID(), "2.5.4.3");
    assertEquals(registry.get("2.5.4.3").getName(), "cn");
    assertEquals(registry.get("2.5.4.3").getName(), "cn");
    assertEquals(registry.get("2.5.4.3").getType(), "Attribute Type");
    assertEquals(registry.get("2.5.4.3").getOrigin(), "RFC 4519");

    assertNull(registry.get("1.2.3.4"));
  }



  /**
   * Tests the behavior when attempting to augment the default registry with
   * an additional schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRegistryWithSchema()
         throws Exception
  {
    final File schemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.2.3.4.1 DESC 'test-syntax' " +
              "X-ORIGIN 'test-origin' )",
         "matchingRules: ( 1.2.3.4.2 NAME 'testMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.4.3 NAME 'test-attr' " +
              "EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 " +
              "X-ORIGIN 'another-origin' )",
         "objectClasses: ( 1.2.3.4.4 NAME 'test-oc' SUP top STRUCTURAL " +
              "MUST cn )",
         "nameForms: ( 1.2.3.4.5 NAME 'test-nf' OC person MUST uid )");

    final Schema schema = Schema.getSchema(schemaFile);
    assertNotNull(schema);


    OIDRegistry registry = OIDRegistry.getDefault();
    assertNotNull(registry);

    assertNotNull(registry.getItems());
    assertFalse(registry.getItems().isEmpty());

    assertNull(registry.get("1.2.3.4.1"));
    assertNull(registry.get("1.2.3.4.2"));
    assertNull(registry.get("1.2.3.4.3"));
    assertNull(registry.get("1.2.3.4.4"));
    assertNull(registry.get("1.2.3.4.5"));

    registry = registry.withSchema(schema);
    assertNotNull(registry);

    assertNotNull(registry.get("1.2.3.4.1"));
    assertEquals(registry.get("1.2.3.4.1").getOID(), "1.2.3.4.1");
    assertEquals(registry.get("1.2.3.4.1").getName(), "test-syntax");
    assertEquals(registry.get("1.2.3.4.1").getType(), "Attribute Syntax");
    assertEquals(registry.get("1.2.3.4.1").getOrigin(), "test-origin");
    assertNull(registry.get("1.2.3.4.1").getURL());

    assertNotNull(registry.get("1.2.3.4.2"));
    assertEquals(registry.get("1.2.3.4.2").getOID(), "1.2.3.4.2");
    assertEquals(registry.get("1.2.3.4.2").getName(), "testMatch");
    assertEquals(registry.get("1.2.3.4.2").getType(), "Matching Rule");
    assertNull(registry.get("1.2.3.4.2").getOrigin());
    assertNull(registry.get("1.2.3.4.2").getURL());

    assertNotNull(registry.get("1.2.3.4.3"));
    assertEquals(registry.get("1.2.3.4.3").getOID(), "1.2.3.4.3");
    assertEquals(registry.get("1.2.3.4.3").getName(), "test-attr");
    assertEquals(registry.get("1.2.3.4.3").getType(), "Attribute Type");
    assertEquals(registry.get("1.2.3.4.3").getOrigin(), "another-origin");
    assertNull(registry.get("1.2.3.4.3").getURL());

    assertNotNull(registry.get("1.2.3.4.4"));
    assertEquals(registry.get("1.2.3.4.4").getOID(), "1.2.3.4.4");
    assertEquals(registry.get("1.2.3.4.4").getName(), "test-oc");
    assertEquals(registry.get("1.2.3.4.4").getType(), "Object Class");
    assertNull(registry.get("1.2.3.4.4").getOrigin(), "another-origin");
    assertNull(registry.get("1.2.3.4.4").getURL());

    assertNotNull(registry.get("1.2.3.4.5"));
    assertEquals(registry.get("1.2.3.4.5").getOID(), "1.2.3.4.5");
    assertEquals(registry.get("1.2.3.4.5").getName(), "test-nf");
    assertEquals(registry.get("1.2.3.4.5").getType(), "Name Form");
    assertNull(registry.get("1.2.3.4.5").getOrigin());
    assertNull(registry.get("1.2.3.4.5").getURL());

    registry = registry.withSchema(schema);
    assertNotNull(registry);

    assertNotNull(registry.get("1.2.3.4.1"));
    assertEquals(registry.get("1.2.3.4.1").getOID(), "1.2.3.4.1");
    assertEquals(registry.get("1.2.3.4.1").getName(), "test-syntax");
    assertEquals(registry.get("1.2.3.4.1").getType(), "Attribute Syntax");
    assertEquals(registry.get("1.2.3.4.1").getOrigin(), "test-origin");
    assertNull(registry.get("1.2.3.4.1").getURL());

    assertNotNull(registry.get("1.2.3.4.2"));
    assertEquals(registry.get("1.2.3.4.2").getOID(), "1.2.3.4.2");
    assertEquals(registry.get("1.2.3.4.2").getName(), "testMatch");
    assertEquals(registry.get("1.2.3.4.2").getType(), "Matching Rule");
    assertNull(registry.get("1.2.3.4.2").getOrigin());
    assertNull(registry.get("1.2.3.4.2").getURL());

    assertNotNull(registry.get("1.2.3.4.3"));
    assertEquals(registry.get("1.2.3.4.3").getOID(), "1.2.3.4.3");
    assertEquals(registry.get("1.2.3.4.3").getName(), "test-attr");
    assertEquals(registry.get("1.2.3.4.3").getType(), "Attribute Type");
    assertEquals(registry.get("1.2.3.4.3").getOrigin(), "another-origin");
    assertNull(registry.get("1.2.3.4.3").getURL());

    assertNotNull(registry.get("1.2.3.4.4"));
    assertEquals(registry.get("1.2.3.4.4").getOID(), "1.2.3.4.4");
    assertEquals(registry.get("1.2.3.4.4").getName(), "test-oc");
    assertEquals(registry.get("1.2.3.4.4").getType(), "Object Class");
    assertNull(registry.get("1.2.3.4.4").getOrigin(), "another-origin");
    assertNull(registry.get("1.2.3.4.4").getURL());

    assertNotNull(registry.get("1.2.3.4.5"));
    assertEquals(registry.get("1.2.3.4.5").getOID(), "1.2.3.4.5");
    assertEquals(registry.get("1.2.3.4.5").getName(), "test-nf");
    assertEquals(registry.get("1.2.3.4.5").getType(), "Name Form");
    assertNull(registry.get("1.2.3.4.5").getOrigin());
    assertNull(registry.get("1.2.3.4.5").getURL());
  }



  /**
   * Examines the contents of the oid-registry.json file and ensures that all
   * of the definitions it contains are found in the default OID registry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOIDRegistryJSONFile()
         throws Exception
  {
    final OIDRegistry oidRegistry = OIDRegistry.getDefault();
    assertNotNull(oidRegistry);

    final File baseDir = new File(System.getProperty("basedir"));
    final File resourceDir = new File(baseDir, "resource");
    final File registryFile = new File(resourceDir, "oid-registry.json");

    final List<JSONObject> missingObjects = new ArrayList<>();
    try (FileInputStream inputStream = new FileInputStream(registryFile);
         JSONObjectReader reader = new JSONObjectReader(inputStream))
    {
      while (true)
      {
        final JSONObject o = reader.readObject();
        if (o == null)
        {
          break;
        }

        final String oid = o.getFieldAsString("oid");
        assertNotNull(oid, "JSON object " + o + " does not contain an OID");

        if (oidRegistry.get(oid) == null)
        {
          missingObjects.add(o);
        }
      }
    }

    if (! missingObjects.isEmpty())
    {
      final StringBuilder errorMessage = new StringBuilder();
      errorMessage.append("The OID registry was missing information about " +
           "one or more JSON objects:");
      errorMessage.append(StaticUtils.EOL);
      for (final JSONObject o : missingObjects)
      {
        errorMessage.append(StaticUtils.EOL);
        errorMessage.append(o.toSingleLineString());
        errorMessage.append(StaticUtils.EOL);
        try
        {
          new OIDRegistryItem(o);
        }
        catch (final Exception e)
        {
          errorMessage.append(e.getMessage());
          errorMessage.append(StaticUtils.EOL);
        }
      }

      fail(errorMessage.toString());
    }
  }



  /**
   * Generates a new version of the OID registry included in the LDAP SDK
   * documentation and ensures that it matches the current version.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPSDKDocumentationIsUpToDate()
         throws Exception
  {
    final File baseDir = new File(System.getProperty("basedir"));
    final File buildDir = new File(baseDir, "build");
    final File testDir = new File(buildDir, "test");
    assertTrue(testDir.exists());
    assertTrue(testDir.isDirectory());

    final File generatedHTMLFile =
         new File(testDir, "ldap-sdk-oid-reference.html");

    try (PrintWriter w = new PrintWriter(generatedHTMLFile))
    {
      final String baseIndent = "              ";

      w.println(baseIndent + "<div align=\"right\">");
      w.println("${TARGET=\"offline\"}                " +
           "<a href=\"${LDAP_SDK_HOME_URL}\" style=\"font-size: 85%\">LDAP " +
           "SDK Home Page</a>");
      w.println("${TARGET=\"offline\"}                <br>");
      w.println(baseIndent + "  <a href=\"${BASE}index.${EXTENSION}\" " +
           "style=\"font-size: 85%\">Product Information</a>");
      w.println(baseIndent + "</div>");
      w.println();
      w.println(baseIndent + "<h2>LDAP OID Reference</h2>");
      w.println();
      w.println(baseIndent + "<p>");
      w.println(baseIndent + "  Object identifiers are used throughout LDAP, " +
           "but they\u2019re particularly common in schema elements, " +
           "controls, and extended operations. This document provides a " +
           "table of some of the most common OIDs used in LDAP along with a " +
           "brief explanation of their purpose and (when applicable) a " +
           "reference to the appropriate specification.");
      w.println(baseIndent + "</p>");
      w.println();
      w.println(baseIndent + "<table border=\"1\" cellpadding=\"5\" " +
           "cellspacing=\"0\">");
      w.println(baseIndent + "  <tr>");
      w.println(baseIndent + "    <th align=\"left\">OID</th>");
      w.println(baseIndent + "    <th align=\"left\">Purpose</th>");
      w.println(baseIndent + "    <th align=\"left\">Source</th>");
      w.println(baseIndent + "  </tr>");

      final OIDRegistry registry = OIDRegistry.getDefault();
      assertNotNull(registry);

      for (final OIDRegistryItem item : registry.getItems().values())
      {
        w.println(baseIndent + "  <tr>");
        w.println(baseIndent + "    <td>" + item.getOID() + "</td>");

        final String type = item.getType();
        assertNotNull(type);
        if (type.equals("Attribute Type") || type.equals("Object Class") ||
            type.equals("Matching Rule") || type.equals("Administrative Alert"))
        {
          w.println(baseIndent + "    <td><tt>" + item.getName() + "</tt> " +
               type + "</td>");
        }
        else
        {
          w.println(baseIndent + "    <td>" + item.getName() + ' ' + type +
               "</td>");
        }

        final String origin = item.getOrigin();
        if (origin == null)
        {
          w.println(baseIndent + "    <td></td>");
        }
        else
        {
          final String url = item.getURL();
          if (url == null)
          {
            w.println(baseIndent + "    <td>" + origin + "</td>");
          }
          else
          {
            w.println(baseIndent + "    <td><a href=\"" + url +
                 "\" target=\"_blank\">" + origin + "</a></td>");
          }
        }

        w.println(baseIndent + "  </tr>");
      }

      w.println(baseIndent + "</table>");
    }


    // Compute SHA-256 digests of the newly generated OID reference with the
    // existing version in the documentation.  If they are different, then fail
    // the test.
    final MessageDigest sha256 = CryptoHelper.getMessageDigest("SHA-256");
    final byte[] generatedFileBytes =
         StaticUtils.readFileBytes(generatedHTMLFile);
    final byte[] generatedFileDigest = sha256.digest(generatedFileBytes);

    final File docsDir = new File(baseDir, "docs");
    final File existingHTMLFile = new File(docsDir, "ldap-oid-reference.html");
    final byte[] existingFileBytes =
         StaticUtils.readFileBytes(existingHTMLFile);
    final byte[] existingFileDigest = sha256.digest(existingFileBytes);

    assertEquals(generatedFileBytes, existingFileBytes,
         "It appears that the OID registry has been updated, but the version " +
              "in the LDAP SDK documentation has not been updated.  Replace '" +
              existingHTMLFile.getAbsolutePath() + "' with '" +
              generatedHTMLFile.getAbsolutePath() + "'.");
  }



  /**
   * Generates a new version of the OID registry in a form that may be published
   * on LDAP.com.  This test does not attempt to ensure that the version on
   * LDAP.com is update to date.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateLDAPDotComOIDReference()
         throws Exception
  {
    final File baseDir = new File(System.getProperty("basedir"));
    final File buildDir = new File(baseDir, "build");
    final File testDir = new File(buildDir, "test");
    assertTrue(testDir.exists());
    assertTrue(testDir.isDirectory());

    final File generatedHTMLFile =
         new File(testDir, "ldap.com-oid-reference.html");

    try (PrintWriter w = new PrintWriter(generatedHTMLFile))
    {
      w.println("<p>");
      w.println("  Object identifiers are used throughout LDAP, but " +
           "they\u2019re particularly common in schema elements, controls, " +
           "and extended operations. This document provides a table of some " +
           "of the most common OIDs used in LDAP along with a brief " +
           "explanation of their purpose and (when applicable) a reference " +
           "to the appropriate specification.");
      w.println("</p>");
      w.println();
      w.println("<p>");
      w.println("  For more information, see the explanation of <a " +
           "href=\"https://ldap.com/object-identifiers/\" " +
           "target=\"_blank\">object identifiers</a> in the <a " +
           "href=\"https://ldap.com/understanding-ldap-schema/\" " +
           "target=\"_blank\">Understanding LDAP Schema</a> section of this " +
           "website. A much more thorough, walkable OID reference database " +
           "(including non-LDAP-related OIDs) may be found at <a " +
           "href=\"https://oidref.com/\" " +
           "target=\"_blank\">https://oidref.com/</a>. To obtain your own " +
           "OID base from the <a href=\"https://www.iana.org/assignments/" +
           "enterprise-numbers/enterprise-numbers\" target=\"_blank\">IANA " +
           "private enterprise number</a> registry, <a " +
           "href=\"https://pen.iana.org/pen/PenApplication.page\" " +
           "target=\"_blank\">use this application form</a>.");
      w.println("</p>");
      w.println();
      w.println("<table border=\"1\" cellspacing=\"0\" cellpadding=\"5\">");
      w.println("  <tbody>");
      w.println("    <tr>");
      w.println("      <th align=\"left\">OID</th>");
      w.println("      <th align=\"left\">Purpose</th>");
      w.println("      <th align=\"left\">Source</th>");
      w.println("    </tr>");

      final OIDRegistry registry = OIDRegistry.getDefault();
      assertNotNull(registry);

      for (final OIDRegistryItem item : registry.getItems().values())
      {
        w.println("    <tr>");
        w.println("      <td>" + item.getOID() + "</td>");

        final String type = item.getType();
        assertNotNull(type);
        if (type.equals("Attribute Type") || type.equals("Object Class") ||
            type.equals("Matching Rule") || type.equals("Administrative Alert"))
        {
            w.println("      <td><tt>" + item.getName() + "</tt> " + type +
                 "</td>");
        }
        else
        {
            w.println("      <td>" + item.getName() + ' ' + type + "</td>");
        }

        final String origin = item.getOrigin();
        if (origin == null)
        {
          w.println("      <td></td>");
        }
        else
        {
          final String url = item.getURL();
          if (url == null)
          {
            w.println("      <td>" + origin + "</td>");
          }
          else
          {
            w.println("      <td><a href=\"" + url +
                 "\" target=\"_blank\">" + origin + "</a></td>");
          }
        }

        w.println("    </tr>");
      }

      w.println("  </tbody>");
      w.println("</table>");
    }
  }



  /**
   * Identifies any String constants in LDAP SDK source files whose name
   * indicates that the value is expected to be an OID.
   *
   * @param  c  The source class to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sdkClasses")
  public void testSourceOIDsAreInTheRegistry(final Class<?> c)
         throws Exception
  {
    for (final Field f : c.getDeclaredFields())
    {
      final String name = f.getName();
      if (name.equals("OID") || name.contains("_OID") || name.contains("OID_"))
      {
        if (f.getType().equals(String.class) &&
             ((f.getModifiers() & Modifier.STATIC) != 0x00) &&
             ((f.getModifiers() & Modifier.FINAL) != 0x00))
        {
          f.setAccessible(true);

          final String oid = (String) f.get(null);
          if (OID.isValidNumericOID(oid))
          {
            assertNotNull(OIDRegistry.getDefault().get(oid),
                 "OID '" + oid + "' defined in constant " +
                      c.getName() + '.' + f.getName() + " is not defined in " +
                      "the OID registry.");
          }
        }
      }
    }
  }



  /**
   * Retrieves the fully-qualified names of all classes included in the SDK.
   *
   * @return  The fully-qualified names of all classes included in the SDK.
   *
   * @throws  Exception  If a problem occurs during processing.
   */
  @DataProvider(name="sdkClasses")
  public Object[][] getSDKClasses()
         throws Exception
  {
    final File baseDir = new File(System.getProperty("basedir"));
    final File buildDir = new File(baseDir, "build");
    final File classesDir = new File(buildDir, "classes");

    final ArrayList<Class<?>> classList = new ArrayList<Class<?>>();
    findClasses("", classesDir,  classList);

    Object[][] classes = new Object[classList.size()][1];
    for (int i=0; i < classes.length; i++)
    {
      classes[i][0] = classList.get(i);
    }

    return classes;
  }



  /**
   * Recursively identifies all classes in the provided directory.
   *
   * @param  p  The package name associated with the provided directory.
   * @param  d  The directory to be processed.
   * @param  l  The to which the classes should be added.
   *
   * @throws  Exception  If a problem occurs during processing.
   */
  private static void findClasses(final String p, final File d,
                                  final ArrayList<Class<?>> l)
          throws Exception
  {
    for (File f : d. listFiles())
    {
      if (f.isDirectory())
      {
        if (p.length() == 0)
        {
          findClasses(f.getName(), f, l);
        }
        else
        {
          findClasses(p + '.' + f.getName(), f, l);
        }
      }
      else if (f.getName().endsWith(".class") &&
               (! f.getName().contains("$")))
      {
        int dotPos = f.getName().lastIndexOf('.');
        String baseName = f.getName().substring(0, dotPos);
        String className = p + '.' + baseName;
        l.add(Class.forName(className));
      }
    }
  }
}
