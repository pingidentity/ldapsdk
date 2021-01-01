/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.persist;



import java.io.File;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFReader;



/**
 * This class provides a number of test cases for the
 * {@code GenerateSchemaFromSource} tool.
 */
public final class GenerateSchemaFromSourceTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides general test coverage for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void provideGeneralTestCoverage()
         throws Exception
  {
    final GenerateSchemaFromSource tool =
         new GenerateSchemaFromSource(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Test the behavior when working with an object that should correspond to the
   * LDAP organizationalUnit object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOrganizationalUnit()
         throws Exception
  {
    final File outputFile = createTempFile();

    final String[] args =
    {
      "--javaClass", TestOrganizationalUnit.class.getName(),
      "--outputFile", outputFile.getAbsolutePath()
    };

    final ResultCode rc = GenerateSchemaFromSource.main(args, System.out,
         System.err);
    assertEquals(rc, ResultCode.SUCCESS);

    final LDIFReader reader = new LDIFReader(outputFile);

    final Entry e = reader.readEntry();
    assertNotNull(e);

    assertNull(reader.readEntry());
    reader.close();

    boolean foundDescription = false;
    boolean foundOU = false;
    assertTrue(e.hasAttribute("attributeTypes"));
    for (final String value : e.getAttribute("attributeTypes").getValues())
    {
      final AttributeTypeDefinition d = new AttributeTypeDefinition(value);
      if (d.hasNameOrOID("description"))
      {
        foundDescription = true;
      }
      else if (d.hasNameOrOID("ou"))
      {
        foundOU = true;
      }
    }

    assertTrue(foundDescription);
    assertTrue(foundOU);

    assertTrue(e.hasAttribute("objectClasses"));
    for (final String value : e.getAttribute("objectClasses").getValues())
    {
      final ObjectClassDefinition d = new ObjectClassDefinition(value);
      assertTrue(d.hasNameOrOID("organizationalUnit"));
    }
  }



  /**
   * Test the behavior when working with an object that should correspond to the
   * LDAP organizationalUnit object class, when the output should be represented
   * as a set of modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOrganizationalUnitAsModifications()
         throws Exception
  {
    final File outputFile = createTempFile();

    final String[] args =
    {
      "--javaClass", TestOrganizationalUnit.class.getName(),
      "--outputFile", outputFile.getAbsolutePath(),
      "--modifyFormat"
    };

    final ResultCode rc = GenerateSchemaFromSource.main(args, System.out,
         System.err);
    assertEquals(rc, ResultCode.SUCCESS);

    final LDIFReader reader = new LDIFReader(outputFile);

    final LDIFModifyChangeRecord r =
         (LDIFModifyChangeRecord) reader.readLDIFRecord();
    assertNotNull(r);

    assertNull(reader.readLDIFRecord());
    reader.close();

    boolean foundDescriptionAttr = false;
    boolean foundOUAttr = false;
    boolean foundOrgUnitOC = false;
    for (final Modification m : r.getModifications())
    {
      if (m.getAttributeName().equalsIgnoreCase("attributeTypes"))
      {
        for (final String v : m.getValues())
        {
          final AttributeTypeDefinition d = new AttributeTypeDefinition(v);
          if (d.hasNameOrOID("description"))
          {
            foundDescriptionAttr = true;
          }
          else if (d.hasNameOrOID("ou"))
          {
            foundOUAttr = true;
          }
        }
      }
      else if (m.getAttributeName().equalsIgnoreCase("objectClasses"))
      {
        for (final String v : m.getValues())
        {
          final ObjectClassDefinition d = new ObjectClassDefinition(v);
          if (d.hasNameOrOID("organizationalUnit"))
          {
            foundOrgUnitOC = true;
          }
        }
      }
    }

    assertTrue(foundDescriptionAttr);
    assertTrue(foundOUAttr);
    assertTrue(foundOrgUnitOC);
  }



  /**
   * Test the ability to generate schema for different types of valid objects.
   *
   * @param  className  The name of the class
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validClasses")
  public void testValidObject(final String className)
         throws Exception
  {
    final File outputFile = createTempFile();

    final String[] args =
    {
      "--javaClass", className,
      "--outputFile", outputFile.getAbsolutePath()
    };

    final ResultCode rc = GenerateSchemaFromSource.main(args, System.out,
         System.err);
    assertEquals(rc, ResultCode.SUCCESS);

    final LDIFReader reader = new LDIFReader(outputFile);

    final Entry e = reader.readEntry();
    assertNotNull(e);

    assertNull(reader.readEntry());
    reader.close();

    assertTrue(e.hasAttribute("attributeTypes"));
    for (final String value : e.getAttribute("attributeTypes").getValues())
    {
      new AttributeTypeDefinition(value);
    }

    assertTrue(e.hasAttribute("objectClasses"));
    for (final String value : e.getAttribute("objectClasses").getValues())
    {
      new ObjectClassDefinition(value);
    }
  }



  /**
   * Provides the names of valid classes that can be used for testing.
   *
   * @return  The names of valid classes that can be used for testing.
   */
  @DataProvider(name="validClasses")
  public Object[][] getValidClasses()
  {
    return new Object[][]
    {
      new Object[] { TestAnnotationsObject.class.getName() },
      new Object[] { TestBasicObject.class.getName() },
      new Object[] { TestMinimalObjectMultipleRDNs.class.getName() },
      new Object[] { TestMultipleRDNFields.class.getName() },
    };
  }



  /**
   * Test the behavior when used with a class that doesn't exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoSuchClass()
         throws Exception
  {
    final File outputFile = createTempFile();

    final String[] args =
    {
      "--javaClass", "com.unboundid.ldap.sdk.persist.NoSuchClass",
      "--outputFile", outputFile.getAbsolutePath()
    };

    final ResultCode rc = GenerateSchemaFromSource.main(args, null, null);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Test the behavior when used with a class that doesn't have the
   * {@code @LDAPObject} annotation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClassNotAnnotated()
         throws Exception
  {
    final File outputFile = createTempFile();

    final String[] args =
    {
      "--javaClass", "com.unboundid.ldap.sdk.persist.TestClassNotAnnotated",
      "--outputFile", outputFile.getAbsolutePath()
    };

    final ResultCode rc = GenerateSchemaFromSource.main(args, null, null);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Test the behavior when used with a class that is annotated but not valid
   * for use with the persistence framework.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidAuxiliaryClass()
         throws Exception
  {
    final File outputFile = createTempFile();

    final String[] args =
    {
      "--javaClass", "com.unboundid.ldap.sdk.persist.TestInvalidAuxiliaryClass",
      "--outputFile", outputFile.getAbsolutePath()
    };

    final ResultCode rc = GenerateSchemaFromSource.main(args, null, null);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Provides test coverage for the {@code getExampleUsages} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetExampleUsages()
         throws Exception
  {
    final GenerateSchemaFromSource tool = new GenerateSchemaFromSource(null,
         null);

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }
}
