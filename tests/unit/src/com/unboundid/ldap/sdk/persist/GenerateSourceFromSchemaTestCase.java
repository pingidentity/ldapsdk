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

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a number of test cases for the
 * {@code GenerateSourceFromSchema} tool.
 */
public final class GenerateSourceFromSchemaTestCase
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
    final GenerateSourceFromSchema tool =
         new GenerateSourceFromSchema(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Tests the ability to generate a source code file using the minimum
   * required set of arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalArguments()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--rdnAttribute", "uid"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, System.out,
         System.err);
    assertNotNull(rc);
    assertEquals(rc, ResultCode.SUCCESS);

    final File sourceFile = new File("InetOrgPerson.java");
    assertTrue(sourceFile.exists());
    sourceFile.delete();
  }



  /**
   * Tests the ability to generate a source code file using a complete set of
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllArguments()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final File outputFile = createTempFile();
    final File outputDir  = outputFile.getParentFile();
    outputFile.delete();

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--outputDirectory", outputFile.getParentFile().getAbsolutePath(),
      "--structuralClass", "inetOrgPerson",
      "--auxiliaryClass", "uidObject",
      "--rdnAttribute", "uid",
      "--operationalAttribute", "entryUUID",
      "--operationalAttribute", "creatorsName",
      "--operationalAttribute", "createTimestamp",
      "--operationalAttribute", "modifiersName",
      "--operationalAttribute", "modifyTimestamp",
      "--lazyAttribute", "description",
      "--lazyAttribute", "createTimestamp",
      "--lazyAttribute", "modifyTimestamp",
      "--defaultParentDN", "dc=example,dc=com",
      "--packageName", "com.example.test",
      "--className", "User",
      "--terse"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, System.out,
         System.err);
    assertNotNull(rc);
    assertEquals(rc, ResultCode.SUCCESS);

    final File sourceFile = new File(outputDir, "User.java");
    assertTrue(sourceFile.exists());
  }



  /**
   * Tests the ability to generate a source code file using a complete set of
   * arguments with multiple structural classes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleAuxiliaryClasses()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final File outputFile = createTempFile();
    final File outputDir  = outputFile.getParentFile();
    outputFile.delete();

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--outputDirectory", outputFile.getParentFile().getAbsolutePath(),
      "--structuralClass", "inetOrgPerson",
      "--auxiliaryClass", "uidObject",
      "--auxiliaryClass", "strongAuthenticationUser",
      "--auxiliaryClass", "extensibleObject",
      "--rdnAttribute", "uid",
      "--defaultParentDN", "dc=example,dc=com",
      "--packageName", "com.example.test",
      "--className", "User"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, System.out,
         System.err);
    assertNotNull(rc);
    assertEquals(rc, ResultCode.SUCCESS);

    final File sourceFile = new File(outputDir, "User.java");
    assertTrue(sourceFile.exists());
  }



  /**
   * Tests the ability to generate a source code file using a complete set of
   * arguments with multiple structural classes and the "--terse" argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleAuxiliaryClassesWithTerse()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final File outputFile = createTempFile();
    final File outputDir  = outputFile.getParentFile();
    outputFile.delete();

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--outputDirectory", outputFile.getParentFile().getAbsolutePath(),
      "--structuralClass", "inetOrgPerson",
      "--auxiliaryClass", "uidObject",
      "--auxiliaryClass", "strongAuthenticationUser",
      "--auxiliaryClass", "extensibleObject",
      "--rdnAttribute", "uid",
      "--defaultParentDN", "dc=example,dc=com",
      "--packageName", "com.example.test",
      "--className", "User",
      "--terse"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, System.out,
         System.err);
    assertNotNull(rc);
    assertEquals(rc, ResultCode.SUCCESS);

    final File sourceFile = new File(outputDir, "User.java");
    assertTrue(sourceFile.exists());
  }



  /**
   * Tests the behavior when attempting to authenticate with an invalid
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrongPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", "wrong-" + getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--rdnAttribute", "uid"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to target a structural object class that
   * does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingStructuralClass()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "theNameOfAClassNotDefinedInTheSchema",
      "--rdnAttribute", "uid"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to target an auxiliary object class that
   * does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingAuxiliaryClass()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--auxiliaryClass", "theNameOfAClassNotDefinedInTheSchema",
      "--rdnAttribute", "uid"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to target a structural object class that
   * exists but is not structural.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStructuralClassNotStructural()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "uidObject",
      "--rdnAttribute", "uid"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to target an auxiliary object class that
   * exists but is not structural.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuxiliaryClassNotAuxiliary()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--auxiliaryClass", "groupOfNames",
      "--rdnAttribute", "uid"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to use an RDN attribute that is not
   * defined in the schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndefinedRDNAttribute()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--rdnAttribute", "theNameOfAnAttributeNotDefinedInTheSchema",
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to use an RDN attribute that is not
   * allowed by any of the object classes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisallowedRDNAttribute()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--rdnAttribute", "member"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to use an operational attribute that is
   * not defined in the schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndefinedOperationalAttribute()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--rdnAttribute", "uid",
      "--operationalAttribute", "theNameOfAnAttributeNotDefinedInTheSchema"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to use an operational attribute that is
   * not declared operational in the server schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationalAttributeNotOperational()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--rdnAttribute", "uid",
      "--operationalAttribute", "cn"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to use a lazily-loaded attribute that is
   * not defined in the schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndefinedLazyAttribute()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--rdnAttribute", "uid",
      "--lazyAttribute", "theNameOfAnAttributeNotDefinedInTheSchema"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to use a lazily-loaded attribute that is
   * not allowed by any of the object classes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisallowedLazyAttribute()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--rdnAttribute", "uid",
      "--lazyAttribute", "member"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when attempting to use an invalid Java class name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidClassName()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--structuralClass", "inetOrgPerson",
      "--rdnAttribute", "uid",
      "--className", "Inet-Org-Person"
    };

    final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
    assertNotNull(rc);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when used with every structural class in the server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessAllStructuralClasses()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final File outputDir = createTempFile();
    outputDir.delete();
    outputDir.mkdir();

    final LDAPConnection conn = getAdminConnection();
    final Schema schema = conn.getSchema();
    conn.close();

    assertNotNull(schema);

    for (final ObjectClassDefinition d : schema.getStructuralObjectClasses())
    {
      final String rdnAttr;
      if (d.getRequiredAttributes().length > 0)
      {
        rdnAttr = d.getRequiredAttributes()[0];
      }
      else if (d.getOptionalAttributes().length > 0)
      {
        rdnAttr = d.getOptionalAttributes()[0];
      }
      else
      {
        continue;
      }

      final String[] args =
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword(),
        "--outputDirectory", outputDir.getAbsolutePath(),
        "--structuralClass", d.getNameOrOID(),
        "--rdnAttribute", rdnAttr
      };

      final ResultCode rc = GenerateSourceFromSchema.main(args, null, null);
      assertNotNull(rc);
      assertEquals(rc, ResultCode.SUCCESS);
    }
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
    final GenerateSourceFromSchema tool = new GenerateSourceFromSchema(null,
         null);

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }
}
