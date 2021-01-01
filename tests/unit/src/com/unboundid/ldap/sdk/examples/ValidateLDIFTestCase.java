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
package com.unboundid.ldap.sdk.examples;



import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.zip.GZIPOutputStream;

import com.unboundid.ldap.sdk.schema.EntryValidator;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.PasswordReader;



/**
 * This class provides a set of test cases for the ValidateLDIF class.
 */
public class ValidateLDIFTestCase
       extends LDAPSDKTestCase
{
  // The path to a compressed version of a valid LDIF file.
  private File compressedLDIF;

  // The path to a compressed and encrypted version of a valid LDIF file.
  private File encryptedLDIF;

  // The path to an invalid LDIF file.
  private File invalidLDIF;

  // The path to a valid LDIF file.
  private File validLDIF;

  // The path to a directory containing a file with schema definitions.
  private File schemaDir;



  /**
   * Performs the necessary setup before running these test cases.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    validLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    invalidLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: organization",
         "objectClass: undefined",
         "dc: example",
         "undefined: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "ou: People",
         "",
         "dn: ou=malformed,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: malformed",
         "noColon",
         "",
         "dn: cn=invalid,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "cn: invalid",
         "uid: test.user",
         "givenName: Test",
         "userPassword: password",
         "dc: not allowed",
         "displayName: value1 for single-valued",
         "displayName: value2 for single-valued",
         "secretary: not a DN like it is supposed to be",
         "",
         "dn: malformed,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "userPassword: password",
         "dc: not allowed",
         "displayName: value1 for single-valued",
         "displayName: value2 for single-valued",
         "secretary: not a DN like it is supposed to be");

    compressedLDIF = createTempFile();
    compressedLDIF.delete();
    FileInputStream is = new FileInputStream(validLDIF);
    OutputStream os =
         new GZIPOutputStream(new FileOutputStream(compressedLDIF));
    final byte[] buffer = new byte[8192];
    while (true)
    {
      final int bytesRead = is.read(buffer);
      if (bytesRead < 0)
      {
        break;
      }
      else
      {
        os.write(buffer, 0, bytesRead);
      }
    }
    is.close();
    os.close();

    encryptedLDIF = createTempFile();
    encryptedLDIF.delete();
    is = new FileInputStream(validLDIF);
    os = new GZIPOutputStream(new PassphraseEncryptedOutputStream("passphrase",
         new FileOutputStream(encryptedLDIF)));
    while (true)
    {
      final int bytesRead = is.read(buffer);
      if (bytesRead < 0)
      {
        break;
      }
      else
      {
        os.write(buffer, 0, bytesRead);
      }
    }
    is.close();
    os.close();

    LDAPConnection conn = getAdminConnection();
    Entry schemaEntry = conn.getEntry("cn=schema", "*", "+");
    conn.close();

    schemaDir = createTempFile();
    schemaDir.delete();
    schemaDir.mkdir();

    File schemaFile = new File(schemaDir, "00-all.ldif");
    LDIFWriter w = new LDIFWriter(schemaFile);
    w.writeEntry(schemaEntry);
    w.close();
  }



  /**
   * Performs any necessary cleanup after processing has completed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if ((schemaDir != null) && schemaDir.exists())
    {
      new File(schemaDir, "00-all.ldif").delete();
      schemaDir.delete();
    }
  }



  /**
   * Provides general test coverage for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void provideGeneralTestCoverage()
         throws Exception
  {
    final ValidateLDIF tool = new ValidateLDIF(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Performs a test with a valid LDIF file with a reject file.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidLDIFWithRejects()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File rejectFile = createTempFile();
    rejectFile.delete();

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-f", validLDIF.getAbsolutePath(),
      "-R", rejectFile.getAbsolutePath(),
      "--ignoreSyntaxViolationsForAttribute", "cn"
    };
    assertEquals(ValidateLDIF.main(args, null, null),
                 ResultCode.SUCCESS);

    assertEquals(rejectFile.length(), 0);
    rejectFile.delete();
  }



  /**
   * Performs a test with a valid LDIF file without a reject file.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidLDIFWithoutRejects()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-f", validLDIF.getAbsolutePath()
    };
    assertEquals(ValidateLDIF.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Performs a test with an invalid LDIF file with a reject file.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidLDIFWithRejects()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File rejectFile = createTempFile();
    rejectFile.delete();

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-f", invalidLDIF.getAbsolutePath(),
      "-R", rejectFile.getAbsolutePath()
    };
    assertFalse(ValidateLDIF.main(args, null, null) == ResultCode.SUCCESS);

    assertFalse(rejectFile.length() == 0);
    rejectFile.delete();
  }



  /**
   * Performs a test with an invalid LDIF file without a reject file.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidLDIFWithoutRejects()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-f", invalidLDIF.getAbsolutePath()
    };
    assertFalse(ValidateLDIF.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test with a compressed LDIF file.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedLDIF()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-f", compressedLDIF.getAbsolutePath(),
      "-c"
    };
    assertEquals(ValidateLDIF.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Performs a test with an encrypted LDIF file when the passphrase is
   * provided in a file.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncryptedLDIFWithPassphraseFromFile()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final File passphraseFile = createTempFile("passphrase");

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-f", encryptedLDIF.getAbsolutePath(),
      "--encryptionPassphraseFile", passphraseFile.getAbsolutePath(),
      "-c"
    };
    assertEquals(ValidateLDIF.main(args, null, null), ResultCode.SUCCESS);
  }



  /**
   * Performs a test with an encrypted LDIF file when the passphrase is
   * provided at an interactive prompt.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncryptedLDIFWithPromptedPassphrase()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    try
    {
      PasswordReader.setTestReaderLines("passphrase");

      String[] args =
      {
        "-h", getTestHost(),
        "-p", String.valueOf(getTestPort()),
        "-D", getTestBindDN(),
        "-w", getTestBindPassword(),
        "-f", encryptedLDIF.getAbsolutePath()
      };
      assertEquals(ValidateLDIF.main(args, null, null), ResultCode.SUCCESS);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Performs a test with an invalid LDIF file with a reject file, ignoring all
   * types of failures.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidLDIFWithRejectsIgnoringFailures()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File rejectFile = createTempFile();
    rejectFile.delete();

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-f", validLDIF.getAbsolutePath(),
      "-R", rejectFile.getAbsolutePath(),
       "--ignoreUndefinedObjectClasses",
       "--ignoreUndefinedAttributes",
       "--ignoreMalformedDNs",
       "--ignoreStructuralObjectClasses",
       "--ignoreProhibitedObjectClasses",
       "--ignoreProhibitedAttributes",
       "--ignoreMissingAttributes",
       "--ignoreSingleValuedAttributes",
       "--ignoreAttributeSyntax",
       "--ignoreNameForms"
    };
    assertEquals(ValidateLDIF.main(args, null, null),
                 ResultCode.SUCCESS);

    assertEquals(rejectFile.length(), 0);
    rejectFile.delete();
  }



  /**
   * Performs a test with an invalid LDIF file without a reject file, ignoring
   * all types of failures.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidLDIFWithoutRejectsIgnoringFailures()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-f", validLDIF.getAbsolutePath(),
       "--ignoreDuplicateValues",
       "--ignoreUndefinedObjectClasses",
       "--ignoreUndefinedAttributes",
       "--ignoreMalformedDNs",
       "--ignoreStructuralObjectClasses",
       "--ignoreProhibitedObjectClasses",
       "--ignoreProhibitedAttributes",
       "--ignoreMissingAttributes",
       "--ignoreSingleValuedAttributes",
       "--ignoreAttributeSyntax",
       "--ignoreNameForms"
    };
    assertEquals(ValidateLDIF.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Performs a test in which the authentication attempt will fail.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthenticationFailure()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", "wrong" + getTestBindPassword(),
      "-f", validLDIF.getAbsolutePath()
    };
    assertFalse(ValidateLDIF.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test with a valid LDIF file with a reject file, using schema
   * read from files rather than a directory.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidLDIFWithRejectsUsingSchemaFiles()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File rejectFile = createTempFile();
    rejectFile.delete();

    String[] args =
    {
      "--schemaDirectory", schemaDir.getAbsolutePath(),
      "-f", validLDIF.getAbsolutePath(),
      "-R", rejectFile.getAbsolutePath()
    };
    assertEquals(ValidateLDIF.main(args, null, null),
                 ResultCode.SUCCESS);

    assertEquals(rejectFile.length(), 0);
    rejectFile.delete();
  }



  /**
   * Performs a test with an empty schema directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptySchemaDirectory()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File emptyDirectory = createTempFile();
    emptyDirectory.delete();
    emptyDirectory.mkdir();

    String[] args =
    {
      "--schemaDirectory", emptyDirectory.getAbsolutePath(),
      "-f", validLDIF.getAbsolutePath()
    };
    assertEquals(ValidateLDIF.main(args, null, null),
                 ResultCode.PARAM_ERROR);

    emptyDirectory.delete();
  }



  /**
   * Performs a test with a malformed schema file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedSchemaFile()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File bogusDirectory = createTempFile();
    bogusDirectory.delete();
    bogusDirectory.mkdir();

    File tmpBogusFile = createTempFile("bogus");
    File bogusFile = new File(bogusDirectory, "bogus.ldif");
    tmpBogusFile.renameTo(bogusFile);

    String[] args =
    {
      "--schemaDirectory", bogusDirectory.getAbsolutePath(),
      "-f", validLDIF.getAbsolutePath()
    };
    assertEquals(ValidateLDIF.main(args, null, null),
                 ResultCode.LOCAL_ERROR);

    bogusFile.delete();
    bogusDirectory.delete();
  }



  /**
   * Performs a test that simply displays usage information for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHelp()
         throws Exception
  {
    String[] args =
    {
      "-H"
    };
    assertEquals(ValidateLDIF.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Performs a test to validate count of multiple structural
   * objects on an entry.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testCountMultipleStructuralObjects()
         throws Exception
  {
    if(!isDirectoryInstanceAvailable())
    {
      return;
    }

    File rejectFile = File.createTempFile("reject", ".ldif");
    File structuralLdif = createTempFile(
            "dn:dc = example, dc = com",
            "objectClass: top",
            "objectClass: domain",
            "dc: example",
            "",
            "dn: ou = People, dc = example, dc = com",
            "objectClass: top",
            "objectClass: organizationalUnit",
            "objectClass: domain",
            "ou: People",
            "dc: subdomain",
            "",
            "dn: uid = user.0, ou = People, dc = example, dc = com",
            "objectClass: top",
            "objectClass: person",
            "objectClass: organizationalPerson",
            "objectClass: inetOrgPerson",
            "objectClass: crlDistributionPoint",
            "uid: user.0",
            "cn: Aaren Atp",
            "sn: Atp");

    String[] args =
    {
      "--schemaDirectory", schemaDir.getAbsolutePath().toString(),
      "-f", structuralLdif.getAbsolutePath().toString(),
      "-R", rejectFile.getAbsolutePath().toString()
    };

    ValidateLDIF validateLDIF = new ValidateLDIF(null, null);
    validateLDIF.runTool(args);
    EntryValidator entryValidator = validateLDIF.getEntryValidator();
    assertEquals(entryValidator
            .getEntriesWithMultipleStructuralObjectClasses(), 2);
  }
}
