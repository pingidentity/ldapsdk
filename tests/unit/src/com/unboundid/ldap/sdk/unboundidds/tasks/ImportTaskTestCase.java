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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the ImportTask class.
 */
public class ImportTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with valid values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Valid()
         throws Exception
  {
    ImportTask t = new ImportTask("foo", "bar", "baz");

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.ImportTask");

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "bar");

    assertNotNull(t.getLDIFFiles());
    assertEquals(t.getLDIFFiles().size(), 1);
    assertEquals(t.getLDIFFiles().get(0), "baz");

    assertFalse(t.append());

    assertFalse(t.replaceExistingEntries());

    assertNull(t.getRejectFile());

    assertFalse(t.overwriteRejectFile());

    assertTrue(t.clearBackend());

    assertNotNull(t.getIncludeBranches());
    assertTrue(t.getIncludeBranches().isEmpty());

    assertNotNull(t.getExcludeBranches());
    assertTrue(t.getExcludeBranches().isEmpty());

    assertNotNull(t.getIncludeFilters());
    assertTrue(t.getIncludeFilters().isEmpty());

    assertNotNull(t.getExcludeFilters());
    assertTrue(t.getExcludeFilters().isEmpty());

    assertNotNull(t.getIncludeAttributes());
    assertTrue(t.getIncludeAttributes().isEmpty());

    assertNotNull(t.getExcludeAttributes());
    assertTrue(t.getExcludeAttributes().isEmpty());

    assertFalse(t.isCompressed());

    assertFalse(t.isEncrypted());

    assertNull(t.getEncryptionPassphraseFile());

    assertFalse(t.skipSchemaValidation());

    assertFalse(t.stripTrailingSpaces());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-import");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with a {@code null} backend ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoBackendID()
         throws Exception
  {
    new ImportTask("foo", null, "baz");
  }



  /**
   * Tests the first constructor with a {@code null} LDIF file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoLDIFFile()
         throws Exception
  {
    new ImportTask("foo", "bar", null);
  }



  /**
   * Tests the second constructor with valid values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2All()
         throws Exception
  {
    List<String> ldifFiles = Arrays.asList("bar", "baz");
    List<String> includeBranches = Arrays.asList("dc=example,dc=com");
    List<String> excludeBranches = Arrays.asList("ou=local,dc=example,dc=com");
    List<String> includeFilters = Arrays.asList("(objectClass=person)");
    List<String> excludeFilters = Arrays.asList("(objectClass=localPerson)");
    List<String> includeAttrs = Arrays.asList("cn", "sn");
    List<String> excludeAttrs = Arrays.asList("userPassword");
    List<String> dependencyIDs = Arrays.asList("dep1", "dep2");
    List<String> notifyOnCompletion = Arrays.asList("peon@example.com");
    List<String> notifyOnError = Arrays.asList("admin@example.com");

    Date d = new Date();

    ImportTask t = new ImportTask("foo", ldifFiles, "userRoot", false, false,
                                  "rejects.ldif", true, true, includeBranches,
                                  excludeBranches, includeFilters,
                                  excludeFilters, includeAttrs, excludeAttrs,
                                  true, false, true, d, dependencyIDs,
                                  FailedDependencyAction.CANCEL,
                                  notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.ImportTask");

    assertNotNull(t.getLDIFFiles());
    assertEquals(t.getLDIFFiles().size(), 2);
    assertEquals(t.getLDIFFiles().get(0), "bar");
    assertEquals(t.getLDIFFiles().get(1), "baz");

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertFalse(t.append());

    assertFalse(t.replaceExistingEntries());

    assertNotNull(t.getRejectFile());
    assertEquals(t.getRejectFile(), "rejects.ldif");

    assertTrue(t.overwriteRejectFile());

    assertTrue(t.clearBackend());

    assertNotNull(t.getIncludeBranches());
    assertEquals(t.getIncludeBranches().size(), 1);
    assertEquals(new DN(t.getIncludeBranches().get(0)),
                 new DN("dc=example,dc=com"));

    assertNotNull(t.getExcludeBranches());
    assertEquals(t.getExcludeBranches().size(), 1);
    assertEquals(new DN(t.getExcludeBranches().get(0)),
                 new DN("ou=local,dc=example,dc=com"));

    assertNotNull(t.getIncludeFilters());
    assertEquals(t.getIncludeFilters().size(), 1);
    assertEquals(t.getIncludeFilters().get(0), "(objectClass=person)");

    assertNotNull(t.getExcludeFilters());
    assertEquals(t.getExcludeFilters().size(), 1);
    assertEquals(t.getExcludeFilters().get(0), "(objectClass=localPerson)");

    assertNotNull(t.getIncludeAttributes());
    assertEquals(t.getIncludeAttributes().size(), 2);
    assertEquals(t.getIncludeAttributes().get(0), "cn");
    assertEquals(t.getIncludeAttributes().get(1), "sn");

    assertNotNull(t.getExcludeAttributes());
    assertEquals(t.getExcludeAttributes().size(), 1);
    assertEquals(t.getExcludeAttributes().get(0), "userPassword");

    assertTrue(t.isCompressed());

    assertFalse(t.isEncrypted());

    assertNull(t.getEncryptionPassphraseFile());

    assertTrue(t.skipSchemaValidation());

    assertFalse(t.stripTrailingSpaces());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-import");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the second constructor with no backend ID or include branches.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NoBackendIDOrIncludeBranches()
         throws Exception
  {
    List<String> ldifFiles = Arrays.asList("foo");

    new ImportTask("foo", ldifFiles, null, false, false, null, true, false,
                   null, null, null, null, null, null, false, false, true, null,
                   null, null, null, null);
  }



  /**
   * Tests the second constructor with a backend ID but no include branches, and
   * both {@code clearBackend} and {@code append} set to false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NoClearBackendOrIncludeBranches()
         throws Exception
  {
    List<String> ldifFiles = Arrays.asList("foo");

    new ImportTask("foo", ldifFiles, "userRoot", false, false, null, true,
                   false, null, null, null, null, null, null, false, false,
                   true, null, null, null, null, null);
  }



  /**
   * Tests the second constructor with a backend ID but no include branches, and
   * both {@code clearBackend} set to {@false} but {@code append} set to true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoClearBackendOrIncludeBranchesWithAppend()
         throws Exception
  {
    List<String> ldifFiles = Arrays.asList("foo");

    new ImportTask("foo", ldifFiles, "userRoot", true, false, null, true,
                   false, null, null, null, null, null, null, false, false,
                   true, null, null, null, null, null);
  }



  /**
   * Tests the third constructor with valid values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3All()
         throws Exception
  {
    List<String> ldifFiles = Arrays.asList("bar", "baz");
    List<String> includeBranches = Arrays.asList("dc=example,dc=com");
    List<String> excludeBranches = Arrays.asList("ou=local,dc=example,dc=com");
    List<String> includeFilters = Arrays.asList("(objectClass=person)");
    List<String> excludeFilters = Arrays.asList("(objectClass=localPerson)");
    List<String> includeAttrs = Arrays.asList("cn", "sn");
    List<String> excludeAttrs = Arrays.asList("userPassword");
    List<String> dependencyIDs = Arrays.asList("dep1", "dep2");
    List<String> notifyOnCompletion = Arrays.asList("peon@example.com");
    List<String> notifyOnError = Arrays.asList("admin@example.com");

    Date d = new Date();

    ImportTask t = new ImportTask("foo", ldifFiles, "userRoot", false, false,
                                  "rejects.ldif", true, true, includeBranches,
                                  excludeBranches, includeFilters,
                                  excludeFilters, includeAttrs, excludeAttrs,
                                  true, false, true, true, d, dependencyIDs,
                                  FailedDependencyAction.CANCEL,
                                  notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.ImportTask");

    assertNotNull(t.getLDIFFiles());
    assertEquals(t.getLDIFFiles().size(), 2);
    assertEquals(t.getLDIFFiles().get(0), "bar");
    assertEquals(t.getLDIFFiles().get(1), "baz");

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertFalse(t.append());

    assertFalse(t.replaceExistingEntries());

    assertNotNull(t.getRejectFile());
    assertEquals(t.getRejectFile(), "rejects.ldif");

    assertTrue(t.overwriteRejectFile());

    assertTrue(t.clearBackend());

    assertNotNull(t.getIncludeBranches());
    assertEquals(t.getIncludeBranches().size(), 1);
    assertEquals(new DN(t.getIncludeBranches().get(0)),
                 new DN("dc=example,dc=com"));

    assertNotNull(t.getExcludeBranches());
    assertEquals(t.getExcludeBranches().size(), 1);
    assertEquals(new DN(t.getExcludeBranches().get(0)),
                 new DN("ou=local,dc=example,dc=com"));

    assertNotNull(t.getIncludeFilters());
    assertEquals(t.getIncludeFilters().size(), 1);
    assertEquals(t.getIncludeFilters().get(0), "(objectClass=person)");

    assertNotNull(t.getExcludeFilters());
    assertEquals(t.getExcludeFilters().size(), 1);
    assertEquals(t.getExcludeFilters().get(0), "(objectClass=localPerson)");

    assertNotNull(t.getIncludeAttributes());
    assertEquals(t.getIncludeAttributes().size(), 2);
    assertEquals(t.getIncludeAttributes().get(0), "cn");
    assertEquals(t.getIncludeAttributes().get(1), "sn");

    assertNotNull(t.getExcludeAttributes());
    assertEquals(t.getExcludeAttributes().size(), 1);
    assertEquals(t.getExcludeAttributes().get(0), "userPassword");

    assertTrue(t.isCompressed());

    assertFalse(t.isEncrypted());

    assertNull(t.getEncryptionPassphraseFile());

    assertTrue(t.skipSchemaValidation());

    assertTrue(t.stripTrailingSpaces());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-import");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the third constructor with valid values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3bAll()
         throws Exception
  {
    List<String> ldifFiles = Arrays.asList("bar", "baz");
    List<String> includeBranches = Arrays.asList("dc=example,dc=com");
    List<String> excludeBranches = Arrays.asList("ou=local,dc=example,dc=com");
    List<String> includeFilters = Arrays.asList("(objectClass=person)");
    List<String> excludeFilters = Arrays.asList("(objectClass=localPerson)");
    List<String> includeAttrs = Arrays.asList("cn", "sn");
    List<String> excludeAttrs = Arrays.asList("userPassword");
    List<String> dependencyIDs = Arrays.asList("dep1", "dep2");
    List<String> notifyOnCompletion = Arrays.asList("peon@example.com");
    List<String> notifyOnError = Arrays.asList("admin@example.com");

    Date d = new Date();

    ImportTask t = new ImportTask("foo", ldifFiles, "userRoot", false, false,
         "rejects.ldif", true, true, includeBranches, excludeBranches,
         includeFilters, excludeFilters, includeAttrs, excludeAttrs, true, true,
         "passphrase.txt", true, true, d, dependencyIDs,
         FailedDependencyAction.CANCEL, notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.ImportTask");

    assertNotNull(t.getLDIFFiles());
    assertEquals(t.getLDIFFiles().size(), 2);
    assertEquals(t.getLDIFFiles().get(0), "bar");
    assertEquals(t.getLDIFFiles().get(1), "baz");

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertFalse(t.append());

    assertFalse(t.replaceExistingEntries());

    assertNotNull(t.getRejectFile());
    assertEquals(t.getRejectFile(), "rejects.ldif");

    assertTrue(t.overwriteRejectFile());

    assertTrue(t.clearBackend());

    assertNotNull(t.getIncludeBranches());
    assertEquals(t.getIncludeBranches().size(), 1);
    assertEquals(new DN(t.getIncludeBranches().get(0)),
                 new DN("dc=example,dc=com"));

    assertNotNull(t.getExcludeBranches());
    assertEquals(t.getExcludeBranches().size(), 1);
    assertEquals(new DN(t.getExcludeBranches().get(0)),
                 new DN("ou=local,dc=example,dc=com"));

    assertNotNull(t.getIncludeFilters());
    assertEquals(t.getIncludeFilters().size(), 1);
    assertEquals(t.getIncludeFilters().get(0), "(objectClass=person)");

    assertNotNull(t.getExcludeFilters());
    assertEquals(t.getExcludeFilters().size(), 1);
    assertEquals(t.getExcludeFilters().get(0), "(objectClass=localPerson)");

    assertNotNull(t.getIncludeAttributes());
    assertEquals(t.getIncludeAttributes().size(), 2);
    assertEquals(t.getIncludeAttributes().get(0), "cn");
    assertEquals(t.getIncludeAttributes().get(1), "sn");

    assertNotNull(t.getExcludeAttributes());
    assertEquals(t.getExcludeAttributes().size(), 1);
    assertEquals(t.getExcludeAttributes().get(0), "userPassword");

    assertTrue(t.isCompressed());

    assertTrue(t.isEncrypted());

    assertNotNull(t.getEncryptionPassphraseFile());
    assertEquals(t.getEncryptionPassphraseFile(), "passphrase.txt");

    assertTrue(t.skipSchemaValidation());

    assertTrue(t.stripTrailingSpaces());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-import");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the fourth constructor with a valid test entry.
   *
   * @param  e  The valid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validEntries")
  public void testConstructor4Valid(final Entry e)
         throws Exception
  {
    ImportTask t = new ImportTask(e);

    assertNotNull(t);


    assertNotNull(t.getLDIFFiles());
    assertFalse(t.getLDIFFiles().isEmpty());

    assertNotNull(t.getIncludeBranches());

    assertNotNull(t.getExcludeBranches());

    assertNotNull(t.getIncludeFilters());

    assertNotNull(t.getExcludeFilters());

    assertNotNull(t.getIncludeAttributes());

    assertNotNull(t.getExcludeAttributes());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-import");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(Task.decodeTask(e));
    assertTrue(Task.decodeTask(e) instanceof ImportTask);
  }



  /**
   * Retrieves a set of entries that may be parsed as valid import task
   * definitions.
   *
   * @return  A set of entries that may be parsed as valid import task
   *          definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "validEntries")
  public Object[][] getValidEntries()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        new Entry("dn: ds-task-id=validTask1,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-import-ldif-file: foo")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=validTask2,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: validTask2",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_dependency",
                  "ds-task-import-ldif-file: foo",
                  "ds-task-import-ldif-file: bar",
                  "ds-task-import-append: true",
                  "ds-task-import-replace-existing: true",
                  "ds-task-import-include-branch: dc=example,dc=com",
                  "ds-task-import-exclude-branch: ou=local,dc=example,dc=com",
                  "ds-task-import-include-filter: (objectClass=person)",
                  "ds-task-import-exclude-filter: (objectClass=localPerson)",
                  "ds-task-import-include-attribute: cn",
                  "ds-task-import-include-attribute: sn",
                  "ds-task-import-exclude-attribute: userPassword",
                  "ds-task-import-reject-file: rejects.ldif",
                  "ds-task-import-overwrite-rejects: true",
                  "ds-task-import-skip-schema-validation: true",
                  "ds-task-import-strip-trailing-spaces: true",
                  "ds-task-import-is-compressed: false",
                  "ds-task-import-is-encrypted: false",
                  "ds-task-import-encryption-passphrase-file: passphrase.txt",
                  "ds-task-import-backend-id: userRoot",
                  "ds-task-import-clear-backend: true",
                  "ds-task-scheduled-start-time: 20080101000000Z",
                  "ds-task-actual-start-time: 20080101000000Z",
                  "ds-task-completion-time: 20080101010101Z",
                  "ds-task-dependency-id: validTask1",
                  "ds-task-failed-dependency-action: cancel",
                  "ds-task-log-message: [01/Jan/2008:00:00:00 +0000] starting",
                  "ds-task-log-message: [01/Jan/2008:01:01:01 +0000] done",
                  "ds-task-notify-on-completion: ray@example.com",
                  "ds-task-notify-on-completion: winston@example.com",
                  "ds-task-notify-on-error: peter@example.com",
                  "ds-task-notify-on-error: egon@example.com")
      },
    };
  }



  /**
   * Tests the fourth constructor with an invalid test entry.
   *
   * @param  e  The invalid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidEntries",
        expectedExceptions = { TaskException.class })
  public void testConstructor4Invalid(final Entry e)
         throws Exception
  {
    new ImportTask(e);
  }



  /**
   * Tests the {@code decodeTask} method with an invalid test entry.
   *
   * @param  e  The invalid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidEntries")
  public void testDecodeTask(final Entry e)
         throws Exception
  {
    try
    {
      assertFalse(Task.decodeTask(e) instanceof ImportTask);
    }
    catch (TaskException te)
    {
      // This is expected for some failure cases.
    }
  }



  /**
   * Retrieves a set of entries that cannot be parsed as valid import task
   * definitions.
   *
   * @return  A set of entries that cannot be parsed as valid import task
   *          definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "invalidEntries")
  public Object[][] getInvalidEntries()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        new Entry("dn: ds-task-id=fails in superclass,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: not-ds-task",
                  "ds-task-id: fails in superclass",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no ldif files,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: no ldif files",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=append not boolean,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: append not boolean",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-import-ldif-file: foo",
                  "ds-task-import-append: not boolean")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=replace existing not boolean," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: replace existing not boolean",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-import-ldif-file: foo",
                  "ds-task-import-replace-existing: not boolean")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=overwrite rejects not boolean," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: overwrite rejects not boolean",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-import-ldif-file: foo",
                  "ds-task-import-overwrite-rejects: not boolean")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=clear backend not boolean," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: clear backend not boolean",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-import-ldif-file: foo",
                  "ds-task-import-clear-backend: not boolean")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=is compressed not boolean," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: is compressed not boolean",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-import-ldif-file: foo",
                  "ds-task-import-is-compressed: not boolean")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=is encrypted not boolean," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: is encrypted not boolean",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-import-ldif-file: foo",
                  "ds-task-import-is-encrypted: not boolean")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=skip schema validation not boolean," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: skip schema validation not boolean",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-import-ldif-file: foo",
                  "ds-task-import-skip-schema-validation: not boolean")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=strip trailing spaces not boolean," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-import",
                  "ds-task-id: strip trailing spaces not boolean",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ImportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-import-ldif-file: foo",
                  "ds-task-import-strip-trailing-spaces: not boolean")
      }
    };
  }



  /**
   * Tests the fifth constructor with values for all properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5All()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : new ImportTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-import-backend-id"))
      {
        properties.put(p, Arrays.<Object>asList("userRoot"));
      }
      else if (name.equals("ds-task-import-ldif-file"))
      {
        properties.put(p, Arrays.<Object>asList("foo.ldif"));
      }
      else if (name.equals("ds-task-import-append"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-import-clear-backend"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.FALSE));
      }
      else if (name.equals("ds-task-import-include-attribute"))
      {
        properties.put(p, Arrays.<Object>asList("cn", "sn"));
      }
      else if (name.equals("ds-task-import-exclude-attribute"))
      {
        properties.put(p, Arrays.<Object>asList("userPassword"));
      }
      else if (name.equals("ds-task-import-include-branch"))
      {
        properties.put(p,
             Arrays.<Object>asList("dc=example,dc=com", "o=example.com"));
      }
      else if (name.equals("ds-task-import-exclude-branch"))
      {
        properties.put(p,
                       Arrays.<Object>asList("ou=Private,dc=example,dc=com"));
      }
      else if (name.equals("ds-task-import-include-filter"))
      {
        properties.put(p, Arrays.<Object>asList("(objectClass=person)"));
      }
      else if (name.equals("ds-task-import-exclude-filter"))
      {
        properties.put(p, Arrays.<Object>asList("(objectClass=privatePerson)"));
      }
      else if (name.equals("ds-task-import-is-encrypted"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.FALSE));
      }
      else if (name.equals("ds-task-import-encryption-passphrase-file"))
      {
        properties.put(p, Arrays.<Object>asList("passphrase.txt"));
      }
      else if (name.equals("ds-task-import-is-compressed"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-import-reject-file"))
      {
        properties.put(p, Arrays.<Object>asList("rejects.ldif"));
      }
      else if (name.equals("ds-task-import-overwrite-rejects"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-import-replace-existing"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.FALSE));
      }
      else if (name.equals("ds-task-import-skip-schema-validation"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-import-strip-trailing-spaces"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
    }

    ImportTask t = new ImportTask(properties);

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getLDIFFiles());
    assertEquals(t.getLDIFFiles().size(), 1);

    assertTrue(t.append());

    assertFalse(t.replaceExistingEntries());

    assertNotNull(t.getRejectFile());
    assertEquals(t.getRejectFile(), "rejects.ldif");

    assertTrue(t.overwriteRejectFile());

    assertFalse(t.clearBackend());

    assertNotNull(t.getIncludeAttributes());
    assertEquals(t.getIncludeAttributes().size(), 2);

    assertNotNull(t.getExcludeAttributes());
    assertEquals(t.getExcludeAttributes().size(), 1);

    assertNotNull(t.getIncludeBranches());
    assertEquals(t.getIncludeBranches().size(), 2);

    assertNotNull(t.getExcludeBranches());
    assertEquals(t.getExcludeBranches().size(), 1);

    assertNotNull(t.getIncludeFilters());
    assertEquals(t.getIncludeFilters().size(), 1);

    assertNotNull(t.getExcludeFilters());
    assertEquals(t.getExcludeFilters().size(), 1);

    assertTrue(t.isCompressed());

    assertFalse(t.isEncrypted());

    assertNotNull(t.getEncryptionPassphraseFile());
    assertEquals(t.getEncryptionPassphraseFile(), "passphrase.txt");

    assertTrue(t.skipSchemaValidation());

    assertTrue(t.stripTrailingSpaces());

    Map<TaskProperty,List<Object>> props = t.getTaskPropertyValues();
    for (TaskProperty p : Task.getCommonTaskProperties())
    {
      if (props.get(p) == null)
      {
        continue;
      }

      if (p.isRequired())
      {
        assertFalse(props.get(p).isEmpty());
      }

      if (! p.isMultiValued())
      {
        assertFalse(props.get(p).size() > 1);
      }

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }

    for (TaskProperty p : t.getTaskSpecificProperties())
    {
      assertNotNull(props.get(p));
      if (p.isRequired())
      {
        assertFalse(props.get(p).isEmpty());
      }

      if (! p.isMultiValued())
      {
        assertFalse(props.get(p).size() > 1);
      }

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }
  }



  /**
   * Tests the fifth constructor with values for all required.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5AllRequired()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : new ImportTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-import-backend-id"))
      {
        properties.put(p, Arrays.<Object>asList("userRoot"));
      }
      else if (name.equals("ds-task-import-ldif-file"))
      {
        properties.put(p, Arrays.<Object>asList("foo.ldif"));
      }
    }

    ImportTask t = new ImportTask(properties);

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getLDIFFiles());
    assertEquals(t.getLDIFFiles().size(), 1);

    assertFalse(t.append());

    assertFalse(t.replaceExistingEntries());

    assertNull(t.getRejectFile());

    assertFalse(t.overwriteRejectFile());

    assertTrue(t.clearBackend());

    assertNotNull(t.getIncludeAttributes());
    assertEquals(t.getIncludeAttributes().size(), 0);

    assertNotNull(t.getExcludeAttributes());
    assertEquals(t.getExcludeAttributes().size(), 0);

    assertNotNull(t.getIncludeBranches());
    assertEquals(t.getIncludeBranches().size(), 0);

    assertNotNull(t.getExcludeBranches());
    assertEquals(t.getExcludeBranches().size(), 0);

    assertNotNull(t.getIncludeFilters());
    assertEquals(t.getIncludeFilters().size(), 0);

    assertNotNull(t.getExcludeFilters());
    assertEquals(t.getExcludeFilters().size(), 0);

    assertFalse(t.isCompressed());

    assertFalse(t.isEncrypted());

    assertFalse(t.skipSchemaValidation());

    assertFalse(t.stripTrailingSpaces());

    Map<TaskProperty,List<Object>> props = t.getTaskPropertyValues();
    for (TaskProperty p : Task.getCommonTaskProperties())
    {
      if (props.get(p) == null)
      {
        continue;
      }

      if (p.isRequired())
      {
        assertFalse(props.get(p).isEmpty());
      }

      if (! p.isMultiValued())
      {
        assertFalse(props.get(p).size() > 1);
      }

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }

    for (TaskProperty p : t.getTaskSpecificProperties())
    {
      assertNotNull(props.get(p));
      if (p.isRequired())
      {
        assertFalse(props.get(p).isEmpty());
      }

      if (! p.isMultiValued())
      {
        assertFalse(props.get(p).size() > 1);
      }

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }
  }



  /**
   * Tests the fifth constructor without any values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor5Empty()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();
    new ImportTask(properties);
  }
}
