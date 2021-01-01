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
import java.util.Collections;
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
 * This class provides test coverage for the ExportTask class.
 */
public class ExportTaskTestCase
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
    ExportTask t = new ExportTask("foo", "bar", "baz");

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.ExportTask");

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "bar");

    assertNotNull(t.getLDIFFile());
    assertEquals(t.getLDIFFile(), "baz");

    assertFalse(t.appendToLDIF());

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

    assertFalse(t.getWrapColumn() > 0);

    assertFalse(t.compress());

    assertFalse(t.encrypt());

    assertNull(t.getEncryptionPassphraseFile());

    assertNull(t.getEncryptionSettingsDefinitionID());

    assertFalse(t.sign());

    assertNull(t.getMaxMegabytesPerSecond());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-export");

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
    new ExportTask("foo", null, "baz");
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
    new ExportTask("foo", "bar", null);
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

    ExportTask t = new ExportTask("foo", "userRoot", "data.ldif", false,
                                  includeBranches, excludeBranches,
                                  includeFilters, excludeFilters, includeAttrs,
                                  excludeAttrs, 80, true, false, true, d,
                                  dependencyIDs, FailedDependencyAction.CANCEL,
                                  notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.ExportTask");

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getLDIFFile());
    assertEquals(t.getLDIFFile(), "data.ldif");

    assertFalse(t.appendToLDIF());

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

    assertEquals(t.getWrapColumn(), 80);

    assertTrue(t.compress());

    assertFalse(t.encrypt());

    assertNull(t.getEncryptionPassphraseFile());

    assertNull(t.getEncryptionSettingsDefinitionID());

    assertTrue(t.sign());

    assertNull(t.getMaxMegabytesPerSecond());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-export");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the second constructor with valid values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2bAll()
         throws Exception
  {
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

    ExportTask t = new ExportTask("foo", "userRoot", "data.ldif", false,
         includeBranches, excludeBranches, includeFilters, excludeFilters,
         includeAttrs, excludeAttrs, 80, true, true, "passphrase.txt",
         "definition", true, 100, d, dependencyIDs,
         FailedDependencyAction.CANCEL, notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.ExportTask");

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getLDIFFile());
    assertEquals(t.getLDIFFile(), "data.ldif");

    assertFalse(t.appendToLDIF());

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

    assertEquals(t.getWrapColumn(), 80);

    assertTrue(t.compress());

    assertTrue(t.encrypt());

    assertNotNull(t.getEncryptionPassphraseFile());
    assertEquals(t.getEncryptionPassphraseFile(), "passphrase.txt");

    assertNotNull(t.getEncryptionSettingsDefinitionID());
    assertEquals(t.getEncryptionSettingsDefinitionID(), "definition");

    assertTrue(t.sign());

    assertNotNull(t.getMaxMegabytesPerSecond());
    assertEquals(t.getMaxMegabytesPerSecond().intValue(), 100);

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-export");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the second constructor with a minimal set of information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Minimal()
         throws Exception
  {
    List<String> includeBranches = Collections.emptyList();
    List<String> excludeBranches = Collections.emptyList();
    List<String> includeFilters = Collections.emptyList();
    List<String> excludeFilters = Collections.emptyList();
    List<String> includeAttrs = Collections.emptyList();
    List<String> excludeAttrs = Collections.emptyList();
    List<String> dependencyIDs = Collections.emptyList();
    List<String> notifyOnCompletion = Collections.emptyList();
    List<String> notifyOnError = Collections.emptyList();

    Date d = new Date();

    ExportTask t = new ExportTask("foo", "userRoot", "data.ldif", true,
                                  includeBranches, excludeBranches,
                                  includeFilters, excludeFilters, includeAttrs,
                                  excludeAttrs, 100, false, true, true, d,
                                  dependencyIDs, FailedDependencyAction.CANCEL,
                                  notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.ExportTask");

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getLDIFFile());
    assertEquals(t.getLDIFFile(), "data.ldif");

    assertTrue(t.appendToLDIF());

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

    assertEquals(t.getWrapColumn(), 100);

    assertFalse(t.compress());

    assertTrue(t.encrypt());

    assertNull(t.getEncryptionPassphraseFile());

    assertNull(t.getEncryptionSettingsDefinitionID());

    assertTrue(t.sign());

    assertNull(t.getMaxMegabytesPerSecond());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-export");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the third constructor with a valid test entry.
   *
   * @param  e  The valid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validEntries")
  public void testConstructor3Valid(final Entry e)
         throws Exception
  {
    ExportTask t = new ExportTask(e);

    assertNotNull(t);

    assertNotNull(t.getLDIFFile());

    assertNotNull(t.getIncludeBranches());

    assertNotNull(t.getExcludeBranches());

    assertNotNull(t.getIncludeFilters());

    assertNotNull(t.getExcludeFilters());

    assertNotNull(t.getIncludeAttributes());

    assertNotNull(t.getExcludeAttributes());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-export");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(Task.decodeTask(e));
    assertTrue(Task.decodeTask(e) instanceof ExportTask);
  }



  /**
   * Retrieves a set of entries that may be parsed as valid export task
   * definitions.
   *
   * @return  A set of entries that may be parsed as valid export task
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
                  "objectclass: ds-task-export",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ExportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-export-backend-id: userRoot",
                  "ds-task-export-ldif-file: foo.ldif")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=validTask2,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-export",
                  "ds-task-id: validTask2",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ExportTask",
                  "ds-task-state: waiting_on_dependency",
                  "ds-task-export-backend-id: userRoot",
                  "ds-task-export-ldif-file: foo",
                  "ds-task-export-append-to-ldif: true",
                  "ds-task-export-include-branch: dc=example,dc=com",
                  "ds-task-export-exclude-branch: ou=local,dc=example,dc=com",
                  "ds-task-export-include-filter: (objectClass=person)",
                  "ds-task-export-exclude-filter: (objectClass=localPerson)",
                  "ds-task-export-include-attribute: cn",
                  "ds-task-export-include-attribute: sn",
                  "ds-task-export-exclude-attribute: userPassword",
                  "ds-task-export-wrap-column: 80",
                  "ds-task-export-compress-ldif: false",
                  "ds-task-export-encrypt-ldif: false",
                  "ds-task-export-encryption-settings-passphrase-file: pw.txt",
                  "ds-task-export-encryption-settings-definition-id: def",
                  "ds-task-export-max-megabytes-per-second: 100",
                  "ds-task-export-sign-hash: true",
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
   * Tests the third constructor with an invalid test entry.
   *
   * @param  e  The invalid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidEntries",
        expectedExceptions = { TaskException.class })
  public void testConstructor3Invalid(final Entry e)
         throws Exception
  {
    new ExportTask(e);
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
      assertFalse(Task.decodeTask(e) instanceof ExportTask);
    }
    catch (TaskException te)
    {
      // This is expected for some failure cases.
    }
  }



  /**
   * Retrieves a set of entries that cannot be parsed as valid export task
   * definitions.
   *
   * @return  A set of entries that cannot be parsed as valid export task
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
                       "ExportTask",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no backend ID,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-export",
                  "ds-task-id: no backend ID",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ExportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-export-ldif-file: foo.ldif")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no ldif file,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-export",
                  "ds-task-id: no ldif file",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ExportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-export-backend-id: userRoot")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid wrap column,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-export",
                  "ds-task-id: invalid wrap column",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ExportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-export-backend-id: userRoot",
                  "ds-task-export-ldif-file: foo.ldif",
                  "ds-task-export-wrap-column: invalid")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid append,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-export",
                  "ds-task-id: invalid append",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ExportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-export-backend-id: userRoot",
                  "ds-task-export-ldif-file: foo.ldif",
                  "ds-task-export-append-to-ldif: invalid")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid compress,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-export",
                  "ds-task-id: invalid compress",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ExportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-export-backend-id: userRoot",
                  "ds-task-export-ldif-file: foo.ldif",
                  "ds-task-export-compress-ldif: invalid")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid encrypt,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-export",
                  "ds-task-id: invalid encrypt",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ExportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-export-backend-id: userRoot",
                  "ds-task-export-ldif-file: foo.ldif",
                  "ds-task-export-encrypt-ldif: invalid")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid sign,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-export",
                  "ds-task-id: invalid sign",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "ExportTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-export-backend-id: userRoot",
                  "ds-task-export-ldif-file: foo.ldif",
                  "ds-task-export-sign-hash: invalid")
      }
    };
  }



  /**
   * Tests the fourth constructor with values for all properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4All()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : new ExportTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-export-backend-id"))
      {
        properties.put(p, Arrays.<Object>asList("userRoot"));
      }
      else if (name.equals("ds-task-export-ldif-file"))
      {
        properties.put(p, Arrays.<Object>asList("foo.ldif"));
      }
      else if (name.equals("ds-task-export-append-to-ldif"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-export-compress-ldif"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-export-encrypt-ldif"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-export-encryption-passphrase-file"))
      {
        properties.put(p, Arrays.<Object>asList("passphrase.txt"));
      }
      else if (name.equals("ds-task-export-encryption-settings-definition-id"))
      {
        properties.put(p, Arrays.<Object>asList("definition"));
      }
      else if (name.equals("ds-task-export-sign-hash"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-export-max-megabytes-per-second"))
      {
        properties.put(p, Arrays.<Object>asList(Long.valueOf(100)));
      }
      else if (name.equals("ds-task-export-include-attribute"))
      {
        properties.put(p, Arrays.<Object>asList("cn", "sn"));
      }
      else if (name.equals("ds-task-export-exclude-attribute"))
      {
        properties.put(p, Arrays.<Object>asList("userPassword"));
      }
      else if (name.equals("ds-task-export-include-branch"))
      {
        properties.put(p, Arrays.<Object>asList("dc=example,dc=com",
                                         "o=example.com"));
      }
      else if (name.equals("ds-task-export-exclude-branch"))
      {
        properties.put(p,
                       Arrays.<Object>asList("ou=Private,dc=example,dc=com"));
      }
      else if (name.equals("ds-task-export-include-filter"))
      {
        properties.put(p, Arrays.<Object>asList("(objectClass=person)"));
      }
      else if (name.equals("ds-task-export-exclude-filter"))
      {
        properties.put(p, Arrays.<Object>asList("(objectClass=private)"));
      }
      else if (name.equals("ds-task-export-wrap-column"))
      {
        properties.put(p, Arrays.<Object>asList(Long.valueOf(75)));
      }
    }

    ExportTask t = new ExportTask(properties);

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getLDIFFile());
    assertEquals(t.getLDIFFile(), "foo.ldif");

    assertTrue(t.appendToLDIF());

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

    assertEquals(t.getWrapColumn(), 75);

    assertTrue(t.compress());

    assertTrue(t.encrypt());

    assertNotNull(t.getEncryptionPassphraseFile());
    assertEquals(t.getEncryptionPassphraseFile(), "passphrase.txt");

    assertNotNull(t.getEncryptionSettingsDefinitionID());
    assertEquals(t.getEncryptionSettingsDefinitionID(), "definition");

    assertTrue(t.sign());

    assertNotNull(t.getMaxMegabytesPerSecond());
    assertEquals(t.getMaxMegabytesPerSecond().intValue(), 100);

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
   * Tests the fourth constructor with values for all required.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4AllRequired()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : new ExportTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-export-backend-id"))
      {
        properties.put(p, Arrays.<Object>asList("userRoot"));
      }
      else if (name.equals("ds-task-export-ldif-file"))
      {
        properties.put(p, Arrays.<Object>asList("foo.ldif"));
      }
    }

    ExportTask t = new ExportTask(properties);

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getLDIFFile());
    assertEquals(t.getLDIFFile(), "foo.ldif");

    assertFalse(t.appendToLDIF());

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

    assertTrue(t.getWrapColumn() <= 0);

    assertFalse(t.compress());

    assertFalse(t.encrypt());

    assertFalse(t.sign());

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
   * Tests the fourth constructor without any values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor4Empty()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();
    new ExportTask(properties);
  }
}
