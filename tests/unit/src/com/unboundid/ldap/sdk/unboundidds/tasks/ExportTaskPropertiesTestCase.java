/*
 * Copyright 2020-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2024 Ping Identity Corporation
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
 * Copyright (C) 2020-2024 Ping Identity Corporation
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

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for export task properties.
 */
public final class ExportTaskPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with the default set of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    ExportTaskProperties p =
         new ExportTaskProperties("userRoot", "userRoot.ldif");
    p = new ExportTaskProperties(p);

    assertNotNull(p.getBackendID());
    assertEquals(p.getBackendID(), "userRoot");

    assertNotNull(p.getLDIFFile());
    assertEquals(p.getLDIFFile(), "userRoot.ldif");

    assertFalse(p.appendToLDIF());

    assertNotNull(p.getIncludeBranches());
    assertTrue(p.getIncludeBranches().isEmpty());

    assertNotNull(p.getExcludeBranches());
    assertTrue(p.getExcludeBranches().isEmpty());

    assertNotNull(p.getIncludeFilters());
    assertTrue(p.getIncludeFilters().isEmpty());

    assertNotNull(p.getExcludeFilters());
    assertTrue(p.getExcludeFilters().isEmpty());

    assertNotNull(p.getIncludeAttributes());
    assertTrue(p.getIncludeAttributes().isEmpty());

    assertNotNull(p.getExcludeAttributes());
    assertTrue(p.getExcludeAttributes().isEmpty());

    assertEquals(p.getWrapColumn(), -1);

    assertFalse(p.compress());

    assertFalse(p.encrypt());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getEncryptionSettingsDefinitionID());

    assertFalse(p.sign());

    assertNull(p.getMaxMegabytesPerSecond());

    assertNotNull(p.getPostExportTaskProcessors());
    assertTrue(p.getPostExportTaskProcessors().isEmpty());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for setting all of the properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllProperties()
         throws Exception
  {
    ExportTaskProperties p =
         new ExportTaskProperties("userRoot", "userRoot.ldif");
    p = new ExportTaskProperties(p);

    assertNotNull(p.getBackendID());
    assertEquals(p.getBackendID(), "userRoot");

    assertNotNull(p.getLDIFFile());
    assertEquals(p.getLDIFFile(), "userRoot.ldif");

    assertFalse(p.appendToLDIF());

    assertNotNull(p.getIncludeBranches());
    assertTrue(p.getIncludeBranches().isEmpty());

    assertNotNull(p.getExcludeBranches());
    assertTrue(p.getExcludeBranches().isEmpty());

    assertNotNull(p.getIncludeFilters());
    assertTrue(p.getIncludeFilters().isEmpty());

    assertNotNull(p.getExcludeFilters());
    assertTrue(p.getExcludeFilters().isEmpty());

    assertNotNull(p.getIncludeAttributes());
    assertTrue(p.getIncludeAttributes().isEmpty());

    assertNotNull(p.getExcludeAttributes());
    assertTrue(p.getExcludeAttributes().isEmpty());

    assertEquals(p.getWrapColumn(), -1);

    assertFalse(p.compress());

    assertFalse(p.encrypt());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getEncryptionSettingsDefinitionID());

    assertFalse(p.sign());

    assertNull(p.getMaxMegabytesPerSecond());

    assertNotNull(p.getPostExportTaskProcessors());
    assertTrue(p.getPostExportTaskProcessors().isEmpty());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setBackendID("otherBackend");
    p.setLDIFFile("other.ldif");
    p.setAppendToLDIF(true);
    p.setIncludeBranches(Arrays.asList("dc=example,dc=com"));
    p.setExcludeBranches(Arrays.asList("ou=Excluded1,dc=example,dc=com",
         "ou=Excluded2,dc=example,dc=com"));
    p.setIncludeFilters(Arrays.asList("(objectClass=person)"));
    p.setExcludeFilters(Arrays.asList("(cn=excluded)", "(sn=excluded)"));
    p.setIncludeAttributes(Arrays.asList("*", "+"));
    p.setExcludeAttributes(Arrays.asList("userPassword"));
    p.setWrapColumn(80);
    p.setCompress(false);
    p.setEncrypt(true);
    p.setEncryptionPassphraseFile("passphrase.txt");
    p.setEncryptionSettingsDefinitionID("abcdef0123456789");
    p.setSign(false);
    p.setMaxMegabytesPerSecond(1234);
    p.setPostExportTaskProcessors(Arrays.asList("Upload to S3"));
    p.setTaskID("test-task");
    p.setScheduledStartTime(new Date());
    p.setDependencyIDs(Arrays.asList("dependency1", "dependency2"));
    p.setFailedDependencyAction(FailedDependencyAction.PROCESS);
    p.setNotifyOnStart(Arrays.asList("start@example.com"));
    p.setNotifyOnCompletion(Arrays.asList("completion@example.com"));
    p.setNotifyOnSuccess(Arrays.asList("success@example.com"));
    p.setNotifyOnError(Arrays.asList("error@example.com"));
    p.setAlertOnStart(true);
    p.setAlertOnSuccess(false);
    p.setAlertOnError(true);

    p = new ExportTaskProperties(p);

    final ExportTask task = new ExportTask(p);
    p = new ExportTaskProperties(task);

    assertNotNull(p.getBackendID());
    assertEquals(p.getBackendID(), "otherBackend");

    assertNotNull(p.getLDIFFile());
    assertEquals(p.getLDIFFile(), "other.ldif");

    assertTrue(p.appendToLDIF());

    assertNotNull(p.getIncludeBranches());
    assertEquals(p.getIncludeBranches(), Arrays.asList("dc=example,dc=com"));

    assertNotNull(p.getExcludeBranches());
    assertEquals(p.getExcludeBranches(),
         Arrays.asList("ou=Excluded1,dc=example,dc=com",
              "ou=Excluded2,dc=example,dc=com"));

    assertNotNull(p.getIncludeFilters());
    assertEquals(p.getIncludeFilters(), Arrays.asList("(objectClass=person)"));

    assertNotNull(p.getExcludeFilters());
    assertEquals(p.getExcludeFilters(),
         Arrays.asList("(cn=excluded)", "(sn=excluded)"));

    assertNotNull(p.getIncludeAttributes());
    assertEquals(p.getIncludeAttributes(), Arrays.asList("*", "+"));

    assertNotNull(p.getExcludeAttributes());
    assertEquals(p.getExcludeAttributes(), Arrays.asList("userPassword"));

    assertEquals(p.getWrapColumn(), 80);

    assertFalse(p.compress());

    assertTrue(p.encrypt());

    assertNotNull(p.getEncryptionPassphraseFile());
    assertEquals(p.getEncryptionPassphraseFile(), "passphrase.txt");

    assertNotNull(p.getEncryptionSettingsDefinitionID());
    assertEquals(p.getEncryptionSettingsDefinitionID(), "abcdef0123456789");

    assertFalse(p.sign());

    assertNotNull(p.getMaxMegabytesPerSecond());
    assertEquals(p.getMaxMegabytesPerSecond().intValue(), 1234);

    assertNotNull(p.getPostExportTaskProcessors());
    assertEquals(p.getPostExportTaskProcessors(),
         Arrays.asList("Upload to S3"));

    assertNotNull(p.getTaskID());
    assertEquals(p.getTaskID(), "test-task");

    assertNotNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertEquals(p.getDependencyIDs(),
         Arrays.asList("dependency1", "dependency2"));

    assertNotNull(p.getFailedDependencyAction());
    assertEquals(p.getFailedDependencyAction(), FailedDependencyAction.PROCESS);

    assertNotNull(p.getNotifyOnStart());
    assertEquals(p.getNotifyOnStart(), Arrays.asList("start@example.com"));

    assertNotNull(p.getNotifyOnCompletion());
    assertEquals(p.getNotifyOnCompletion(),
         Arrays.asList("completion@example.com"));

    assertNotNull(p.getNotifyOnSuccess());
    assertEquals(p.getNotifyOnSuccess(), Arrays.asList("success@example.com"));

    assertNotNull(p.getNotifyOnError());
    assertEquals(p.getNotifyOnError(), Arrays.asList("error@example.com"));

    assertNotNull(p.getAlertOnStart());
    assertEquals(p.getAlertOnStart(), Boolean.TRUE);

    assertNotNull(p.getAlertOnSuccess());
    assertEquals(p.getAlertOnSuccess(), Boolean.FALSE);

    assertNotNull(p.getAlertOnError());
    assertEquals(p.getAlertOnError(), Boolean.TRUE);

    assertNotNull(p.toString());


    p.setBackendID("userRoot");
    p.setLDIFFile("userRoot.ldif");
    p.setAppendToLDIF(false);
    p.setIncludeBranches(null);
    p.setExcludeBranches(null);
    p.setIncludeFilters(null);
    p.setExcludeFilters(null);
    p.setIncludeAttributes(null);
    p.setExcludeAttributes(null);
    p.setWrapColumn(0);
    p.setCompress(true);
    p.setEncrypt(false);
    p.setEncryptionPassphraseFile(null);
    p.setEncryptionSettingsDefinitionID(null);
    p.setSign(true);
    p.setMaxMegabytesPerSecond(null);
    p.setPostExportTaskProcessors(null);
    p.setTaskID(null);
    p.setScheduledStartTime(null);
    p.setDependencyIDs(null);
    p.setFailedDependencyAction(null);
    p.setNotifyOnStart(null);
    p.setNotifyOnCompletion(null);
    p.setNotifyOnSuccess(null);
    p.setNotifyOnError(null);
    p.setAlertOnStart(false);
    p.setAlertOnSuccess(true);
    p.setAlertOnError(null);

    p = new ExportTaskProperties(p);

    assertNotNull(p.getBackendID());
    assertEquals(p.getBackendID(), "userRoot");

    assertNotNull(p.getLDIFFile());
    assertEquals(p.getLDIFFile(), "userRoot.ldif");

    assertFalse(p.appendToLDIF());

    assertNotNull(p.getIncludeBranches());
    assertTrue(p.getIncludeBranches().isEmpty());

    assertNotNull(p.getExcludeBranches());
    assertTrue(p.getExcludeBranches().isEmpty());

    assertNotNull(p.getIncludeFilters());
    assertTrue(p.getIncludeFilters().isEmpty());

    assertNotNull(p.getExcludeFilters());
    assertTrue(p.getExcludeFilters().isEmpty());

    assertNotNull(p.getIncludeAttributes());
    assertTrue(p.getIncludeAttributes().isEmpty());

    assertNotNull(p.getExcludeAttributes());
    assertTrue(p.getExcludeAttributes().isEmpty());

    assertEquals(p.getWrapColumn(), -1);

    assertTrue(p.compress());

    assertFalse(p.encrypt());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getEncryptionSettingsDefinitionID());

    assertTrue(p.sign());

    assertNull(p.getMaxMegabytesPerSecond());

    assertNotNull(p.getPostExportTaskProcessors());
    assertTrue(p.getPostExportTaskProcessors().isEmpty());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNotNull(p.getAlertOnStart());
    assertEquals(p.getAlertOnStart(), Boolean.FALSE);

    assertNotNull(p.getAlertOnSuccess());
    assertEquals(p.getAlertOnSuccess(), Boolean.TRUE);

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }
}
