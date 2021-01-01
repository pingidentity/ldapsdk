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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the collect support data task
 * properties.
 */
public final class CollectSupportDataTaskPropertiesTestCase
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
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the output path property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputPath()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setOutputPath("/tmp/test-output-path");
    p = new CollectSupportDataTaskProperties(p);

    assertNotNull(p.getOutputPath());
    assertEquals(p.getOutputPath(), "/tmp/test-output-path");

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setOutputPath(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the encryption passphrase file property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncryptionPassphraseFile()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setEncryptionPassphraseFile("/tmp/pw.txt");
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNotNull(p.getEncryptionPassphraseFile());
    assertEquals(p.getEncryptionPassphraseFile(), "/tmp/pw.txt");

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setEncryptionPassphraseFile(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the include expensive data property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeExpensiveData()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeExpensiveData(true);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNotNull(p.getIncludeExpensiveData());
    assertTrue(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeExpensiveData(false);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNotNull(p.getIncludeExpensiveData());
    assertFalse(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeExpensiveData(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the include replication state dump property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeReplicationStateDump()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeReplicationStateDump(true);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNotNull(p.getIncludeReplicationStateDump());
    assertTrue(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

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


    p.setIncludeReplicationStateDump(false);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNotNull(p.getIncludeReplicationStateDump());
    assertFalse(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeReplicationStateDump(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the include binary files property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeBinaryFiles()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeBinaryFiles(true);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNotNull(p.getIncludeBinaryFiles());
    assertTrue(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeBinaryFiles(false);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNotNull(p.getIncludeBinaryFiles());
    assertFalse(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeBinaryFiles(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the include extension source property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeExtensionSource()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeExtensionSource(true);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNotNull(p.getIncludeExtensionSource());
    assertTrue(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeExtensionSource(false);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNotNull(p.getIncludeExtensionSource());
    assertFalse(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setIncludeExtensionSource(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the use sequential mode property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseSequentialMode()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setUseSequentialMode(true);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNotNull(p.getUseSequentialMode());
    assertTrue(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setUseSequentialMode(false);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNotNull(p.getUseSequentialMode());
    assertFalse(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setUseSequentialMode(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the security level property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityLevel()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    for (final CollectSupportDataSecurityLevel l :
         CollectSupportDataSecurityLevel.values())
    {
      p.setSecurityLevel(l);
      p = new CollectSupportDataTaskProperties(p);

      assertNull(p.getOutputPath());

      assertNull(p.getEncryptionPassphraseFile());

      assertNull(p.getIncludeExpensiveData());

      assertNull(p.getIncludeReplicationStateDump());

      assertNull(p.getIncludeBinaryFiles());

      assertNull(p.getIncludeExtensionSource());

      assertNull(p.getUseSequentialMode());

      assertNotNull(p.getSecurityLevel());
      assertEquals(p.getSecurityLevel(), l);

      assertNull(p.getReportCount());

      assertNull(p.getReportIntervalSeconds());

      assertNull(p.getJStackCount());

      assertNull(p.getLogDuration());

      assertNull(p.getLogDurationMillis());

      assertNull(p.getLogFileHeadCollectionSizeKB());

      assertNull(p.getLogFileTailCollectionSizeKB());

      assertNull(p.getComment());

      assertNull(p.getRetainPreviousSupportDataArchiveCount());

      assertNull(p.getRetainPreviousSupportDataArchiveAge());

      assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setSecurityLevel(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the report count property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReportCount()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setReportCount(0);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNotNull(p.getReportCount());
    assertEquals(p.getReportCount().intValue(), 0);

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setReportCount(1234);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNotNull(p.getReportCount());
    assertEquals(p.getReportCount().intValue(), 1234);

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setReportCount(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the report interval seconds property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReportIntervalSeconds()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setReportIntervalSeconds(1);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNotNull(p.getReportIntervalSeconds());
    assertEquals(p.getReportIntervalSeconds().intValue(), 1);

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setReportIntervalSeconds(4321);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNotNull(p.getReportIntervalSeconds());
    assertEquals(p.getReportIntervalSeconds().intValue(), 4321);

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setReportIntervalSeconds(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the jstack count property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJStackCount()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setJStackCount(0);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNotNull(p.getJStackCount());
    assertEquals(p.getJStackCount().intValue(), 0);

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setJStackCount(5678);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNotNull(p.getJStackCount());
    assertEquals(p.getJStackCount().intValue(), 5678);

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setJStackCount(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the log duration property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogDuration()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setLogDuration("5 minutes");
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNotNull(p.getLogDuration());
    assertEquals(p.getLogDuration(), "5 minutes");

    assertNotNull(p.getLogDurationMillis());
    assertEquals(p.getLogDurationMillis().longValue(), 300_000L);

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    try
    {
      p.setLogDuration("malformed");
      fail("Expected an exception from a malformed log duration");
    }
    catch (final TaskException e)
    {
      // This was expected.
    }

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNotNull(p.getLogDuration());
    assertEquals(p.getLogDuration(), "5 minutes");

    assertNotNull(p.getLogDurationMillis());
    assertEquals(p.getLogDurationMillis().longValue(), 300_000L);

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setLogDuration(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setLogDurationMillis(3_600_000L);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNotNull(p.getLogDuration());
    assertEquals(p.getLogDuration(), "1 hour");

    assertNotNull(p.getLogDurationMillis());
    assertEquals(p.getLogDurationMillis().longValue(), 3_600_000L);

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setLogDurationMillis(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the log file head collection size in
   * kilobytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogFileHeadCollectionSizeKB()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setLogFileHeadCollectionSizeKB(123);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNotNull(p.getLogFileHeadCollectionSizeKB());
    assertEquals(p.getLogFileHeadCollectionSizeKB().intValue(), 123);

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setLogFileHeadCollectionSizeKB(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the log file tail collection size in
   * kilobytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogFileTailCollectionSizeKB()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setLogFileTailCollectionSizeKB(456);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNotNull(p.getLogFileTailCollectionSizeKB());
    assertEquals(p.getLogFileTailCollectionSizeKB().intValue(), 456);

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setLogFileTailCollectionSizeKB(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the comment property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testComment()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setComment("foo");
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNotNull(p.getComment());
    assertEquals(p.getComment(), "foo");

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setComment(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the retain previous support data archive
   * count property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetainPreviousSupportDataArchiveCount()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setRetainPreviousSupportDataArchiveCount(5);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNotNull(p.getRetainPreviousSupportDataArchiveCount());
    assertEquals(p.getRetainPreviousSupportDataArchiveCount().intValue(), 5);

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setRetainPreviousSupportDataArchiveCount(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the retain previous support data archive age
   * property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetainPreviousSupportDataArchiveAge()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setRetainPreviousSupportDataArchiveAge("1 week");
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNotNull(p.getRetainPreviousSupportDataArchiveAge());
    assertEquals(p.getRetainPreviousSupportDataArchiveAge(), "1 week");

    assertNotNull(p.getRetainPreviousSupportDataArchiveAgeMillis());
    assertEquals(p.getRetainPreviousSupportDataArchiveAgeMillis().longValue(),
         604_800_000L);

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


    try
    {
      p.setRetainPreviousSupportDataArchiveAge("malformed");
      fail("Expected an exception from a malformed retain age");
    }
    catch (final TaskException e)
    {
      // This was expected.
    }

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNotNull(p.getRetainPreviousSupportDataArchiveAge());
    assertEquals(p.getRetainPreviousSupportDataArchiveAge(), "1 week");

    assertNotNull(p.getRetainPreviousSupportDataArchiveAgeMillis());
    assertEquals(p.getRetainPreviousSupportDataArchiveAgeMillis().longValue(),
         604_800_000L);

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


    p.setRetainPreviousSupportDataArchiveAge(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setRetainPreviousSupportDataArchiveAgeMillis(432_000_000L);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNotNull(p.getRetainPreviousSupportDataArchiveAge());
    assertEquals(p.getRetainPreviousSupportDataArchiveAge(), "5 days");

    assertNotNull(p.getRetainPreviousSupportDataArchiveAgeMillis());
    assertEquals(p.getRetainPreviousSupportDataArchiveAgeMillis().longValue(),
         432_000_000L);

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


    p.setRetainPreviousSupportDataArchiveAgeMillis(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the task ID property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTaskID()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setTaskID("123-456-7890");
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

    assertNotNull(p.getTaskID());
    assertEquals(p.getTaskID(), "123-456-7890");

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


    p.setTaskID(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the scheduled start time property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScheduledStartTime()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    final Date d = new Date();
    p.setScheduledStartTime(d);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

    assertNull(p.getTaskID());

    assertNotNull(p.getScheduledStartTime());
    assertEquals(p.getScheduledStartTime(), d);

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


    p.setScheduledStartTime(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the dependency IDs property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDependencyIDs()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setDependencyIDs(Arrays.asList("1", "2", "3"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertFalse(p.getDependencyIDs().isEmpty());
    assertEquals(p.getDependencyIDs(), Arrays.asList("1", "2", "3"));

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


    p.setDependencyIDs(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setDependencyIDs(Collections.singletonList("4"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertFalse(p.getDependencyIDs().isEmpty());
    assertEquals(p.getDependencyIDs(), Collections.singletonList("4"));

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


    p.setDependencyIDs(Collections.<String>emptyList());
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the failed dependency action property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedDependencyAction()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    for (final FailedDependencyAction a :
         FailedDependencyAction.values())
    {
      p.setFailedDependencyAction(a);
      p = new CollectSupportDataTaskProperties(p);

      assertNull(p.getOutputPath());

      assertNull(p.getEncryptionPassphraseFile());

      assertNull(p.getIncludeExpensiveData());

      assertNull(p.getIncludeReplicationStateDump());

      assertNull(p.getIncludeBinaryFiles());

      assertNull(p.getIncludeExtensionSource());

      assertNull(p.getUseSequentialMode());

      assertNull(p.getSecurityLevel());

      assertNull(p.getReportCount());

      assertNull(p.getReportIntervalSeconds());

      assertNull(p.getJStackCount());

      assertNull(p.getLogDuration());

      assertNull(p.getLogDurationMillis());

      assertNull(p.getLogFileHeadCollectionSizeKB());

      assertNull(p.getLogFileTailCollectionSizeKB());

      assertNull(p.getComment());

      assertNull(p.getRetainPreviousSupportDataArchiveCount());

      assertNull(p.getRetainPreviousSupportDataArchiveAge());

      assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

      assertNull(p.getTaskID());

      assertNull(p.getScheduledStartTime());

      assertNotNull(p.getDependencyIDs());
      assertTrue(p.getDependencyIDs().isEmpty());

      assertNotNull(p.getFailedDependencyAction());
      assertEquals(p.getFailedDependencyAction(), a);

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


    p.setFailedDependencyAction(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the notify on start property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotifyOnStart()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setNotifyOnStart(Arrays.asList("start1@example.com",
         "start2@example.com"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertFalse(p.getNotifyOnStart().isEmpty());
    assertEquals(p.getNotifyOnStart(),
         Arrays.asList("start1@example.com", "start2@example.com"));

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


    p.setNotifyOnStart(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setNotifyOnStart(Collections.singletonList("start3@example.com"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertFalse(p.getNotifyOnStart().isEmpty());
    assertEquals(p.getNotifyOnStart(),
         Collections.singletonList("start3@example.com"));

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


    p.setNotifyOnStart(Collections.<String>emptyList());
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the notify on completion property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotifyOnCompletion()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setNotifyOnCompletion(Arrays.asList("end1@example.com",
         "end2@example.com"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertFalse(p.getNotifyOnCompletion().isEmpty());
    assertEquals(p.getNotifyOnCompletion(),
         Arrays.asList("end1@example.com", "end2@example.com"));

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnCompletion(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setNotifyOnCompletion(Collections.singletonList("end3@example.com"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertFalse(p.getNotifyOnCompletion().isEmpty());
    assertEquals(p.getNotifyOnCompletion(),
         Collections.singletonList("end3@example.com"));

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnCompletion(Collections.<String>emptyList());
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the notify on success property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotifyOnSuccess()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setNotifyOnSuccess(Arrays.asList("success1@example.com",
         "success2@example.com"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
    assertFalse(p.getNotifyOnSuccess().isEmpty());
    assertEquals(p.getNotifyOnSuccess(),
         Arrays.asList("success1@example.com", "success2@example.com"));

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnSuccess(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setNotifyOnSuccess(Collections.singletonList("success3@example.com"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
    assertFalse(p.getNotifyOnSuccess().isEmpty());
    assertEquals(p.getNotifyOnSuccess(),
         Collections.singletonList("success3@example.com"));

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnSuccess(Collections.<String>emptyList());
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the notify on error property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotifyOnError()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setNotifyOnError(Arrays.asList("error1@example.com",
         "error2@example.com"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
    assertFalse(p.getNotifyOnError().isEmpty());
    assertEquals(p.getNotifyOnError(),
         Arrays.asList("error1@example.com", "error2@example.com"));

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnError(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setNotifyOnError(Collections.singletonList("error3@example.com"));
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
    assertFalse(p.getNotifyOnError().isEmpty());
    assertEquals(p.getNotifyOnError(),
         Collections.singletonList("error3@example.com"));

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnError(Collections.<String>emptyList());
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the alert on start property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAlertOnStart()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setAlertOnStart(true);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
    assertTrue(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnStart(false);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
    assertFalse(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnStart(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the alert on success property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAlertOnSuccess()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setAlertOnSuccess(true);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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

    assertNotNull(p.getAlertOnSuccess());
    assertTrue(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnSuccess(false);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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

    assertNotNull(p.getAlertOnSuccess());
    assertFalse(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnSuccess(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior related to the alert on error property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAlertOnError()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    p.setAlertOnError(true);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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

    assertNotNull(p.getAlertOnError());
    assertTrue(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnError(false);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNotNull(p.getAlertOnError());
    assertFalse(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnError(null);
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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
   * Tests the behavior when setting all of the properties at once.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetAllProperties()
         throws Exception
  {
    CollectSupportDataTaskProperties p = new CollectSupportDataTaskProperties();
    p = new CollectSupportDataTaskProperties(p);

    assertNull(p.getOutputPath());

    assertNull(p.getEncryptionPassphraseFile());

    assertNull(p.getIncludeExpensiveData());

    assertNull(p.getIncludeReplicationStateDump());

    assertNull(p.getIncludeBinaryFiles());

    assertNull(p.getIncludeExtensionSource());

    assertNull(p.getUseSequentialMode());

    assertNull(p.getSecurityLevel());

    assertNull(p.getReportCount());

    assertNull(p.getReportIntervalSeconds());

    assertNull(p.getJStackCount());

    assertNull(p.getLogDuration());

    assertNull(p.getLogDurationMillis());

    assertNull(p.getLogFileHeadCollectionSizeKB());

    assertNull(p.getLogFileTailCollectionSizeKB());

    assertNull(p.getComment());

    assertNull(p.getRetainPreviousSupportDataArchiveCount());

    assertNull(p.getRetainPreviousSupportDataArchiveAge());

    assertNull(p.getRetainPreviousSupportDataArchiveAgeMillis());

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


    final Date d = new Date();

    p.setOutputPath("/tmp/output-path");
    p.setEncryptionPassphraseFile("/tmp/pw.txt");
    p.setIncludeExpensiveData(true);
    p.setIncludeReplicationStateDump(false);
    p.setIncludeBinaryFiles(true);
    p.setIncludeExtensionSource(false);
    p.setUseSequentialMode(true);
    p.setSecurityLevel(CollectSupportDataSecurityLevel.MAXIMUM);
    p.setReportCount(2);
    p.setReportIntervalSeconds(3);
    p.setJStackCount(4);
    p.setLogDuration("5 minutes");
    p.setLogFileHeadCollectionSizeKB(123);
    p.setLogFileTailCollectionSizeKB(456);
    p.setComment("foo");
    p.setRetainPreviousSupportDataArchiveCount(5);
    p.setRetainPreviousSupportDataArchiveAge("1 week");
    p.setTaskID("123-456-7890");
    p.setScheduledStartTime(d);
    p.setDependencyIDs(Arrays.asList("d1", "d2", "d3"));
    p.setFailedDependencyAction(FailedDependencyAction.CANCEL);
    p.setNotifyOnStart(
         Arrays.asList("start1@example.com", "start2@example.com"));
    p.setNotifyOnCompletion(
         Arrays.asList("end1@example.com", "end2@example.com"));
    p.setNotifyOnSuccess(
         Arrays.asList("success1@example.com", "success2@example.com"));
    p.setNotifyOnError(
         Arrays.asList("error1@example.com", "error2@example.com"));
    p.setAlertOnStart(true);
    p.setAlertOnSuccess(false);
    p.setAlertOnError(true);

    p = new CollectSupportDataTaskProperties(p);


    assertNotNull(p.getOutputPath());
    assertEquals(p.getOutputPath(), "/tmp/output-path");

    assertNotNull(p.getEncryptionPassphraseFile());
    assertEquals(p.getEncryptionPassphraseFile(), "/tmp/pw.txt");

    assertNotNull(p.getIncludeExpensiveData());
    assertTrue(p.getIncludeExpensiveData());

    assertNotNull(p.getIncludeReplicationStateDump());
    assertFalse(p.getIncludeReplicationStateDump());

    assertNotNull(p.getIncludeBinaryFiles());
    assertTrue(p.getIncludeBinaryFiles());

    assertNotNull(p.getIncludeExtensionSource());
    assertFalse(p.getIncludeExtensionSource());

    assertNotNull(p.getUseSequentialMode());
    assertTrue(p.getUseSequentialMode());

    assertNotNull(p.getSecurityLevel());
    assertEquals(p.getSecurityLevel(), CollectSupportDataSecurityLevel.MAXIMUM);

    assertNotNull(p.getReportCount());
    assertEquals(p.getReportCount().intValue(), 2);

    assertNotNull(p.getReportIntervalSeconds());
    assertEquals(p.getReportIntervalSeconds().intValue(), 3);

    assertNotNull(p.getJStackCount());
    assertEquals(p.getJStackCount().intValue(), 4);

    assertNotNull(p.getLogDuration());
    assertEquals(p.getLogDuration(), "5 minutes");

    assertNotNull(p.getLogDurationMillis());
    assertEquals(p.getLogDurationMillis().longValue(), 300_000L);

    assertNotNull(p.getLogFileHeadCollectionSizeKB());
    assertEquals(p.getLogFileHeadCollectionSizeKB().intValue(), 123);

    assertNotNull(p.getLogFileTailCollectionSizeKB());
    assertEquals(p.getLogFileTailCollectionSizeKB().intValue(), 456);

    assertNotNull(p.getComment());
    assertEquals(p.getComment(), "foo");

    assertNotNull(p.getRetainPreviousSupportDataArchiveCount());
    assertEquals(p.getRetainPreviousSupportDataArchiveCount().intValue(), 5);

    assertNotNull(p.getRetainPreviousSupportDataArchiveAge());
    assertEquals(p.getRetainPreviousSupportDataArchiveAge(), "1 week");

    assertNotNull(p.getRetainPreviousSupportDataArchiveAgeMillis());
    assertEquals(p.getRetainPreviousSupportDataArchiveAgeMillis().longValue(),
         604_800_000L);

    assertNotNull(p.getTaskID());
    assertEquals(p.getTaskID(), "123-456-7890");

    assertNotNull(p.getScheduledStartTime());
    assertEquals(p.getScheduledStartTime(), d);

    assertNotNull(p.getDependencyIDs());
    assertFalse(p.getDependencyIDs().isEmpty());
    assertEquals(p.getDependencyIDs(), Arrays.asList("d1", "d2", "d3"));

    assertNotNull(p.getFailedDependencyAction());
    assertEquals(p.getFailedDependencyAction(),
         FailedDependencyAction.CANCEL);

    assertNotNull(p.getNotifyOnStart());
    assertFalse(p.getNotifyOnStart().isEmpty());
    assertEquals(p.getNotifyOnStart(),
         Arrays.asList("start1@example.com", "start2@example.com"));

    assertNotNull(p.getNotifyOnCompletion());
    assertFalse(p.getNotifyOnCompletion().isEmpty());
    assertEquals(p.getNotifyOnCompletion(),
         Arrays.asList("end1@example.com", "end2@example.com"));

    assertNotNull(p.getNotifyOnSuccess());
    assertFalse(p.getNotifyOnSuccess().isEmpty());
    assertEquals(p.getNotifyOnSuccess(),
         Arrays.asList("success1@example.com", "success2@example.com"));

    assertNotNull(p.getNotifyOnError());
    assertFalse(p.getNotifyOnError().isEmpty());
    assertEquals(p.getNotifyOnError(),
         Arrays.asList("error1@example.com", "error2@example.com"));

    assertNotNull(p.getAlertOnStart());
    assertTrue(p.getAlertOnStart());

    assertNotNull(p.getAlertOnSuccess());
    assertFalse(p.getAlertOnSuccess());

    assertNotNull(p.getAlertOnError());
    assertTrue(p.getAlertOnError());

    assertNotNull(p.toString());
  }
}
