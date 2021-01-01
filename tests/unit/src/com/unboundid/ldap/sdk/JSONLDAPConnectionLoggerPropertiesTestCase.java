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
package com.unboundid.ldap.sdk;



import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.logging.Handler;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.TestLogHandler;



/**
 * This class provides a set of test cases for the JSON LDAP connection logger
 * properties class.
 */
public final class JSONLDAPConnectionLoggerPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * The log handler to use for testing.
   */
  private static final Handler TEST_LOG_HANDER = new TestLogHandler();



  /**
   * Tests the behavior when using all the default settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultSettings()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the log connects property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogConnects()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogConnects(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertFalse(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogConnects(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the log disconnects property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogDisconnects()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogDisconnects(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertFalse(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogDisconnects(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the log requests property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogRequests()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogRequests(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertFalse(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogRequests(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the log final results property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogFinalResults()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogFinalResults(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertFalse(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogFinalResults(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the log search entries property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogSearchEntries()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogSearchEntries(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertTrue(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogSearchEntries(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the log search references property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogSearchReferences()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogSearchReferences(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertTrue(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogSearchReferences(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the log intermediate responses property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogIntermediateResponses()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogIntermediateResponses(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertFalse(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogIntermediateResponses(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the operation types property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationTypes()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setOperationTypes((OperationType[]) null);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertTrue(p.getOperationTypes().isEmpty());

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    for (final OperationType t : OperationType.values())
    {
      p.setOperationTypes(t);
      p = new JSONLDAPConnectionLoggerProperties(p);
      logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
      p = new JSONLDAPConnectionLoggerProperties(logger);

      assertTrue(p.logConnects());
      assertTrue(p.logDisconnects());
      assertTrue(p.logRequests());
      assertTrue(p.logFinalResults());
      assertFalse(p.logSearchEntries());
      assertFalse(p.logSearchReferences());
      assertTrue(p.logIntermediateResponses());

      assertNotNull(p.getOperationTypes());
      assertFalse(p.getOperationTypes().isEmpty());
      assertEquals(p.getOperationTypes(), EnumSet.of(t));

      assertTrue(p.includeAddAttributeNames());
      assertFalse(p.includeAddAttributeValues());

      assertTrue(p.includeModifyAttributeNames());
      assertFalse(p.includeModifyAttributeValues());

      assertTrue(p.includeSearchEntryAttributeNames());
      assertFalse(p.includeSearchEntryAttributeValues());

      assertNotNull(p.getAttributesToRedact());
      assertFalse(p.getAttributesToRedact().isEmpty());
      assertEquals(p.getAttributesToRedact(),
           StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

      assertTrue(p.includeControlOIDs());

      assertNotNull(p.getSchema());

      assertTrue(p.flushAfterConnectMessages());
      assertTrue(p.flushAfterDisconnectMessages());
      assertFalse(p.flushAfterRequestMessages());
      assertTrue(p.flushAfterFinalResultMessages());
      assertFalse(p.flushAfterNonFinalResultMessages());

      assertNotNull(p.toString());
      assertFalse(p.toString().isEmpty());
    }


    p.setOperationTypes();
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertTrue(p.getOperationTypes().isEmpty());

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setOperationTypes(OperationType.BIND, OperationType.SEARCH);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(),
         EnumSet.of(OperationType.BIND, OperationType.SEARCH));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setOperationTypes((List<OperationType>) null);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertTrue(p.getOperationTypes().isEmpty());

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    for (final OperationType t : OperationType.values())
    {
      p.setOperationTypes(StaticUtils.setOf(t));
      p = new JSONLDAPConnectionLoggerProperties(p);
      logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
      p = new JSONLDAPConnectionLoggerProperties(logger);

      assertTrue(p.logConnects());
      assertTrue(p.logDisconnects());
      assertTrue(p.logRequests());
      assertTrue(p.logFinalResults());
      assertFalse(p.logSearchEntries());
      assertFalse(p.logSearchReferences());
      assertTrue(p.logIntermediateResponses());

      assertNotNull(p.getOperationTypes());
      assertFalse(p.getOperationTypes().isEmpty());
      assertEquals(p.getOperationTypes(), EnumSet.of(t));

      assertTrue(p.includeAddAttributeNames());
      assertFalse(p.includeAddAttributeValues());

      assertTrue(p.includeModifyAttributeNames());
      assertFalse(p.includeModifyAttributeValues());

      assertTrue(p.includeSearchEntryAttributeNames());
      assertFalse(p.includeSearchEntryAttributeValues());

      assertNotNull(p.getAttributesToRedact());
      assertFalse(p.getAttributesToRedact().isEmpty());
      assertEquals(p.getAttributesToRedact(),
           StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

      assertTrue(p.includeControlOIDs());

      assertNotNull(p.getSchema());

      assertTrue(p.flushAfterConnectMessages());
      assertTrue(p.flushAfterDisconnectMessages());
      assertFalse(p.flushAfterRequestMessages());
      assertTrue(p.flushAfterFinalResultMessages());
      assertFalse(p.flushAfterNonFinalResultMessages());

      assertNotNull(p.toString());
      assertFalse(p.toString().isEmpty());
    }


    p.setOperationTypes(Collections.<OperationType>emptyList());
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertTrue(p.getOperationTypes().isEmpty());

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setOperationTypes(Arrays.asList(OperationType.ADD, OperationType.DELETE));
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(),
         EnumSet.of(OperationType.ADD, OperationType.DELETE));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setOperationTypes(EnumSet.allOf(OperationType.class));
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the include add attribute names property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeAddAttributeNames()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeAddAttributeNames(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertFalse(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeAddAttributeNames(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the include add attribute values property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeAddAttributeValues()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeAddAttributeValues(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertTrue(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeAddAttributeValues(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the include modify attribute names property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeModifyAttributeNames()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeModifyAttributeNames(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertFalse(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeModifyAttributeNames(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the include modify attribute values property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeModifyAttributeValues()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeModifyAttributeValues(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertTrue(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeModifyAttributeValues(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the include search entry attribute names property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeSearchEntryAttributeNames()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeSearchEntryAttributeNames(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertFalse(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeSearchEntryAttributeNames(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the include search entry attribute values property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeSearchEntryAttributeValues()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeSearchEntryAttributeValues(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertTrue(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeSearchEntryAttributeValues(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the schema property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchema()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setSchema(null);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setSchema(Schema.getDefaultStandardSchema());
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the attributes to redact property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributesToRedact()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setAttributesToRedact((String[]) null);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertTrue(p.getAttributesToRedact().isEmpty());

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setAttributesToRedact("userPassword");
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setAttributesToRedact();
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertTrue(p.getAttributesToRedact().isEmpty());

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setAttributesToRedact(Collections.singletonList("unicodePwd"));
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setAttributesToRedact((List<String>) null);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertTrue(p.getAttributesToRedact().isEmpty());

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setAttributesToRedact(StaticUtils.setOf("userPassword", "authPassword",
         "unicodePwd"));
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setAttributesToRedact(Collections.<String>emptyList());
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertTrue(p.getAttributesToRedact().isEmpty());

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the include control OIDs property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeControlOIDs()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeControlOIDs(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertFalse(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setIncludeControlOIDs(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the flush after connect messages property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFlushAfterConnectMessages()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterConnectMessages(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertFalse(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterConnectMessages(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the flush after disconnect messages property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFlushAfterDisconnectMessages()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterDisconnectMessages(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertFalse(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterDisconnectMessages(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the flush after request messages property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFlushAfterRequestMessages()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterRequestMessages(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertTrue(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterRequestMessages(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the flush after final result messages property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFlushAfterFinalResultMessages()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterFinalResultMessages(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertFalse(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterFinalResultMessages(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior for the flush after non-final result messages property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFlushAfterNonFinalResultMessages()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterNonFinalResultMessages(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertTrue(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setFlushAfterNonFinalResultMessages(false);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }



  /**
   * Tests the behavior when setting all properties to non-default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllProperties()
         throws Exception
  {
    JSONLDAPConnectionLoggerProperties p =
         new JSONLDAPConnectionLoggerProperties();
    p = new JSONLDAPConnectionLoggerProperties(p);

    JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertTrue(p.logConnects());
    assertTrue(p.logDisconnects());
    assertTrue(p.logRequests());
    assertTrue(p.logFinalResults());
    assertFalse(p.logSearchEntries());
    assertFalse(p.logSearchReferences());
    assertTrue(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertFalse(p.getOperationTypes().isEmpty());
    assertEquals(p.getOperationTypes(), EnumSet.allOf(OperationType.class));

    assertTrue(p.includeAddAttributeNames());
    assertFalse(p.includeAddAttributeValues());

    assertTrue(p.includeModifyAttributeNames());
    assertFalse(p.includeModifyAttributeValues());

    assertTrue(p.includeSearchEntryAttributeNames());
    assertFalse(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertFalse(p.getAttributesToRedact().isEmpty());
    assertEquals(p.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(p.includeControlOIDs());

    assertNotNull(p.getSchema());

    assertTrue(p.flushAfterConnectMessages());
    assertTrue(p.flushAfterDisconnectMessages());
    assertFalse(p.flushAfterRequestMessages());
    assertTrue(p.flushAfterFinalResultMessages());
    assertFalse(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());


    p.setLogConnects(false);
    p.setLogDisconnects(false);
    p.setLogRequests(false);
    p.setLogFinalResults(false);
    p.setLogSearchEntries(true);
    p.setLogSearchReferences(true);
    p.setLogIntermediateResponses(false);
    p.setOperationTypes();
    p.setIncludeAddAttributeNames(false);
    p.setIncludeAddAttributeValues(true);
    p.setIncludeModifyAttributeNames(false);
    p.setIncludeModifyAttributeValues(true);
    p.setIncludeSearchEntryAttributeNames(false);
    p.setIncludeSearchEntryAttributeValues(true);
    p.setAttributesToRedact();
    p.setIncludeControlOIDs(false);
    p.setSchema(null);
    p.setFlushAfterConnectMessages(false);
    p.setFlushAfterDisconnectMessages(false);
    p.setFlushAfterRequestMessages(true);
    p.setFlushAfterFinalResultMessages(false);
    p.setFlushAfterNonFinalResultMessages(true);
    p = new JSONLDAPConnectionLoggerProperties(p);
    logger = new JSONLDAPConnectionLogger(TEST_LOG_HANDER, p);
    p = new JSONLDAPConnectionLoggerProperties(logger);

    assertFalse(p.logConnects());
    assertFalse(p.logDisconnects());
    assertFalse(p.logRequests());
    assertFalse(p.logFinalResults());
    assertTrue(p.logSearchEntries());
    assertTrue(p.logSearchReferences());
    assertFalse(p.logIntermediateResponses());

    assertNotNull(p.getOperationTypes());
    assertTrue(p.getOperationTypes().isEmpty());

    assertFalse(p.includeAddAttributeNames());
    assertTrue(p.includeAddAttributeValues());

    assertFalse(p.includeModifyAttributeNames());
    assertTrue(p.includeModifyAttributeValues());

    assertFalse(p.includeSearchEntryAttributeNames());
    assertTrue(p.includeSearchEntryAttributeValues());

    assertNotNull(p.getAttributesToRedact());
    assertTrue(p.getAttributesToRedact().isEmpty());

    assertFalse(p.includeControlOIDs());

    assertNull(p.getSchema());

    assertFalse(p.flushAfterConnectMessages());
    assertFalse(p.flushAfterDisconnectMessages());
    assertTrue(p.flushAfterRequestMessages());
    assertFalse(p.flushAfterFinalResultMessages());
    assertTrue(p.flushAfterNonFinalResultMessages());

    assertNotNull(p.toString());
    assertFalse(p.toString().isEmpty());
  }
}
