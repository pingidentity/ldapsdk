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
package com.unboundid.util;



import java.io.ByteArrayInputStream;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Null;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DisconnectType;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;



/**
 * This class provides test coverage for the Debug class.  Note that methods in
 * this class should not make any assumptions about whether debugging will be
 * enabled and with what debug types, so each method is ensuring that the
 * debugger has the appropriate configuration before performing the tests.
 */
public class DebugTestCase
       extends UtilTestCase
{
  // Indicates whether the logger was enabled before running these test cases.
  private boolean enabledBeforeStarting;

  // Indicates whether the logger was using parent handlers before running
  // these test cases.
  private boolean useParentHandlersBeforeStarting;

  // The set of configured debug types that were in use before running these
  // test cases.
  private EnumSet<DebugType> debugTypesBeforeStarting;

  // The log level that was in use before running these test cases.
  private Level levelBeforeStarting;

  // The logger that is in use by the debug subsystem.
  private Logger logger;

  // The test log handler that we will use to determine whether messages have
  // been logged or not.
  private TestLogHandler testLogHandler;



  /**
   * Configures the underlying logger with a special handler so that we can use
   * it to test whether debug messages are properly generated.
   */
  @BeforeClass()
  public void setUp()
  {
    enabledBeforeStarting    = Debug.debugEnabled();
    debugTypesBeforeStarting = Debug.getDebugTypes();

    logger = Debug.getLogger();
    levelBeforeStarting = logger.getLevel();
    useParentHandlersBeforeStarting = logger.getUseParentHandlers();
    logger.setLevel(Level.ALL);
    logger.setUseParentHandlers(false);

    testLogHandler = new TestLogHandler();
    testLogHandler.setFilter(null);
    testLogHandler.setLevel(Level.ALL);
    logger.addHandler(testLogHandler);
  }



  /**
   * Remove the custom handler from the logger since we no longer need it.
   */
  @AfterClass()
  public void cleanUp()
  {
    logger.removeHandler(testLogHandler);

    Debug.setEnabled(enabledBeforeStarting, debugTypesBeforeStarting);
    logger.setLevel(levelBeforeStarting);
    logger.setUseParentHandlers(useParentHandlersBeforeStarting);
  }



  /**
   * Tests the {@code initialize} method with a {@code null} property set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeNull()
         throws Exception
  {
    Debug.initialize(null);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with an empty property set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeEmpty()
         throws Exception
  {
    Debug.initialize(new Properties());

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the enabled property set to an
   * empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeEnabledEmpty()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_ENABLED, "");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the enabled property set to
   * "true".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeEnabledTrue()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_ENABLED, "true");
    Debug.initialize(props);

    assertTrue(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the enabled property set to
   * "false".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeEnabledFalse()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_ENABLED, "false");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the enabled property set to an
   * invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testInitializeEnabledInvalid()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_ENABLED, "invalid");
    Debug.initialize(props);
  }



  /**
   * Tests the {@code initialize} method with the includeStackTrace property set
   * to an empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeIncludeStackTraceEmpty()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_INCLUDE_STACK_TRACE, "");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the includeStackTrace property set
   * to "true".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeIncludeStackTraceTrue()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_INCLUDE_STACK_TRACE, "true");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertTrue(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the includeStackTrace property set
   * to "false".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeIncludeStackTraceFalse()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_INCLUDE_STACK_TRACE, "false");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the includeStackTrace property set
   * to an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testInitializeIncludeStackTraceInvalid()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_INCLUDE_STACK_TRACE, "invalid");
    Debug.initialize(props);
  }



  /**
   * Tests the {@code initialize} method with the type property set to an empty
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeTypeEmpty()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_TYPE, "");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the type property set to a single
   * valid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeTypeSingleValid()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_TYPE, "ldap");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.of(DebugType.LDAP));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the type property set to multiple
   * valid values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeTypeMultipleValid()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_TYPE,
                      "asn1,connect,exception,ldap,ldif");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(),
                 EnumSet.of(DebugType.ASN1, DebugType.CONNECT,
                            DebugType.EXCEPTION, DebugType.LDAP,
                            DebugType.LDIF));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the type property set to a single
   * invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testInitializeTypeSingleInalid()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_TYPE, "invalid");
    Debug.initialize(props);
  }



  /**
   * Tests the {@code initialize} method with the type property set to multiple
   * values, including an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testInitializeTypeMultipleWithInvalid()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_TYPE,
                      "asn1,connect,exception,ldap,ldif,other,invalid");
    Debug.initialize(props);
  }



  /**
   * Tests the {@code initialize} method with the level property set to an empty
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelEmpty()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to "ALL".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelAll()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "ALL");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to
   * "SEVERE".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelSevere()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "SEVERE");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.SEVERE);

    // NOTE:  We need to make sure the level gets set back to "ALL" so other
    // tests run correctly.
    logger.setLevel(Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to
   * "WARNING".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelWarning()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "WARNING");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.WARNING);

    // NOTE:  We need to make sure the level gets set back to "ALL" so other
    // tests run correctly.
    logger.setLevel(Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to
   * "INFO".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelInfo()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "INFO");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.INFO);

    // NOTE:  We need to make sure the level gets set back to "ALL" so other
    // tests run correctly.
    logger.setLevel(Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to
   * "CONFIG".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelConfig()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "CONFIG");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.CONFIG);

    // NOTE:  We need to make sure the level gets set back to "ALL" so other
    // tests run correctly.
    logger.setLevel(Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to
   * "FINE".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelFine()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "FINE");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.FINE);

    // NOTE:  We need to make sure the level gets set back to "ALL" so other
    // tests run correctly.
    logger.setLevel(Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to
   * "FINER".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelFiner()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "FINER");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.FINER);

    // NOTE:  We need to make sure the level gets set back to "ALL" so other
    // tests run correctly.
    logger.setLevel(Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to
   * "FINEST".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelFinest()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "FINEST");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.FINEST);

    // NOTE:  We need to make sure the level gets set back to "ALL" so other
    // tests run correctly.
    logger.setLevel(Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to
   * "OFF".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitializeLevelOff()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "OFF");
    Debug.initialize(props);

    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.includeStackTrace());
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
    assertEquals(Debug.getLogger().getLevel(), Level.OFF);

    // NOTE:  We need to make sure the level gets set back to "ALL" so other
    // tests run correctly.
    logger.setLevel(Level.ALL);
  }



  /**
   * Tests the {@code initialize} method with the level property set to an
   * invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testInitializeLevelInvalid()
         throws Exception
  {
    Properties props = new Properties();
    props.setProperty(Debug.PROPERTY_DEBUG_LEVEL, "INVALID");
    Debug.initialize(props);
  }



  /**
   * Provides test coverage for the methods used control whether debugging is
   * enabled and determining the set of configured debug types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnableAndDisable()
         throws Exception
  {
    // Disable the debugger without setting any debug types (which will make the
    // set all types).
    Debug.setEnabled(false);
    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    assertFalse(Debug.debugEnabled(DebugType.CONNECTION_POOL));
    assertFalse(Debug.debugEnabled(DebugType.EXCEPTION));
    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    assertFalse(Debug.debugEnabled(DebugType.OTHER));
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));

    // Enable the debugger for only exceptions.
    Debug.setEnabled(true, EnumSet.of(DebugType.EXCEPTION));
    assertTrue(Debug.debugEnabled());
    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    assertFalse(Debug.debugEnabled(DebugType.CONNECTION_POOL));
    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    assertFalse(Debug.debugEnabled(DebugType.OTHER));
    assertEquals(Debug.getDebugTypes(), EnumSet.of(DebugType.EXCEPTION));

    // Disable the debugger, using a type set of only LDAP.
    Debug.setEnabled(false, EnumSet.of(DebugType.LDAP));
    assertFalse(Debug.debugEnabled());
    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    assertFalse(Debug.debugEnabled(DebugType.CONNECTION_POOL));
    assertFalse(Debug.debugEnabled(DebugType.EXCEPTION));
    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    assertFalse(Debug.debugEnabled(DebugType.OTHER));
    assertEquals(Debug.getDebugTypes(), EnumSet.of(DebugType.LDAP));

    // Enable the debugger without setting any debug types (which will make the
    // set all types).
    Debug.setEnabled(true);
    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    assertTrue(Debug.debugEnabled(DebugType.CONNECTION_POOL));
    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    assertTrue(Debug.debugEnabled(DebugType.OTHER));
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));

    // Enable the debugger a null set of debug types (which will make the set
    // all types).
    Debug.setEnabled(true, null);
    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    assertTrue(Debug.debugEnabled(DebugType.CONNECTION_POOL));
    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    assertTrue(Debug.debugEnabled(DebugType.OTHER));
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));

    // Enable the debugger an empty set of debug types (which will make the set
    // all types).
    Debug.setEnabled(true, EnumSet.noneOf(DebugType.class));
    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    assertTrue(Debug.debugEnabled(DebugType.CONNECTION_POOL));
    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    assertTrue(Debug.debugEnabled(DebugType.OTHER));
    assertEquals(Debug.getDebugTypes(), EnumSet.allOf(DebugType.class));
  }



  /**
   * Tests the {@code includeStackTrace} and {@code setIncludeStackTrace}
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeStackTrace()
         throws Exception
  {
    Debug.initialize();
    Debug.setEnabled(true);
    assertFalse(Debug.includeStackTrace());

    testLogHandler.resetMessageCount();
    Debug.debug(Level.SEVERE, DebugType.OTHER, "foo");
    String s = testLogHandler.getMessagesString();
    assertTrue(s.contains("foo"));
    assertFalse(s.contains("caller-stack-trace"));
    assertValidJSON(testLogHandler.getMessagesString());

    Debug.setIncludeStackTrace(true);
    assertTrue(Debug.includeStackTrace());

    testLogHandler.resetMessageCount();
    Debug.debug(Level.SEVERE, DebugType.OTHER, "foo");
    s = testLogHandler.getMessagesString();
    assertTrue(s.contains("foo"));
    assertTrue(s.contains("caller-stack-trace"));
    assertValidJSON(testLogHandler.getMessagesString());

    Debug.setIncludeStackTrace(false);
    assertFalse(Debug.includeStackTrace());

    testLogHandler.resetMessageCount();
    Debug.debug(Level.SEVERE, DebugType.OTHER, "foo");
    s = testLogHandler.getMessagesString();
    assertTrue(s.contains("foo"));
    assertFalse(s.contains("caller-stack-trace"));
    assertValidJSON(testLogHandler.getMessagesString());
  }



  /**
   * Ensures that the provided string consists of zero or more valid JSON
   * objects.
   *
   * @param  s  The string to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void assertValidJSON(final String s)
          throws Exception
  {
    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(StaticUtils.getBytes(s));
    try (JSONObjectReader r = new JSONObjectReader(inputStream))
    {
      while (true)
      {
        final JSONObject o = r.readObject();
        if (o == null)
        {
          break;
        }
      }
    }
  }



  /**
   * Tests the first {@code debugException} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugException} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugException} method with the debugger enabled and
   * a debug type set that includes only the exception type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException1EnabledOnlyException()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.EXCEPTION));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugException} method with the debugger enabled and
   * a debug type set that includes the exception type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException1EnabledIncludeException()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.EXCEPTION, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugException} method with the debugger enabled and
   * a debug type set that does not include the exception type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException1EnabledWithoutException()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugException} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(Level.FINEST,  new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugException} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(Level.FINEST, new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugException} method with the debugger enabled
   * and a debug type set that includes only the exception type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException2EnabledOnlyException()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.EXCEPTION));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(Level.FINEST, new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugException} method with the debugger enabled
   * and a debug type set that includes the exception type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException2EnabledIncludeException()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.EXCEPTION, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(Level.FINEST, new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugException} method with the debugger enabled
   * and a debug type set that does not include the exception type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugException2EnabledWithoutException()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.EXCEPTION));
    Debug.debugException(Level.FINEST, new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugConnect} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect("server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugConnect} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect("server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugConnect} method with the debugger enabled and
   * a debug type set that includes only the connect type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect1EnabledOnlyConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CONNECT));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect("server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugConnect} method with the debugger enabled and
   * a debug type set that includes the connect type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect1EnabledIncludeConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CONNECT, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect("server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugConnect} method with the debugger enabled and
   * a debug type set that does not include the connect type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect1EnabledWithoutConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect("server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugConnect} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect(Level.FINEST, "server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugConnect} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect(Level.FINEST, "server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugConnect} method with the debugger enabled and
   * a debug type set that includes only the connect type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect2EnabledOnlyConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CONNECT));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect(Level.FINEST, "server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugConnect} method with the debugger enabled and
   * a debug type set that includes the connect type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect2EnabledIncludeConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CONNECT, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect(Level.FINEST, "server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugConnect} method with the debugger enabled and
   * a debug type set that does not include the connect type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnect2EnabledWithoutConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugConnect(Level.FINEST, "server.example.com", 389);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugDisconnect} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect("server.example.com", 389, DisconnectType.UNBIND,
                          "testDebugDisconnect1DisabledAll", null);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugDisconnect} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect("server.example.com", 389, DisconnectType.UNBIND,
                          "testDebugDisconnect1EnabledAll", new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugDisconnect} method with the debugger enabled
   * and a debug type set that includes only the connect type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect1EnabledOnlyConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CONNECT));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect("server.example.com", 389, DisconnectType.UNBIND,
                          "testDebugDisconnect1EnabledOnlyConnect", null);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugDisconnect} method with the debugger enabled
   * and a debug type set that includes the connect type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect1EnabledIncludeConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CONNECT, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect("server.example.com", 389, DisconnectType.UNBIND,
                          "testDebugDisconnect1EnabledIncludeConnect", null);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugDisconnect} method with the debugger enabled
   * and a debug type set that does not include the connect type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect1EnabledWithoutConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect("server.example.com", 389, DisconnectType.UNBIND,
                          "testDebugDisconnect1EnabledWIthoutConnect", null);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugDisconnect} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect(Level.FINEST, "server.example.com", 389,
                          DisconnectType.UNBIND,
                          "testDebugDisconnect2DisabledAll", null);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugDisconnect} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect(Level.FINEST, "server.example.com", 389,
                          DisconnectType.UNBIND,
                          "testDebugDisconnect2EnabledAll", new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugDisconnect} method with the debugger enabled
   * and a debug type set that includes only the connect type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect2EnabledOnlyConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CONNECT));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect(Level.FINEST, "server.example.com", 389,
                          DisconnectType.UNBIND,
                          "testDebugDisconnect2EnabledOnlyConnect", null);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugDisconnect} method with the debugger enabled
   * and a debug type set that includes the connect type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect2EnabledIncludeConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CONNECT, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect(Level.FINEST, "server.example.com", 389,
                          DisconnectType.UNBIND,
                          "testDebugDisconnect2EnabledIncludeConnect", null);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugDisconnect} method with the debugger enabled
   * and a debug type set that does not include the connect type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugDisconnect2EnabledWithoutConnect()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CONNECT));
    Debug.debugDisconnect(Level.FINEST, "server.example.com", 389,
                          DisconnectType.UNBIND,
                          "testDebugDisconnect2EnabledWithoutConnect", null);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugLDAPRequest} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugLDAPRequest} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDAPRequest} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest1EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDAPRequest} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest1EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDAPRequest} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest1EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugLDAPRequest} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(Level.FINEST,
                           new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugLDAPRequest} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(Level.FINEST,
                           new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDAPRequest} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest2EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(Level.FINEST,
                           new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDAPRequest} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest2EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(Level.FINEST,
                           new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDAPRequest} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPRequest2EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPRequest(Level.FINEST,
                           new DeleteRequest("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugLDAPResult} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult1EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult1EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult1EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugLDAPResult} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST, new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST, new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult2EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST, new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult2EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST, new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult2EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST, new LDAPResult(1, ResultCode.SUCCESS));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the third {@code debugLDAPResult} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult3DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(e);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the third {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult3EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(e);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the third {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult3EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(e);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the third {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult3EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(e);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the third {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult3EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(e);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the fourth {@code debugLDAPResult} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult4DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, e);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the fourth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult4EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, e);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fourth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult4EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, e);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fourth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult4EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, e);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fourth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult4EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    SearchResultEntry e =
         new SearchResultEntry("dc=example,dc=com", attrs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, e);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the fifth {@code debugLDAPResult} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult5DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(r);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the fifth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult5EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(r);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fifth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult5EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(r);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fifth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult5EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(r);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fifth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult5EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(r);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the sixth {@code debugLDAPResult} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult6DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, r);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the sixth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult6EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, r);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the sixth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult6EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, r);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the sixth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult6EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, r);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the sixth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult6EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server1.example.com/dc=example,dc=com"
    };
    SearchResultReference r =
         new SearchResultReference(refs, new Control[0]);
    Debug.debugLDAPResult(Level.FINEST, r);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the seventh {@code debugLDAPResult} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult7DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the seventh {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult7EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the seventh {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult7EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the seventh {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult7EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the seventh {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult7EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the eighth {@code debugLDAPResult} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult8DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST,
                          new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the eighth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult8EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST,
                          new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the eighth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes only the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult8EnabledOnlyLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST,
                          new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the eighth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that includes the LDAP type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult8EnabledIncludeLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST,
                          new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the eighth {@code debugLDAPResult} method with the debugger enabled
   * and a debug type set that does not include the LDAP type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDAPResult8EnabledWithoutLDAP()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDAP));
    Debug.debugLDAPResult(Level.FINEST,
                          new IntermediateResponse("1.2.3.4", null));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugASN1Write} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugASN1Write} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugASN1Write} method with the debugger enabled
   * and a debug type set that includes only the ASN.1 type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write1EnabledOnlyASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.ASN1));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugASN1Write} method with the debugger enabled
   * and a debug type set that includes the ASN.1 type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write1EnabledIncludeASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.ASN1, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugASN1Write} method with the debugger enabled
   * and a debug type set that does not include the ASN.1 type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write1EnabledWithoutASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugASN1Write} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugASN1Write} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugASN1Write} method with the debugger enabled
   * and a debug type set that includes only the ASN.1 type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write2EnabledOnlyASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.ASN1));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugASN1Write} method with the debugger enabled
   * and a debug type set that includes the ASN.1 type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write2EnabledIncludeASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.ASN1, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugASN1Write} method with the debugger enabled
   * and a debug type set that does not include the ASN.1 type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Write2EnabledWithoutASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Write(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugASN1Read} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugASN1Read} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugASN1Read} method with the debugger enabled
   * and a debug type set that includes only the ASN.1 type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read1EnabledOnlyASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.ASN1));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugASN1Read} method with the debugger enabled
   * and a debug type set that includes the ASN.1 type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read1EnabledIncludeASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.ASN1, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugASN1Read} method with the debugger enabled
   * and a debug type set that does not include the ASN.1 type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read1EnabledWithoutASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugASN1Read} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugASN1Read} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugASN1Read} method with the debugger enabled
   * and a debug type set that includes only the ASN.1 type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read2EnabledOnlyASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.ASN1));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugASN1Read} method with the debugger enabled
   * and a debug type set that includes the ASN.1 type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read2EnabledIncludeASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.ASN1, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugASN1Read} method with the debugger enabled
   * and a debug type set that does not include the ASN.1 type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1Read2EnabledWithoutASN1()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.ASN1));
    Debug.debugASN1Read(Level.FINEST, new ASN1Null());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Provides coverage for the method that debugs the read of an ASN.1 element
   * using the streaming API in which a request may be read an element at a time
   * instead of the full message all at once.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugASN1ReadElementComponents()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.ASN1));

    Debug.debugASN1Read(Level.INFO, "Null", 0x05, 0, null);

    Debug.debugASN1Read(Level.INFO, "Boolean", 0x01, 1, true);

    Debug.debugASN1Read(Level.INFO, "byte[]", 0x04, 4,
         new byte[] { 0x01, 0x02, 0x03, 0x04 });

    assertTrue(testLogHandler.getMessageCount() >= 3);
  }



  /**
   * Provides coverage for the method that debugs connection pool interaction.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugConnectionPool()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CONNECTION_POOL));

    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnectionPool pool = ds.getConnectionPool(1);

    assertNotNull(pool.getRootDSE());
    assertTrue(testLogHandler.getMessageCount() >= 2);
    testLogHandler.resetMessageCount();

    pool.setConnectionPoolName("Test pool");
    final LDAPConnection conn = pool.getConnection();
    conn.setConnectionName("Test connection");
    pool.releaseConnection(conn);
    assertTrue(testLogHandler.getMessageCount() >= 2);
    testLogHandler.resetMessageCount();

    pool.close();
    assertTrue(testLogHandler.getMessageCount() >= 1);
    testLogHandler.resetMessageCount();

    try
    {
      pool.getRootDSE();
      fail("Expected an exception when trying to use a closed pool");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
    assertTrue(testLogHandler.getMessageCount() >= 1);
    testLogHandler.resetMessageCount();

    Debug.debugConnectionPool(Level.SEVERE, pool, null, "Test message",
         new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDIFWrite} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite1EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite1EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite1EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugLDIFWrite} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite2EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite2EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite2EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the third {@code debugLDIFWrite} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite3DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(Level.FINEST, new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the third {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite3EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(Level.FINEST, new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the third {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite3EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(Level.FINEST, new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the third {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite3EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(Level.FINEST, new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the third {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite3EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFWrite(Level.FINEST,  new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the fourth {@code debugLDIFWrite} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite4DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(Level.FINEST,
                         new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the fourth {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite4EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(Level.FINEST,
                         new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fourth {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite4EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(Level.FINEST,
                         new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fourth {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite4EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(Level.FINEST,
                         new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fourth {@code debugLDIFWrite} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFWrite4EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFWrite(Level.FINEST,
                         new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugLDIFRead} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead1EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead1EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead1EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugLDIFRead} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead2EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead2EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead2EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the third {@code debugLDIFRead} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead3DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(Level.FINEST, new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the third {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead3EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(Level.FINEST, new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the third {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead3EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(Level.FINEST, new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the third {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead3EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(Level.FINEST, new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the third {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead3EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };
    Debug.debugLDIFRead(Level.FINEST,  new Entry("dc=example,dc=com", attrs));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the fourth {@code debugLDIFRead} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead4DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(Level.FINEST,
                        new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the fourth {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead4EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(Level.FINEST,
                        new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fourth {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead4EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(Level.FINEST,
                        new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fourth {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead4EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(Level.FINEST,
                        new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the fourth {@code debugLDIFRead} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugLDIFRead4EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debugLDIFRead(Level.FINEST,
                        new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugMonitor} method with the debugger disabled and
   * a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor1DisabledAll()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debugMonitor} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor1EnabledAll()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugMonitor} method with the debugger enabled
   * and a debug type set that includes only the monitor type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor1EnabledOnlyMonitor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(true, EnumSet.of(DebugType.MONITOR));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugMonitor} method with the debugger enabled
   * and a debug type set that includes the monitor type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor1EnabledIncludeMonitor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(true, EnumSet.of(DebugType.MONITOR, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debugMonitor} method with the debugger enabled
   * and a debug type set that does not include the monitor type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor1EnabledWithoutMonitor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugMonitor} method with the debugger disabled and
   * a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor2DisabledAll()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(Level.FINEST, e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debugMonitor} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor2EnabledAll()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(Level.FINEST, e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugMonitor} method with the debugger enabled
   * and a debug type set that includes only the monitor type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor2EnabledOnlyMonitor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(true, EnumSet.of(DebugType.MONITOR));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(Level.FINEST, e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugMonitor} method with the debugger enabled
   * and a debug type set that includes the monitor type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor2EnabledIncludeMonitor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(true, EnumSet.of(DebugType.MONITOR, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(Level.FINEST, e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debugMonitor} method with the debugger enabled
   * and a debug type set that does not include the monitor type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugMonitor2EnabledWithoutMonitor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.MONITOR));
    Debug.debugMonitor(Level.FINEST, e, "Read Monitor Entry");
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the {@code debugCodingError} method with the debugger disabled and a
   * debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugCodingErrorDisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CODING_ERROR));
    LDAPSDKUsageException e = new LDAPSDKUsageException("You screwed up");
    Debug.debugCodingError(e);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the {@code debugCodingError} method with the debugger enabled and a
   * debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugCodingErrorEnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CODING_ERROR));
    LDAPSDKUsageException e = new LDAPSDKUsageException("You screwed up");
    Debug.debugCodingError(e);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the {@code debugCodingError} method with the debugger enabled and a
   * debug type set that includes only the monitor type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugCodingErrorEnabledOnlyMonitor()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CODING_ERROR));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CODING_ERROR));
    LDAPSDKUsageException e = new LDAPSDKUsageException("You screwed up");
    Debug.debugCodingError(e);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the {@code debugCodingError} method with the debugger enabled and a
   * debug type set that includes the monitor type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugCodingErrorEnabledIncludeMonitor()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.CODING_ERROR, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.CODING_ERROR));
    LDAPSDKUsageException e = new LDAPSDKUsageException("You screwed up");
    Debug.debugCodingError(e);
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the {@code debugCodingError} method with the debugger enabled and a
   * debug type set that does not include the monitor type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugCodingErrorEnabledWithoutMonitor()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.CODING_ERROR));
    LDAPSDKUsageException e = new LDAPSDKUsageException("You screwed up");
    Debug.debugCodingError(e);
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debug} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug1DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.");
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the first {@code debug} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug1EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.");
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debug} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug1EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.");
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debug} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug1EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.");
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the first {@code debug} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug1EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.");
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debug} method with the debugger disabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug2DisabledAll()
         throws Exception
  {
    Debug.setEnabled(false);
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.",
                new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests the second {@code debug} method with the debugger enabled
   * and a debug type set of all types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug2EnabledAll()
         throws Exception
  {
    Debug.setEnabled(true);
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.",
                new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debug} method with the debugger enabled
   * and a debug type set that includes only the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug2EnabledOnlyLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.",
                new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debug} method with the debugger enabled
   * and a debug type set that includes the LDIF type among others.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug2EnabledIncludeLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.LDIF, DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertTrue(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.",
                new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 1);
  }



  /**
   * Tests the second {@code debug} method with the debugger enabled
   * and a debug type set that does not include the LDIF type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug2EnabledWithoutLDIF()
         throws Exception
  {
    Debug.setEnabled(true, EnumSet.of(DebugType.OTHER));
    testLogHandler.resetMessageCount();

    assertFalse(Debug.debugEnabled(DebugType.LDIF));
    Debug.debug(Level.FINEST, DebugType.LDIF, "Reached the end of the file.",
                new Exception());
    assertTrue(testLogHandler.getMessageCount() >= 0);
  }



  /**
   * Tests debugging to ensure that it is working as expected when actually
   * communicating with a Directory Server.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugWithServer()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    Debug.setEnabled(true);

    // Note:  It is possible in some cases to get more messages than we
    // expect (e.g., because an exception was caught on disconnect, or a
    // previous closure is only now getting registered).  For that reason, we'll
    // be lenient and accept the case in which at least the expected number of
    // messages were generated.

    // Get an admin connection to the server.  This should result in five
    // debug events:
    // 1.  CONNECT when the connection is established.
    // 2.  LDAP when the bind request LDAP message is written.
    // 3.  ASN1 when the bind request ASN.1 element is written.
    // 4.  LDAP when the bind result LDAP message is read.
    testLogHandler.resetMessageCount();
    LDAPConnection conn = getAdminConnection();
    assertTrue((testLogHandler.getMessageCount() >= 4),
               testLogHandler.getMessagesString());
    assertValidJSON(testLogHandler.getMessagesString());


    // Add an entry to the server.  This should result in four debug events:
    // 1.  LDAP when the add request LDAP message is written.
    // 2.  ASN1 when the add request ASN.1 element is written.
    // 3.  LDAP when the add result LDAP message is read.
    testLogHandler.resetMessageCount();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    assertTrue((testLogHandler.getMessageCount() >= 3),
               testLogHandler.getMessagesString());
    assertValidJSON(testLogHandler.getMessagesString());


    // Read the entry back.  This should result in six debug events:
    // 1.  LDAP when the search request LDAP message is written.
    // 2.  ASN1 when the search request ASN.1 element is written.
    // 3.  LDAP when the search result entry LDAP message is read.
    // 4.  LDAP when the search result done LDAP message is read.
    testLogHandler.resetMessageCount();
    conn.getEntry(getTestBaseDN());
    assertTrue((testLogHandler.getMessageCount() >= 4),
               testLogHandler.getMessagesString());
    assertValidJSON(testLogHandler.getMessagesString());


    // Remove entry from the server.  This should result in four debug events:
    // 1.  LDAP when the delete request LDAP message is written.
    // 2.  ASN1 when the delete request ASN.1 element is written.
    // 3.  LDAP when the delete result LDAP message is read.
    testLogHandler.resetMessageCount();
    conn.delete(getTestBaseDN());
    assertTrue((testLogHandler.getMessageCount() >= 3),
               testLogHandler.getMessagesString());
    assertValidJSON(testLogHandler.getMessagesString());


    // Close the connection to the server.  This should result in three debug
    // events:
    // 1.  LDAP when the unbind request LDAP message is written.
    // 2.  ASN1 when the unbind request ASN.1 element is written.
    // 3.  CONNECT when the connection is closed.
    testLogHandler.resetMessageCount();
    conn.close();
    assertTrue((testLogHandler.getMessageCount() >= 3),
               testLogHandler.getMessagesString());
    assertValidJSON(testLogHandler.getMessagesString());
  }



  /**
   * Tests the {@code forName} method with automated tests based on the actual
   * name of the enum values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameAutomated()
         throws Exception
  {
    for (final DebugType value : DebugType.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(DebugType.forName(name));
        assertEquals(DebugType.forName(name), value);
      }
    }

    assertNull(DebugType.forName("some undefined name"));
  }



  /**
   * Retrieves a set of names for testing the {@code forName} method based on
   * the provided set of names.
   *
   * @param  baseNames  The base set of names to use to generate the full set of
   *                    names.  It must not be {@code null} or empty.
   *
   * @return  The full set of names to use for testing.
   */
  private static Set<String> getNames(final String... baseNames)
  {
    final HashSet<String> nameSet = new HashSet<>(10);
    for (final String name : baseNames)
    {
      nameSet.add(name);
      nameSet.add(name.toLowerCase());
      nameSet.add(name.toUpperCase());

      final String nameWithDashesInsteadOfUnderscores = name.replace('_', '-');
      nameSet.add(nameWithDashesInsteadOfUnderscores);
      nameSet.add(nameWithDashesInsteadOfUnderscores.toLowerCase());
      nameSet.add(nameWithDashesInsteadOfUnderscores.toUpperCase());

      final String nameWithUnderscoresInsteadOfDashes = name.replace('-', '_');
      nameSet.add(nameWithUnderscoresInsteadOfDashes);
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toLowerCase());
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toUpperCase());

      final StringBuilder nameWithoutUnderscoresOrDashes = new StringBuilder();
      for (final char c : name.toCharArray())
      {
        if ((c != '-') && (c != '_'))
        {
          nameWithoutUnderscoresOrDashes.append(c);
        }
      }
      nameSet.add(nameWithoutUnderscoresOrDashes.toString());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toLowerCase());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toUpperCase());
    }

    return nameSet;
  }
}
