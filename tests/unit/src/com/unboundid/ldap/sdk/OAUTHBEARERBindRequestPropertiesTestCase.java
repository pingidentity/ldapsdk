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



import org.testng.annotations.Test;

import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * OAUTHBEARERBindRequestProperties class.
 */
public class OAUTHBEARERBindRequestPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a set of properties that only contain an access
   * token.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyAccessToken()
         throws Exception
  {
    OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");

    properties = new OAUTHBEARERBindRequestProperties(properties);

    final OAUTHBEARERBindRequest bindRequest =
         new OAUTHBEARERBindRequest(properties);
    properties = new OAUTHBEARERBindRequestProperties(bindRequest);

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "the-access-token");

    assertNull(properties.getAuthorizationID());

    assertNull(properties.getServerAddress());

    assertNull(properties.getServerPort());

    assertNull(properties.getRequestMethod());

    assertNull(properties.getRequestPath());

    assertNull(properties.getRequestPostData());

    assertNull(properties.getRequestQueryString());

    assertNotNull(properties.getAdditionalKeyValuePairs());
    assertTrue(properties.getAdditionalKeyValuePairs().isEmpty());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for a set of properties that have values for all
   * properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllProperties()
         throws Exception
  {
    OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");
    properties.setAuthorizationID("u:jdoe");
    properties.setServerAddress("ds.example.com");
    properties.setServerPort(389);
    properties.setRequestMethod("POST");
    properties.setRequestPath("/");
    properties.setRequestPostData("the-post-data");
    properties.setRequestQueryString("query=string");
    properties.addKeyValuePair("keyOne", "value1");
    properties.addKeyValuePair("keyTwo", "value2");

    properties = new OAUTHBEARERBindRequestProperties(properties);

    final OAUTHBEARERBindRequest bindRequest =
         new OAUTHBEARERBindRequest(properties);
    properties = new OAUTHBEARERBindRequestProperties(bindRequest);

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "the-access-token");

    assertNotNull(properties.getAuthorizationID());
    assertEquals(properties.getAuthorizationID(), "u:jdoe");

    assertNotNull(properties.getServerAddress());
    assertEquals(properties.getServerAddress(), "ds.example.com");

    assertNotNull(properties.getServerPort());
    assertEquals(properties.getServerPort().intValue(), 389);

    assertNotNull(properties.getRequestMethod());
    assertEquals(properties.getRequestMethod(), "POST");

    assertNotNull(properties.getRequestPath());
    assertEquals(properties.getRequestPath(), "/");

    assertNotNull(properties.getRequestPostData());
    assertEquals(properties.getRequestPostData(), "the-post-data");

    assertNotNull(properties.getRequestQueryString());
    assertEquals(properties.getRequestQueryString(), "query=string");

    assertNotNull(properties.toString());

    properties.setAccessToken("different-access-token");

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "different-access-token");

    assertNotNull(properties.getAuthorizationID());
    assertEquals(properties.getAuthorizationID(), "u:jdoe");

    assertNotNull(properties.getServerAddress());
    assertEquals(properties.getServerAddress(), "ds.example.com");

    assertNotNull(properties.getServerPort());
    assertEquals(properties.getServerPort().intValue(), 389);

    assertNotNull(properties.getRequestMethod());
    assertEquals(properties.getRequestMethod(), "POST");

    assertNotNull(properties.getRequestPath());
    assertEquals(properties.getRequestPath(), "/");

    assertNotNull(properties.getRequestPostData());
    assertEquals(properties.getRequestPostData(), "the-post-data");

    assertNotNull(properties.getRequestQueryString());
    assertEquals(properties.getRequestQueryString(), "query=string");

    assertNotNull(properties.getAdditionalKeyValuePairs());
    assertFalse(properties.getAdditionalKeyValuePairs().isEmpty());
    assertEquals(properties.getAdditionalKeyValuePairs(),
         StaticUtils.mapOf("keyOne", "value1", "keyTwo", "value2"));

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior around the ability to set additional key-value pairs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdditionalKeyValuePairs()
         throws Exception
  {
    OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");

    properties = new OAUTHBEARERBindRequestProperties(properties);

    OAUTHBEARERBindRequest bindRequest = new OAUTHBEARERBindRequest(properties);
    properties = new OAUTHBEARERBindRequestProperties(bindRequest);

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "the-access-token");

    assertNull(properties.getAuthorizationID());

    assertNull(properties.getServerAddress());

    assertNull(properties.getServerPort());

    assertNull(properties.getRequestMethod());

    assertNull(properties.getRequestPath());

    assertNull(properties.getRequestPostData());

    assertNull(properties.getRequestQueryString());

    assertNotNull(properties.getAdditionalKeyValuePairs());
    assertTrue(properties.getAdditionalKeyValuePairs().isEmpty());

    assertNotNull(properties.toString());


    properties.addKeyValuePair("key", "value");

    properties = new OAUTHBEARERBindRequestProperties(properties);

    bindRequest = new OAUTHBEARERBindRequest(properties);
    properties = new OAUTHBEARERBindRequestProperties(bindRequest);

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "the-access-token");

    assertNull(properties.getAuthorizationID());

    assertNull(properties.getServerAddress());

    assertNull(properties.getServerPort());

    assertNull(properties.getRequestMethod());

    assertNull(properties.getRequestPath());

    assertNull(properties.getRequestPostData());

    assertNull(properties.getRequestQueryString());

    assertNotNull(properties.getAdditionalKeyValuePairs());
    assertFalse(properties.getAdditionalKeyValuePairs().isEmpty());
    assertEquals(properties.getAdditionalKeyValuePairs(),
         StaticUtils.mapOf("key", "value"));

    assertNotNull(properties.toString());


    properties.addKeyValuePair("keyTwo", "");

    properties = new OAUTHBEARERBindRequestProperties(properties);

    bindRequest = new OAUTHBEARERBindRequest(properties);
    properties = new OAUTHBEARERBindRequestProperties(bindRequest);

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "the-access-token");

    assertNull(properties.getAuthorizationID());

    assertNull(properties.getServerAddress());

    assertNull(properties.getServerPort());

    assertNull(properties.getRequestMethod());

    assertNull(properties.getRequestPath());

    assertNull(properties.getRequestPostData());

    assertNull(properties.getRequestQueryString());

    assertNotNull(properties.getAdditionalKeyValuePairs());
    assertFalse(properties.getAdditionalKeyValuePairs().isEmpty());
    assertEquals(properties.getAdditionalKeyValuePairs(),
         StaticUtils.mapOf("key", "value", "keyTwo", ""));

    assertNotNull(properties.toString());


    properties.addKeyValuePair("key", "differentValue");

    properties = new OAUTHBEARERBindRequestProperties(properties);

    bindRequest = new OAUTHBEARERBindRequest(properties);
    properties = new OAUTHBEARERBindRequestProperties(bindRequest);

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "the-access-token");

    assertNull(properties.getAuthorizationID());

    assertNull(properties.getServerAddress());

    assertNull(properties.getServerPort());

    assertNull(properties.getRequestMethod());

    assertNull(properties.getRequestPath());

    assertNull(properties.getRequestPostData());

    assertNull(properties.getRequestQueryString());

    assertNotNull(properties.getAdditionalKeyValuePairs());
    assertFalse(properties.getAdditionalKeyValuePairs().isEmpty());
    assertEquals(properties.getAdditionalKeyValuePairs(),
         StaticUtils.mapOf("key", "differentValue", "keyTwo", ""));

    assertNotNull(properties.toString());


    properties.removeKeyValuePair("nonexistent");

    properties = new OAUTHBEARERBindRequestProperties(properties);

    bindRequest = new OAUTHBEARERBindRequest(properties);
    properties = new OAUTHBEARERBindRequestProperties(bindRequest);

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "the-access-token");

    assertNull(properties.getAuthorizationID());

    assertNull(properties.getServerAddress());

    assertNull(properties.getServerPort());

    assertNull(properties.getRequestMethod());

    assertNull(properties.getRequestPath());

    assertNull(properties.getRequestPostData());

    assertNull(properties.getRequestQueryString());

    assertNotNull(properties.getAdditionalKeyValuePairs());
    assertFalse(properties.getAdditionalKeyValuePairs().isEmpty());
    assertEquals(properties.getAdditionalKeyValuePairs(),
         StaticUtils.mapOf("key", "differentValue", "keyTwo", ""));

    assertNotNull(properties.toString());


    properties.removeKeyValuePair("key");

    properties = new OAUTHBEARERBindRequestProperties(properties);

    bindRequest = new OAUTHBEARERBindRequest(properties);
    properties = new OAUTHBEARERBindRequestProperties(bindRequest);

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "the-access-token");

    assertNull(properties.getAuthorizationID());

    assertNull(properties.getServerAddress());

    assertNull(properties.getServerPort());

    assertNull(properties.getRequestMethod());

    assertNull(properties.getRequestPath());

    assertNull(properties.getRequestPostData());

    assertNull(properties.getRequestQueryString());

    assertNotNull(properties.getAdditionalKeyValuePairs());
    assertFalse(properties.getAdditionalKeyValuePairs().isEmpty());
    assertEquals(properties.getAdditionalKeyValuePairs(),
         StaticUtils.mapOf("keyTwo", ""));

    assertNotNull(properties.toString());


    properties.clearAdditionalKeyValuePairs();

    properties = new OAUTHBEARERBindRequestProperties(properties);

    bindRequest = new OAUTHBEARERBindRequest(properties);
    properties = new OAUTHBEARERBindRequestProperties(bindRequest);

    assertNotNull(properties.getAccessToken());
    assertEquals(properties.getAccessToken(), "the-access-token");

    assertNull(properties.getAuthorizationID());

    assertNull(properties.getServerAddress());

    assertNull(properties.getServerPort());

    assertNull(properties.getRequestMethod());

    assertNull(properties.getRequestPath());

    assertNull(properties.getRequestPostData());

    assertNull(properties.getRequestQueryString());

    assertNotNull(properties.getAdditionalKeyValuePairs());
    assertTrue(properties.getAdditionalKeyValuePairs().isEmpty());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior when trying to create a set of properties with a
   * {@code null} access token.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullAccessToken()
         throws Exception
  {
    final String accessToken = null;
    new OAUTHBEARERBindRequestProperties(accessToken);
  }



  /**
   * Tests the behavior when trying to create a set of properties with an empty
   * access token.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyAccessToken()
         throws Exception
  {
    new OAUTHBEARERBindRequestProperties("");
  }



  /**
   * Tests the behavior when trying to create a set of properties with a port
   * that is too small.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testPortTooSmall()
         throws Exception
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");
    properties.setServerPort(0);
  }



  /**
   * Tests the behavior when trying to create a set of properties with a port
   * that is too large.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testPortTooLarge()
         throws Exception
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");
    properties.setServerPort(65536);
  }



  /**
   * Tests the behavior when trying to add a key-value pair with a {@code null}
   * key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testAddKeyValuePairNullKey()
         throws Exception
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");
    properties.addKeyValuePair(null, "value");
  }



  /**
   * Tests the behavior when trying to add a key-value pair with an empty key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testAddKeyValuePairEmptyKey()
         throws Exception
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");
    properties.addKeyValuePair("", "value");
  }



  /**
   * Tests the behavior when trying to add a key-value pair with a key that
   * contains a non-alphabetic character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testAddKeyValuePairKeyHasNonNumericCharacter()
         throws Exception
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");
    properties.addKeyValuePair("key1", "value");
  }



  /**
   * Tests the behavior when trying to add a key-value pair with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testAddKeyValuePairNullValue()
         throws Exception
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");
    properties.addKeyValuePair("key", null);
  }



  /**
   * Tests the behavior when trying to add a key-value pair with a value that
   * contains the 0x00 character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testAddKeyValuePairValueWith0Byte()
         throws Exception
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");
    properties.addKeyValuePair("key", "a\u0000b");
  }



  /**
   * Tests the behavior when trying to add a key-value pair with a value that
   * contains the 0x01 character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testAddKeyValuePairValueWith1Byte()
         throws Exception
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties("the-access-token");
    properties.addKeyValuePair("key", "a\u0001b");
  }
}
