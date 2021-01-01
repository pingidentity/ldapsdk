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



import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the OAUTHBEARERBindRequest class.
 */
public class OAUTHBEARERBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a bind request that only contains an access token.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyAccessToken()
         throws Exception
  {
    OAUTHBEARERBindRequest bindRequest =
         new OAUTHBEARERBindRequest("the-access-token");

    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getSASLMechanismName());
    assertEquals(bindRequest.getSASLMechanismName(), "OAUTHBEARER");

    assertNotNull(bindRequest.getAccessToken());
    assertEquals(bindRequest.getAccessToken(), "the-access-token");

    assertNull(bindRequest.getAuthorizationID());

    assertNull(bindRequest.getServerAddress());

    assertNull(bindRequest.getServerPort());

    assertNull(bindRequest.getRequestMethod());

    assertNull(bindRequest.getRequestPath());

    assertNull(bindRequest.getRequestPostData());

    assertNull(bindRequest.getRequestQueryString());

    assertNotNull(bindRequest.getAdditionalKeyValuePairs());
    assertTrue(bindRequest.getAdditionalKeyValuePairs().isEmpty());

    assertNotNull(bindRequest.encodeCredentials());
    assertEquals(bindRequest.encodeCredentials(),
         new ASN1OctetString("n,,\u0001auth=Bearer the-access-token\u0001"));

    assertNotNull(bindRequest.toString());

    final List<String> toCodeLines = new ArrayList<>();
    bindRequest.toCode(toCodeLines, "testRequestID", 4, true);
    assertFalse(toCodeLines.isEmpty());
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
    properties.setAuthorizationID("dn:uid=jdoe,ou=People,dc=example,dc=com");
    properties.setServerAddress("ds.example.com");
    properties.setServerPort(389);
    properties.setRequestMethod("POST");
    properties.setRequestPath("/");
    properties.setRequestPostData("the-post-data");
    properties.setRequestQueryString("query=string");
    properties.addKeyValuePair("keyOne", "value1");
    properties.addKeyValuePair("keyTwo", "value2");

    OAUTHBEARERBindRequest bindRequest = new OAUTHBEARERBindRequest(properties,
         new Control("1.2.3.4"),
         new Control("5.6.7.8", true, new ASN1OctetString("foo")));

    bindRequest = bindRequest.duplicate();

    properties = new OAUTHBEARERBindRequestProperties(properties);

    assertNotNull(bindRequest.getAccessToken());
    assertEquals(bindRequest.getAccessToken(), "the-access-token");

    assertNotNull(bindRequest.getAuthorizationID());
    assertEquals(bindRequest.getAuthorizationID(),
         "dn:uid=jdoe,ou=People,dc=example,dc=com");

    assertNotNull(bindRequest.getServerAddress());
    assertEquals(bindRequest.getServerAddress(), "ds.example.com");

    assertNotNull(bindRequest.getServerPort());
    assertEquals(bindRequest.getServerPort().intValue(), 389);

    assertNotNull(bindRequest.getRequestMethod());
    assertEquals(bindRequest.getRequestMethod(), "POST");

    assertNotNull(bindRequest.getRequestPath());
    assertEquals(bindRequest.getRequestPath(), "/");

    assertNotNull(bindRequest.getRequestPostData());
    assertEquals(bindRequest.getRequestPostData(), "the-post-data");

    assertNotNull(bindRequest.getRequestQueryString());
    assertEquals(bindRequest.getRequestQueryString(), "query=string");

    assertNotNull(bindRequest.getAdditionalKeyValuePairs());
    assertFalse(bindRequest.getAdditionalKeyValuePairs().isEmpty());
    assertEquals(bindRequest.getAdditionalKeyValuePairs(),
         StaticUtils.mapOf("keyOne", "value1", "keyTwo", "value2"));

    assertNotNull(bindRequest.encodeCredentials());
    assertEquals(bindRequest.encodeCredentials(),
         new ASN1OctetString("n,a=dn:uid=3Djdoe=2Cou=3DPeople=2Cdc=3Dexample" +
              "=2Cdc=3Dcom,\u0001auth=Bearer the-access-token\u0001" +
              "host=ds.example.com\u0001port=389\u0001mthd=POST\u0001path=/" +
              "\u0001post=the-post-data\u0001qs=query=string\u0001" +
              "keyOne=value1\u0001keyTwo=value2\u0001"));

    assertNotNull(bindRequest.toString());

    final List<String> toCodeLines = new ArrayList<>();
    bindRequest.toCode(toCodeLines, "testRequestID", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior when processing a successful bind.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessSuccess()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addSASLBindHandler(new TestOAUTHBEARERInMemorySASLBindHandler());

    try (InMemoryDirectoryServer ds =  new InMemoryDirectoryServer(config))
    {
      ds.startListening();

      try (LDAPConnection conn = ds.getConnection())
      {
        final OAUTHBEARERBindResult bindResult = (OAUTHBEARERBindResult)
             assertResultCodeEquals(conn,
                  new OAUTHBEARERBindRequest("success"),
                  ResultCode.SUCCESS);

        assertNotNull(bindResult.getInitialBindResult());

        assertNull(bindResult.getFinalBindResult());

        assertNull(bindResult.getFailureDetailsObject());
      }
    }
  }



  /**
   * Tests the behavior when processing a failed bind that does not contain
   * credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessFailureWithoutCredentials()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addSASLBindHandler(new TestOAUTHBEARERInMemorySASLBindHandler());

    try (InMemoryDirectoryServer ds =  new InMemoryDirectoryServer(config))
    {
      ds.startListening();

      try (LDAPConnection conn = ds.getConnection())
      {
        final OAUTHBEARERBindResult bindResult = (OAUTHBEARERBindResult)
             assertResultCodeEquals(conn,
                  new OAUTHBEARERBindRequest("failure-without-credentials"),
                  ResultCode.INVALID_CREDENTIALS);

        assertNotNull(bindResult.getInitialBindResult());

        assertNull(bindResult.getFinalBindResult());

        assertNull(bindResult.getFailureDetailsObject());
      }
    }
  }



  /**
   * Tests the behavior when processing a failed bind that does contain
   * credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessFailureWithCredentials()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addSASLBindHandler(new TestOAUTHBEARERInMemorySASLBindHandler());

    try (InMemoryDirectoryServer ds =  new InMemoryDirectoryServer(config))
    {
      ds.startListening();

      try (LDAPConnection conn = ds.getConnection())
      {
        final OAUTHBEARERBindRequest bindRequest =
             new OAUTHBEARERBindRequest("sasl-bind-in-progress");
        assertTrue(bindRequest.getLastMessageID() < 0);

        final OAUTHBEARERBindResult bindResult = (OAUTHBEARERBindResult)
             assertResultCodeEquals(conn, bindRequest,
                  ResultCode.INVALID_CREDENTIALS);

        assertNotNull(bindResult.getInitialBindResult());

        assertNotNull(bindResult.getFinalBindResult());

        assertNotNull(bindResult.getFailureDetailsObject());

        assertNotNull(bindResult.getAuthorizationErrorCode());
        assertEquals(bindResult.getAuthorizationErrorCode(), "invalid_token");

        assertTrue(bindRequest.getLastMessageID() > 0);
      }
    }
  }
}
