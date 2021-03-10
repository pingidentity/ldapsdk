/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.extensions;



import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases for the StartTLSExtendedRequest
 * class.
 */
public class StartTLSExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    StartTLSExtendedRequest r = new StartTLSExtendedRequest();
    r = new StartTLSExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.1466.20037");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    StartTLSExtendedRequest r = new StartTLSExtendedRequest(controls);
    r = new StartTLSExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.1466.20037");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the third constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    SSLContext sslContext =
         CryptoHelper.getSSLContext(SSLUtil.getDefaultSSLProtocol());
    sslContext.init(null, null, null);

    StartTLSExtendedRequest r = new StartTLSExtendedRequest(sslContext);
    r = new StartTLSExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.1466.20037");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fourth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SSLContext sslContext =
         CryptoHelper.getSSLContext(SSLUtil.getDefaultSSLProtocol());
    sslContext.init(null, null, null);

    StartTLSExtendedRequest r =
         new StartTLSExtendedRequest(sslContext, controls);
    r = new StartTLSExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.1466.20037");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fifth constructor with a generic request containing a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor5WithValue()
         throws Exception
  {
    new StartTLSExtendedRequest(
             new ExtendedRequest("1.2.3.4", new ASN1OctetString("foo")));
  }



  /**
   * Tests the ability to communicate with a Directory Server using a connection
   * secured with StartTLS.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTLSCommunicationWithSSLContext()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    try
    {
      RootDSE rootDSE = conn.getRootDSE();
      if (! rootDSE.supportsExtendedOperation(
                 StartTLSExtendedRequest.STARTTLS_REQUEST_OID))
      {
        return;
      }

      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      SSLContext sslContext = sslUtil.createSSLContext();

      StartTLSExtendedRequest request = new StartTLSExtendedRequest(sslContext);
      ExtendedResult result = conn.processExtendedOperation(request);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);

      if (result.getOID() != null)
      {
        assertEquals(result.getOID(), "1.3.6.1.4.1.1466.20037");
      }

      assertNull(result.getValue());

      rootDSE = conn.getRootDSE();
      assertNotNull(rootDSE);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to communicate with a Directory Server using a connection
   * secured with StartTLS.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTLSCommunicationWithSocketFactory()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    try
    {
      RootDSE rootDSE = conn.getRootDSE();
      if (! rootDSE.supportsExtendedOperation(
                 StartTLSExtendedRequest.STARTTLS_REQUEST_OID))
      {
        return;
      }

      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();

      StartTLSExtendedRequest request =
           new StartTLSExtendedRequest(sslSocketFactory);
      ExtendedResult result = conn.processExtendedOperation(request);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);

      if (result.getOID() != null)
      {
        assertEquals(result.getOID(), "1.3.6.1.4.1.1466.20037");
      }

      assertNull(result.getValue());

      rootDSE = conn.getRootDSE();
      assertNotNull(rootDSE);
    }
    finally
    {
      conn.close();
    }
  }
}
