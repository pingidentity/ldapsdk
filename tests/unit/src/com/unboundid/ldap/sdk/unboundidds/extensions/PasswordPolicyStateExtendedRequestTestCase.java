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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.NoSuchElementException;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * PasswordPolicyStateExtendedRequest class.
 */
public class PasswordPolicyStateExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with no operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NoOps()
         throws Exception
  {
    String userDN = "uid=test.user,ou=People,dc=example,dc=com";
    PasswordPolicyStateExtendedRequest extendedRequest =
         new PasswordPolicyStateExtendedRequest(userDN);
    extendedRequest = new PasswordPolicyStateExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.4.1.30221.1.6.1");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getUserDN(), userDN);

    assertNotNull(extendedRequest.getOperations());
    assertEquals(extendedRequest.getOperations().length, 0);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 0);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the first constructor with a single operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1SingleOp()
         throws Exception
  {
    String userDN = "uid=test.user,ou=People,dc=example,dc=com";
    PasswordPolicyStateExtendedRequest extendedRequest =
         new PasswordPolicyStateExtendedRequest(userDN,
                  PasswordPolicyStateOperation.
                       createSetAccountDisabledStateOperation(true));
    extendedRequest = new PasswordPolicyStateExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.4.1.30221.1.6.1");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getUserDN(), userDN);

    assertNotNull(extendedRequest.getOperations());
    assertEquals(extendedRequest.getOperations().length, 1);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 0);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the first constructor with multiple operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1MultipleOps()
         throws Exception
  {
    String userDN = "uid=test.user,ou=People,dc=example,dc=com";
    PasswordPolicyStateExtendedRequest extendedRequest =
         new PasswordPolicyStateExtendedRequest(userDN,
                  PasswordPolicyStateOperation.
                       createSetAccountDisabledStateOperation(true),
                  PasswordPolicyStateOperation.
                       createSetPasswordResetStateOperation(true));
    extendedRequest = new PasswordPolicyStateExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.4.1.30221.1.6.1");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getUserDN(), userDN);

    assertNotNull(extendedRequest.getOperations());
    assertEquals(extendedRequest.getOperations().length, 2);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 0);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the second constructor with no operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoOps()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    String userDN = "uid=test.user,ou=People,dc=example,dc=com";
    PasswordPolicyStateExtendedRequest extendedRequest =
         new PasswordPolicyStateExtendedRequest(userDN, controls);
    extendedRequest = new PasswordPolicyStateExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.4.1.30221.1.6.1");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getUserDN(), userDN);

    assertNotNull(extendedRequest.getOperations());
    assertEquals(extendedRequest.getOperations().length, 0);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 2);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the second constructor with a single operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleOp()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    String userDN = "uid=test.user,ou=People,dc=example,dc=com";
    PasswordPolicyStateExtendedRequest extendedRequest =
         new PasswordPolicyStateExtendedRequest(userDN, controls,
                  PasswordPolicyStateOperation.
                       createSetAccountDisabledStateOperation(true));
    extendedRequest = new PasswordPolicyStateExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.4.1.30221.1.6.1");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getUserDN(), userDN);

    assertNotNull(extendedRequest.getOperations());
    assertEquals(extendedRequest.getOperations().length, 1);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 2);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the second constructor with multiple operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleOps()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    String userDN = "uid=test.user,ou=People,dc=example,dc=com";
    PasswordPolicyStateExtendedRequest extendedRequest =
         new PasswordPolicyStateExtendedRequest(userDN, controls,
                  PasswordPolicyStateOperation.
                       createSetAccountDisabledStateOperation(true),
                  PasswordPolicyStateOperation.
                       createSetPasswordResetStateOperation(true));
    extendedRequest = new PasswordPolicyStateExtendedRequest(extendedRequest);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "1.3.6.1.4.1.30221.1.6.1");

    assertNotNull(extendedRequest.getValue());

    assertEquals(extendedRequest.getUserDN(), userDN);

    assertNotNull(extendedRequest.getOperations());
    assertEquals(extendedRequest.getOperations().length, 2);

    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 2);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());
  }



  /**
   * Tests the third constructor with a generic request containing no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NoValue()
         throws Exception
  {
    new PasswordPolicyStateExtendedRequest(new ExtendedRequest("1.2.3.4"));
  }



  /**
   * Tests the third constructor with a generic request containing an invalid
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3InvalidValue()
         throws Exception
  {
    new PasswordPolicyStateExtendedRequest(
             new ExtendedRequest("1.2.3.4", new ASN1OctetString("foo")));
  }



  /**
   * Tests the third constructor with a generic request containing an empty
   * value sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3EmptyValueSequence()
         throws Exception
  {
    new PasswordPolicyStateExtendedRequest(new ExtendedRequest("1.2.3.4",
             new ASN1OctetString(new ASN1Sequence().encode())));
  }



  /**
   * Tests the third constructor with a generic request containing an invalid
   * value sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3InvalidValueSequence()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString("foo"),
      new ASN1OctetString("bar")
    };

    new PasswordPolicyStateExtendedRequest(new ExtendedRequest("1.2.3.4",
             new ASN1OctetString(new ASN1Sequence(elements).encode())));
  }



  /**
   * Tests the ability to process a password policy state request and response
   * over protocol using a request with no operations (which should be a "get
   * all" request).
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendGetAllRequest()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String userDN = "uid=test.user," + getTestBaseDN();

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.add("dn: " + userDN,
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");

    try
    {
      PasswordPolicyStateExtendedRequest request =
           new PasswordPolicyStateExtendedRequest(userDN);
      PasswordPolicyStateExtendedResult result = request.process(conn, 1);

      assertNotNull(result);

      assertEquals(result.getResultCode(), ResultCode.SUCCESS);

      assertNotNull(result.getValue());

      assertEquals(new DN(result.getUserDN()), new DN(userDN));

      for (PasswordPolicyStateOperation o : result.getOperations())
      {
        int opType = o.getOperationType();

        assertNotNull(result.getOperation(opType));

        try
        {
          result.getBooleanValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getGeneralizedTimeValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getGeneralizedTimeValues(opType);
        } catch (Exception e) {}

        try
        {
          result.getIntValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getStringValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getStringValues(opType);
        } catch (Exception e) {}
      }

      assertNotNull(result.getStringValue(
           PasswordPolicyStateOperation.OP_TYPE_GET_PW_POLICY_DN));

      int invalidOpType = 12345;
      assertNull(result.getOperation(invalidOpType));
      assertNull(result.getStringValue(invalidOpType));
      assertNull(result.getStringValues(invalidOpType));
      assertNull(result.getGeneralizedTimeValue(invalidOpType));
      assertNull(result.getGeneralizedTimeValues(invalidOpType));

      try
      {
        result.getBooleanValue(invalidOpType);
        fail("Expected an exception from getBooleanValue(invalidOpType)");
      } catch (NoSuchElementException nsee) {}

      try
      {
        result.getIntValue(invalidOpType);
        fail("Expected an exception from getIntValue(invalidOpType)");
      } catch (NoSuchElementException nsee) {}

      assertNotNull(result.toString());
    }
    finally
    {
      try
      {
        conn.delete(userDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
    }
  }



  /**
   * Tests the ability to process a password policy state request and response
   * over protocol using a request with a single operation.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendOneOperation()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String userDN = "uid=test.user," + getTestBaseDN();

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.add("dn: " + userDN,
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");

    try
    {
      PasswordPolicyStateExtendedRequest request =
           new PasswordPolicyStateExtendedRequest(userDN,
                    PasswordPolicyStateOperation.
                         createGetPasswordPolicyDNOperation());
      PasswordPolicyStateExtendedResult result = request.process(conn, 1);

      assertNotNull(result);

      assertEquals(result.getResultCode(), ResultCode.SUCCESS);

      assertNotNull(result.getValue());

      assertEquals(new DN(result.getUserDN()), new DN(userDN));

      for (PasswordPolicyStateOperation o : result.getOperations())
      {
        int opType = o.getOperationType();

        assertNotNull(result.getOperation(opType));

        try
        {
          result.getBooleanValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getGeneralizedTimeValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getGeneralizedTimeValues(opType);
        } catch (Exception e) {}

        try
        {
          result.getIntValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getStringValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getStringValues(opType);
        } catch (Exception e) {}
      }

      assertNotNull(result.getStringValue(
           PasswordPolicyStateOperation.OP_TYPE_GET_PW_POLICY_DN));

      int invalidOpType = 12345;
      assertNull(result.getOperation(invalidOpType));
      assertNull(result.getStringValue(invalidOpType));
      assertNull(result.getStringValues(invalidOpType));
      assertNull(result.getGeneralizedTimeValue(invalidOpType));
      assertNull(result.getGeneralizedTimeValues(invalidOpType));

      try
      {
        result.getBooleanValue(invalidOpType);
        fail("Expected an exception from getBooleanValue(invalidOpType)");
      } catch (NoSuchElementException nsee) {}

      try
      {
        result.getIntValue(invalidOpType);
        fail("Expected an exception from getIntValue(invalidOpType)");
      } catch (NoSuchElementException nsee) {}

      assertNotNull(result.toString());
    }
    finally
    {
      try
      {
        conn.delete(userDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
    }
  }



  /**
   * Tests the ability to process a password policy state request and response
   * over protocol using a request with multiple operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendMultipleOperations()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String userDN = "uid=test.user," + getTestBaseDN();

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.add("dn: " + userDN,
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");

    try
    {
      PasswordPolicyStateExtendedRequest request =
           new PasswordPolicyStateExtendedRequest(userDN,
                    PasswordPolicyStateOperation.
                         createGetPasswordPolicyDNOperation(),
                    PasswordPolicyStateOperation.
                         createClearPasswordResetStateOperation());
      PasswordPolicyStateExtendedResult result = request.process(conn, 1);

      assertNotNull(result);

      assertEquals(result.getResultCode(), ResultCode.SUCCESS);

      assertNotNull(result.getValue());

      assertEquals(new DN(result.getUserDN()), new DN(userDN));

      for (PasswordPolicyStateOperation o : result.getOperations())
      {
        int opType = o.getOperationType();

        assertNotNull(result.getOperation(opType));

        try
        {
          result.getBooleanValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getGeneralizedTimeValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getGeneralizedTimeValues(opType);
        } catch (Exception e) {}

        try
        {
          result.getIntValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getStringValue(opType);
        } catch (Exception e) {}

        try
        {
          result.getStringValues(opType);
        } catch (Exception e) {}
      }

      assertNotNull(result.getStringValue(
           PasswordPolicyStateOperation.OP_TYPE_GET_PW_POLICY_DN));

      int invalidOpType = 12345;
      assertNull(result.getOperation(invalidOpType));
      assertNull(result.getStringValue(invalidOpType));
      assertNull(result.getStringValues(invalidOpType));
      assertNull(result.getGeneralizedTimeValue(invalidOpType));
      assertNull(result.getGeneralizedTimeValues(invalidOpType));

      try
      {
        result.getBooleanValue(invalidOpType);
        fail("Expected an exception from getBooleanValue(invalidOpType)");
      } catch (NoSuchElementException nsee) {}

      try
      {
        result.getIntValue(invalidOpType);
        fail("Expected an exception from getIntValue(invalidOpType)");
      } catch (NoSuchElementException nsee) {}

      assertNotNull(result.toString());
    }
    finally
    {
      try
      {
        conn.delete(userDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
    }
  }
}
