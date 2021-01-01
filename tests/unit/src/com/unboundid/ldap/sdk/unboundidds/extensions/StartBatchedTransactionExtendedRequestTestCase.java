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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.unboundidds.controls.
            BatchedTransactionSpecificationRequestControl;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.controls.PostReadRequestControl;



/**
 * This class provides a set of test cases for the
 * StartBatchedTransactionExtendedRequest class.  It also provides coverage for
 * the StartBatchedTransactionExtendedResponse and
 * EndBatchedTransactionExtendedRequest classes, as well as testing
 * transactional functionality.
 */
public class StartBatchedTransactionExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    StartBatchedTransactionExtendedRequest r =
         new StartBatchedTransactionExtendedRequest();
    r = new StartBatchedTransactionExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.1");

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

    StartBatchedTransactionExtendedRequest r =
         new StartBatchedTransactionExtendedRequest(controls);
    r = new StartBatchedTransactionExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.1");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the third constructor with a generic request containing a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3WithValue()
         throws Exception
  {
    new StartBatchedTransactionExtendedRequest(
             new ExtendedRequest("1.2.3.4", new ASN1OctetString("foo")));
  }



  /**
   * Tests the process of creating a transaction, including multiple operations
   * as part of that transaction, and then committing it.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCommitTransaction()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    RootDSE rootDSE = conn.getRootDSE();
    if ((rootDSE == null) ||
        (! rootDSE.supportsExtendedOperation(
                StartBatchedTransactionExtendedRequest.
                     START_BATCHED_TRANSACTION_REQUEST_OID)))
    {
      conn.close();
      return;
    }

    StartBatchedTransactionExtendedResult startTxnResult =
         (StartBatchedTransactionExtendedResult)
         conn.processExtendedOperation(
              new StartBatchedTransactionExtendedRequest());

    assertEquals(startTxnResult.getResultCode(), ResultCode.SUCCESS);

    ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);

    assertNotNull(startTxnResult.toString());

    Control[] controls =
    {
      new BatchedTransactionSpecificationRequestControl(txnID),
      new PostReadRequestControl(true)
    };

    AddRequest addRequest =
         new AddRequest(getTestBaseDN(), getBaseEntryAttributes(), controls);
    conn.add(addRequest);

    Modification[] mods =
    {
      new Modification(ModificationType.REPLACE, "description", "foo")
    };

    ModifyRequest modifyRequest =
         new ModifyRequest(getTestBaseDN(), mods, controls);
    conn.modify(modifyRequest);

    EndBatchedTransactionExtendedResult endTxnResult =
         (EndBatchedTransactionExtendedResult)
         conn.processExtendedOperation(
              new EndBatchedTransactionExtendedRequest(txnID, true));

    assertEquals(endTxnResult.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(endTxnResult.getOperationResponseControls());
    assertFalse(endTxnResult.getOperationResponseControls().isEmpty());

    assertNotNull(endTxnResult.toString());

    conn.delete(getTestBaseDN());

    conn.close();
  }



  /**
   * Tests the process of creating a transaction, including multiple operations
   * as part of that transaction, and then aborting it.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbortTransaction()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    RootDSE rootDSE = conn.getRootDSE();
    if ((rootDSE == null) ||
        (! rootDSE.supportsExtendedOperation(
                StartBatchedTransactionExtendedRequest.
                     START_BATCHED_TRANSACTION_REQUEST_OID)))
    {
      conn.close();
      return;
    }

    StartBatchedTransactionExtendedResult startTxnResult =
         (StartBatchedTransactionExtendedResult)
         conn.processExtendedOperation(
              new StartBatchedTransactionExtendedRequest());

    assertEquals(startTxnResult.getResultCode(), ResultCode.SUCCESS);

    ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);

    assertNotNull(startTxnResult.toString());

    Control[] controls =
    {
      new BatchedTransactionSpecificationRequestControl(txnID)
    };

    AddRequest addRequest =
         new AddRequest(getTestBaseDN(), getBaseEntryAttributes(), controls);
    conn.add(addRequest);

    Modification[] mods =
    {
      new Modification(ModificationType.REPLACE, "description", "foo")
    };

    ModifyRequest modifyRequest =
         new ModifyRequest(getTestBaseDN(), mods, controls);
    conn.modify(modifyRequest);

    ExtendedResult endTxnResult = conn.processExtendedOperation(
         new EndBatchedTransactionExtendedRequest(txnID, false));

    assertEquals(endTxnResult.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(endTxnResult.toString());

    try
    {
      assertNull(conn.getEntry(getTestBaseDN()));
    }
    finally
    {
      conn.close();
    }
  }
}
