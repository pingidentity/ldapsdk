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
package com.unboundid.ldap.sdk.examples;



import java.io.File;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.logging.FileHandler;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.AccessLogRequestHandler;
import com.unboundid.ldap.listener.LDAPListener;
import com.unboundid.ldap.listener.LDAPListenerConfig;
import com.unboundid.ldap.listener.TestRequestHandler;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.CompareResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.IntermediateResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.sdk.AsyncRequestID;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.util.NullOutputStream;



/**
 * This class provides a set of test cases for the LDAPDebugger class.
 */
public class LDAPDebuggerTestCase
       extends LDAPSDKTestCase
{
  // A connection to the debugger.
  private LDAPConnection conn;

  // The debugger that will be used for the tests.
  private LDAPDebugger debugger;

  // The LDAP listener that will serve as the target directory server.
  private LDAPListener listener;



  /**
   * Create the listener that will be used for this class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final File debuggerLogFile = createTempFile();
    debuggerLogFile.delete();

    final File codeLogFile = createTempFile();
    codeLogFile.delete();

    final File listenerLogFile = createTempFile();
    listenerLogFile.delete();

    final AccessLogRequestHandler requestHandler = new AccessLogRequestHandler(
         new FileHandler(listenerLogFile.getAbsolutePath()),
         new TestRequestHandler());

    final LDAPListenerConfig config = new LDAPListenerConfig(0, requestHandler);
    listener = new LDAPListener(config);
    listener.startListening();

    final int listenerPort = listener.getListenPort();

    debugger =new LDAPDebugger(null, null);
    assertEquals(
         debugger.runTool(
              "--hostname", "localhost",
              "--port", String.valueOf(listenerPort),
              "--outputFile", debuggerLogFile.getAbsolutePath(),
              "--codeLogFile", codeLogFile.getAbsolutePath()),
         ResultCode.SUCCESS);

    conn = new LDAPConnection("localhost",
         debugger.getListener().getListenPort());

    TestRequestHandler.setControls(
         new Control("4.3.2.1", true, new ASN1OctetString("x")),
         new Control("4.3.2.2", false, new ASN1OctetString("y")));
  }



  /**
   * Performs the necessary cleanup after running these test cases.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    conn.close();
    debugger.shutDown();
    listener.shutDown(true);
  }



  /**
   * Provides general test coverage for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void provideGeneralTestCoverage()
         throws Exception
  {
    final LDAPDebugger tool = new LDAPDebugger(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Provides test coverage for the abandon operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandon()
         throws Exception
  {
    final AsyncRequestID requestID =
         InternalSDKHelper.createAsyncRequestID(1, null);
    conn.abandon(requestID);
  }



  /**
   * Provides test coverage for a successful add operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulAdd()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new AddResponseProtocolOp(0, null, null, null));

    final AddRequest r = new AddRequest(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    r.addControl(new Control("1.2.3.4"));
    conn.add(r);
  }



  /**
   * Provides test coverage for a failed add operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailedAdd()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new AddResponseProtocolOp(32, "dc=example,dc=com", "msg",
              Arrays.asList("ldap://server1.example.com/dc=example,dc=com",
                   "ldap://server2.example.com/dc=example,dc=com")));

    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Provides test coverage for a successful simple bind operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulSimpleBind()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new BindResponseProtocolOp(0, null, null, null, null));

    final SimpleBindRequest r = new SimpleBindRequest(
         "uid=admin,dc=example,dc=com", "password", new Control("1.2.3.4"));
    conn.bind(r);
  }



  /**
   * Provides test coverage for a failed simple bind operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailedSimpleBind()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new BindResponseProtocolOp(49, null, null, null,
              new ASN1OctetString("foo")));

    conn.bind("uid=admin,dc=example,dc=com", "password");
  }



  /**
   * Provides test coverage for a failed SASL PLAIN bind operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailedSASLPLAINBind()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new BindResponseProtocolOp(32, "dc=example,dc=com", "msg",
              Arrays.asList("ldap://server1.example.com/dc=example,dc=com",
                   "ldap://server2.example.com/dc=example,dc=com"),
              new ASN1OctetString("foo")));

    conn.bind(new PLAINBindRequest("u:admin", "wrong",
         new ManageDsaITRequestControl(),
         new AuthorizationIdentityRequestControl()));
  }



  /**
   * Provides test coverage for a successful compare operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulCompare()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new CompareResponseProtocolOp(6, null, null, null));

    final CompareRequest r =
         new CompareRequest("dc=example,dc=com", "foo", "bar");
    r.addControl(new Control("1.2.3.4"));
    conn.compare(r);
  }



  /**
   * Provides test coverage for a failed compare operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailedCompare()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new CompareResponseProtocolOp(32, "dc=example,dc=com", "msg",
              Arrays.asList("ldap://server1.example.com/dc=example,dc=com",
                   "ldap://server2.example.com/dc=example,dc=com")));

    conn.compare("dc=example,dc=com", "foo", "bar");
  }



  /**
   * Provides test coverage for a successful delete operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulDelete()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new DeleteResponseProtocolOp(0, null, null, null));

    final DeleteRequest r = new DeleteRequest("dc=example,dc=com");
    r.addControl(new Control("1.2.3.4"));
    conn.delete(r);
  }



  /**
   * Provides test coverage for a failed delete operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailedDelete()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new DeleteResponseProtocolOp(32, "dc=example,dc=com", "msg",
              Arrays.asList("ldap://server1.example.com/dc=example,dc=com",
                   "ldap://server2.example.com/dc=example,dc=com")));

    conn.delete("dc=example,dc=com");
  }



  /**
   * Provides test coverage for a successful extended operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulExtendedOperation()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new ExtendedResponseProtocolOp(0, null, null, null, null, null));


    final ExtendedRequest r = new ExtendedRequest("1.2.3.4",
         new ASN1OctetString("foo"), new Control[] { new Control("1.2.3.5") });
    conn.processExtendedOperation(r);
  }



  /**
   * Provides test coverage for a failed extended operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedExtendedOperation()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new ExtendedResponseProtocolOp(32, "dc=example,dc=com", "msg",
              Arrays.asList("ldap://server1.example.com/dc=example,dc=com",
                   "ldap://server2.example.com/dc=example,dc=com"),
              "1.2.3.5", new ASN1OctetString("baz")));

    TestRequestHandler.setReturnIntermediateResponses(
         new IntermediateResponseProtocolOp("5.6.7.8",
              new ASN1OctetString("a")),
         new IntermediateResponseProtocolOp("5.6.7.9",
              new ASN1OctetString("b")));

    try
    {
      conn.processExtendedOperation("1.2.3.4",
           new ASN1OctetString("bar"));
    }
    finally
    {
      TestRequestHandler.setReturnIntermediateResponses();
      TestRequestHandler.setControls();
    }
  }



  /**
   * Provides test coverage for a successful modify operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulModify()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new ModifyResponseProtocolOp(0, null, null, null));

    final ModifyRequest r = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "delete: description",
         "description: foo",
         "-",
         "add: description",
         "description: bar");
    r.addControl(new Control("1.2.3.4"));
    conn.modify(r);
  }



  /**
   * Provides test coverage for a failed modify operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailedModify()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new ModifyResponseProtocolOp(32, "dc=example,dc=com", "msg",
              Arrays.asList("ldap://server1.example.com/dc=example,dc=com",
                   "ldap://server2.example.com/dc=example,dc=com")));

    conn.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "delete: description",
         "description: foo",
         "-",
         "add: description",
         "description: bar");
  }



  /**
   * Provides test coverage for a successful modify DN operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulModifyDN()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new ModifyDNResponseProtocolOp(0, null, null, null));

    final ModifyDNRequest r = new ModifyDNRequest("ou=People,dc=example,dc=com",
         "ou=Users", true, "o=example.com");
    r.addControl(new Control("1.2.3.4"));
    conn.modifyDN(r);
  }



  /**
   * Provides test coverage for a failed modify DN operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailedModifyDN()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new ModifyDNResponseProtocolOp(32, "dc=example,dc=com", "msg",
              Arrays.asList("ldap://server1.example.com/dc=example,dc=com",
                   "ldap://server2.example.com/dc=example,dc=com")));

    conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true,
         "o=example.com");
  }



  /**
   * Provides test coverage for a successful search operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulSearch()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new SearchResultDoneProtocolOp(0, null, null, null));

    TestRequestHandler.setReturnEntries(
         new SearchResultEntryProtocolOp("dc=example,dc=com",
              Arrays.asList(new Attribute("objectClass", "top", "domain"),
                   new Attribute("dc", "example"))));

    TestRequestHandler.setReturnReferences(
         new SearchResultReferenceProtocolOp(Arrays.asList(
              "ldap://server1.example.com/dc=example,dc=com",
              "ldap://server2.example.com/dc=example,dc=com")));

    try
    {
      final SearchRequest r = new SearchRequest("dc=example,dc=com",
           SearchScope.BASE, "(objectClass=*)");
      r.addControl(new Control("1.2.3.4"));
      conn.search(r);
    }
    finally
    {
      TestRequestHandler.setReturnEntries();
      TestRequestHandler.setReturnReferences();
    }
  }



  /**
   * Provides test coverage for a failed search operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailedSearch()
         throws Exception
  {
    TestRequestHandler.setReturnOp(
         new SearchResultDoneProtocolOp(32, "dc=example,dc=com", "msg",
              Arrays.asList("ldap://server1.example.com/dc=example,dc=com",
                   "ldap://server2.example.com/dc=example,dc=com")));

    conn.search("dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)", "*", "+");
  }



  /**
   * Provides test coverage for the ability to get help information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHelp()
         throws Exception
  {
    final PrintStream systemOut = System.out;
    final PrintStream systemErr = System.err;

    try
    {
      System.setOut(NullOutputStream.getPrintStream());
      System.setErr(NullOutputStream.getPrintStream());

      LDAPDebugger.main(new String[] { "--help" });
    }
    finally
    {
      System.setOut(systemOut);
      System.setErr(systemErr);
    }
  }
}
