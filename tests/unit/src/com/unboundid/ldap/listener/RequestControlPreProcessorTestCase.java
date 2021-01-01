/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.DontUseCopyRequestControl;
import com.unboundid.ldap.sdk.controls.DraftLDUPSubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.PermissiveModifyRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadRequestControl;
import com.unboundid.ldap.sdk.controls.PreReadRequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.controls.RFC3672SubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortRequestControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.controls.SortKey;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.controls.TransactionSpecificationRequestControl;
import com.unboundid.ldap.sdk.controls.VirtualListViewRequestControl;



/**
 * This class provides a set of test cases for the request control
 * pre-processor.
 */
public final class RequestControlPreProcessorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the assertion request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAssertionControl()
         throws Exception
  {
    final String oid = AssertionRequestControl.ASSERTION_REQUEST_OID;

    final Control vc = new AssertionRequestControl("(objectClass=*)", true);
    final Control vn = new AssertionRequestControl("(objectClass=*)", false);
    final Control ic = new Control(oid, true);
    final Control in = new Control(oid, false);

    final Class<?> c = AssertionRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the authorization identity control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthorizationIdentityControl()
         throws Exception
  {
    final String oid =
         AuthorizationIdentityRequestControl.AUTHORIZATION_IDENTITY_REQUEST_OID;

    final Control vc = new AuthorizationIdentityRequestControl(true);
    final Control vn = new AuthorizationIdentityRequestControl(false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = AuthorizationIdentityRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the don't use copy request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDontUseCopyControl()
         throws Exception
  {
    final String oid = DontUseCopyRequestControl.DONT_USE_COPY_REQUEST_OID;

    final Control vc = new DontUseCopyRequestControl();
    final Control vn = new Control(oid, false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = DontUseCopyRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the manage DSA IT control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testManageDsaITControl()
         throws Exception
  {
    final String oid = ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID;

    final Control vc = new ManageDsaITRequestControl(true);
    final Control vn = new ManageDsaITRequestControl(false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = ManageDsaITRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the permissive modify control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPermissiveModifyControl()
         throws Exception
  {
    final String oid =
         PermissiveModifyRequestControl.PERMISSIVE_MODIFY_REQUEST_OID;

    final Control vc = new PermissiveModifyRequestControl(true);
    final Control vn = new PermissiveModifyRequestControl(false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = PermissiveModifyRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the post-read control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPostReadControl()
         throws Exception
  {
    final String oid = PostReadRequestControl.POST_READ_REQUEST_OID;

    final Control vc = new PostReadRequestControl(true);
    final Control vn = new PostReadRequestControl(false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = PostReadRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the pre-read control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPreReadControl()
         throws Exception
  {
    final String oid = PreReadRequestControl.PRE_READ_REQUEST_OID;

    final Control vc = new PreReadRequestControl(true);
    final Control vn = new PreReadRequestControl(false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = PreReadRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the proxied auth v1 control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthV1Control()
         throws Exception
  {
    final String oid = ProxiedAuthorizationV1RequestControl.
         PROXIED_AUTHORIZATION_V1_REQUEST_OID;

    final Control vc = new ProxiedAuthorizationV1RequestControl("cn=test");
    final Control vn = new Control(oid, false, vc.getValue());
    final Control ic = new Control(oid, true);
    final Control in = new Control(oid, false);

    final Class<?> c = ProxiedAuthorizationV1RequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the proxied auth v2 control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthV2Control()
         throws Exception
  {
    final String oid = ProxiedAuthorizationV2RequestControl.
         PROXIED_AUTHORIZATION_V2_REQUEST_OID;

    final Control vc = new ProxiedAuthorizationV2RequestControl("dn:cn=test");
    final Control vn = new Control(oid, false, vc.getValue());
    final Control ic = new Control(oid, true);
    final Control in = new Control(oid, false);

    final Class<?> c = ProxiedAuthorizationV2RequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the server-side sort control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSideSortControl()
         throws Exception
  {
    final String oid =
         ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID;

    final Control vc = new ServerSideSortRequestControl(true,
         new SortKey("sn"), new SortKey("givenName"), new SortKey("uid"));
    final Control vn = new ServerSideSortRequestControl(false,
         new SortKey("sn"), new SortKey("givenName"), new SortKey("uid"));
    final Control ic = new Control(oid, true);
    final Control in = new Control(oid, false);

    final Class<?> c = ServerSideSortRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimplePagedResultsControl()
         throws Exception
  {
    final String oid = SimplePagedResultsControl.PAGED_RESULTS_OID;

    final Control vc = new SimplePagedResultsControl(10, true);
    final Control vn = new SimplePagedResultsControl(10, false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = SimplePagedResultsControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the subentries control as described in
   * draft-ietf-ldup-subentry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDraftLDUPSubentriesControl()
         throws Exception
  {
    final String oid = DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID;

    final Control vc = new DraftLDUPSubentriesRequestControl(true);
    final Control vn = new DraftLDUPSubentriesRequestControl(false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = DraftLDUPSubentriesRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the subentries control as described in RFC 3672.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRFC3672LDUPSubentriesControl()
         throws Exception
  {
    final String oid = RFC3672SubentriesRequestControl.SUBENTRIES_REQUEST_OID;

    final Control vc = new RFC3672SubentriesRequestControl(true, true);
    final Control vn = new RFC3672SubentriesRequestControl(false,false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = RFC3672SubentriesRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the subtree delete control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubtreeDeleteControl()
         throws Exception
  {
    final String oid = SubtreeDeleteRequestControl.SUBTREE_DELETE_REQUEST_OID;

    final Control vc = new SubtreeDeleteRequestControl(true);
    final Control vn = new SubtreeDeleteRequestControl(false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    final Class<?> c = SubtreeDeleteRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the transaction specification request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransactionSpecificationControl()
         throws Exception
  {
    final String oid = TransactionSpecificationRequestControl.
         TRANSACTION_SPECIFICATION_REQUEST_OID;

    final Control vc = new TransactionSpecificationRequestControl(
         new ASN1OctetString("0"));
    final Control vn = new Control(oid, false, vc.getValue());
    final Control ic = new Control(oid, true);
    final Control in = new Control(oid, false);

    final Class<?> c = TransactionSpecificationRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for the virtual list view request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVirtualListViewControl()
         throws Exception
  {
    final String oid =
         VirtualListViewRequestControl.VIRTUAL_LIST_VIEW_REQUEST_OID;

    final Control vc =
         new VirtualListViewRequestControl(0, 0, 9, 0, null, true);
    final Control vn =
         new VirtualListViewRequestControl(0, 0, 9, 0, null, false);
    final Control ic = new Control(oid, true, new ASN1OctetString("foo"));
    final Control in = new Control(oid, false, new ASN1OctetString("foo"));

    // The VLV control requires the server-side sort control.
    final ServerSideSortRequestControl sortRequest =
         new ServerSideSortRequestControl(new SortKey("uid"));

    final Class<?> c = VirtualListViewRequestControl.class;

    // Test with acceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      // A valid critical control.
      ensureControlHandled(opType, Arrays.asList(vc, sortRequest), oid, c);

      // A valid non-critical control.
      ensureControlHandled(opType, Arrays.asList(vn, sortRequest), oid, c);

      // Multiple instances of the control.
      ensureException(opType, Arrays.asList(vc, vn, sortRequest));

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic, sortRequest));

      // Malformed non-critical control.
      ensureException(opType, Arrays.asList(in, sortRequest));

      // The VLV control without the server-side sort control.
      ensureException(opType, Arrays.asList(vc));

      // The VLV control and the simple paged results control.
      ensureException(opType, Arrays.asList(vc, sortRequest,
           new SimplePagedResultsControl(10)));
    }

    // Test with unacceptable operation types.
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A valid critical control.
      ensureException(opType, Arrays.asList(vc));

      // A valid non-critical control.
      ensureControlIgnored(opType, Arrays.asList(vn), oid);

      // Malformed critical control.
      ensureException(opType, Arrays.asList(ic));

      // Malformed non-critical control.
      ensureControlIgnored(opType, Arrays.asList(in), oid);
    }
  }



  /**
   * Provides test coverage for a completely unsupported control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnsupportedControl()
         throws Exception
  {
    final String oid = "1.2.3.4";

    final Control cc = new Control(oid, true);
    final Control nc = new Control(oid, false);

    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST))
    {
      // A critical control.
      ensureException(opType, Arrays.asList(cc));

      // A non-critical control.
      ensureControlIgnored(opType, Arrays.asList(nc), oid);
    }
  }



  /**
   * Provides test coverage for the case in which a request includes both the
   * proxied auth v1 and v2 controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleProxyControls()
         throws Exception
  {
    for (final byte opType : Arrays.asList(
              LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
              LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST))
    {
      ensureException(opType, Arrays.<Control>asList(
           new ProxiedAuthorizationV1RequestControl("cn=test"),
           new ProxiedAuthorizationV2RequestControl("dn:cn=test")));
    }
  }



  /**
   * Ensures that processing can be performed correctly with the provided
   * information.
   *
   * @param  t  The operation type to use for the test.
   * @param  l  The list of controls to use for the test.
   * @param  o  The OID of the expected control.
   * @param  c  The class of the expected control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void ensureControlHandled(final byte t,
                                           final List<Control> l,
                                           final String o, final Class<?> c)
          throws Exception
  {
    final Map<String,Control> m =
         RequestControlPreProcessor.processControls(t, l);

    final Control ctl = m.get(o);
    assertNotNull(ctl);

    if (c != null)
    {
      assertEquals(ctl.getClass(), c);
    }
  }



  /**
   * Ensures that processing can be performed correctly with the provided
   * information.
   *
   * @param  t  The operation type to use for the test.
   * @param  l  The list of controls to use for the test.
   * @param  o  The OID of the expected control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void ensureControlIgnored(final byte t, final List<Control> l,
                                           final String o)
          throws Exception
  {
    final Map<String,Control> m =
         RequestControlPreProcessor.processControls(t, l);

    assertFalse(m.containsKey(o));
  }



  /**
   * Ensures that attempting to process with the provided information throws
   * an exception.
   *
   * @param  t  The operation type to use for the test.
   * @param  l  The list of controls to use for the test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void ensureException(final byte t, final List<Control> l)
          throws Exception
  {
    try
    {
      RequestControlPreProcessor.processControls(t, l);
      fail("Expected an exception during processing.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }
}
