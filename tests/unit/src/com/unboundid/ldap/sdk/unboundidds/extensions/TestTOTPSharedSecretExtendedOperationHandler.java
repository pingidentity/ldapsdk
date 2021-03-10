/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryExtendedOperationHandler;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.matchingrules.OctetStringMatchingRule;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Base32;
import com.unboundid.util.CryptoHelper;



/**
 * This class provides an implementation of an extended operation handler that
 * can be used to add support for the generate TOTP shared secret and revoke
 * TOTP shared secret extended operations to the in-memory directory server.  It
 * supports both "normal" operation (in which the generate request will cause a
 * new secret to be generated and returned to the client, and the revoke request
 * will attempt to remove one or all secrets from a user's entry), but it also
 * supports a mode in which each type of request can return a canned response.
 */
public final class TestTOTPSharedSecretExtendedOperationHandler
       extends InMemoryExtendedOperationHandler
{
  // The extended result to return in response to the next revoke TOTP shared
  // secret request that is received.
  private final AtomicReference<ExtendedResult> nextRevokeResult;

  // The extended result to return in response to the next generate TOTP shared
  // secret request that is received.
  private final AtomicReference<GenerateTOTPSharedSecretExtendedResult>
       nextGenerateResult;



  /**
   * Creates a new instance of this extended operation handler.
   */
  public TestTOTPSharedSecretExtendedOperationHandler()
  {
    nextGenerateResult =
         new AtomicReference<GenerateTOTPSharedSecretExtendedResult>();
    nextRevokeResult = new AtomicReference<ExtendedResult>();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedOperationHandlerName()
  {
    return "Generate TOTP Shared Secret";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Arrays.asList(
         GenerateTOTPSharedSecretExtendedRequest.
              GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
         RevokeTOTPSharedSecretExtendedRequest.
              REVOKE_TOTP_SHARED_SECRET_REQUEST_OID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult processExtendedOperation(
                             final InMemoryRequestHandler handler,
                             final int messageID, final ExtendedRequest request)
  {
    final String oid = request.getOID();
    if (oid.equals(GenerateTOTPSharedSecretExtendedRequest.
             GENERATE_TOTP_SHARED_SECRET_REQUEST_OID))
    {
      final GenerateTOTPSharedSecretExtendedResult cannedResult =
           nextGenerateResult.get();
      if (cannedResult == null)
      {
        try
        {
          return doGenerate(request, handler);
        }
        catch (final LDAPException le)
        {
          return new ExtendedResult(le);
        }
      }
      {
        return cannedResult;
      }
    }
    else if (oid.equals(RevokeTOTPSharedSecretExtendedRequest.
                  REVOKE_TOTP_SHARED_SECRET_REQUEST_OID))
    {
      final ExtendedResult cannedResult = nextRevokeResult.get();
      if (cannedResult == null)
      {
        try
        {
          return doRevoke(request, handler);
        }
        catch (final LDAPException le)
        {
          return new ExtendedResult(le);
        }
      }
      {
        return cannedResult;
      }
    }
    else
    {
      return new ExtendedResult(messageID, ResultCode.UNWILLING_TO_PERFORM,
           "Unsupported OID " + oid, null, null, null, null, null);
    }
  }



  /**
   * Performs the appropriate processing for a generate TOTP shared secret
   * request.
   *
   * @param  r  The request for which to generate the result.
   * @param  h  The associated in-memory request handler.
   *
   * @return  The result generated for the request.
   *
   * @throws  LDAPException  If an unexpected problem occurs.
   */
  private static ExtendedResult doGenerate(final ExtendedRequest r,
                                           final InMemoryRequestHandler h)
          throws LDAPException
  {
    // Decode the request.
    final GenerateTOTPSharedSecretExtendedRequest request =
         new GenerateTOTPSharedSecretExtendedRequest(r);


    // Get the entry for the given authentication ID.  Also check the static
    // password if one was provided.
    final Entry authEntry = getAuthEntry(request.getAuthenticationID(),
         request.getStaticPasswordBytes(), h);


    // Generate the TOTP secret.
    final byte[] rawTOTPSecretBytes = new byte[10];
    CryptoHelper.getSecureRandom().nextBytes(rawTOTPSecretBytes);
    final String base32TOTPSecret = Base32.encode(rawTOTPSecretBytes);


    // Update the user entry.
    h.modifyEntry(authEntry.getDN(),
         Collections.singletonList(new Modification(ModificationType.ADD,
              "ds-auth-totp-shared-secret", base32TOTPSecret)));


    // Return the response.
    return new GenerateTOTPSharedSecretExtendedResult(r.getLastMessageID(),
         base32TOTPSecret);
  }



  /**
   * Performs the appropriate processing for a revoke TOTP shared secret
   * request.
   *
   * @param  r  The request for which to generate the result.
   * @param  h  The associated in-memory request handler.
   *
   * @return  The result generated for the request.
   *
   * @throws  LDAPException  If an unexpected problem occurs.
   */
  private static ExtendedResult doRevoke(final ExtendedRequest r,
                                         final InMemoryRequestHandler h)
          throws LDAPException
  {
    // Decode the request.
    final RevokeTOTPSharedSecretExtendedRequest request =
         new RevokeTOTPSharedSecretExtendedRequest(r);


    // Get the entry for the given authentication ID.  Also check the static
    // password if one was provided.
    final Entry authEntry = getAuthEntry(request.getAuthenticationID(),
         request.getStaticPasswordBytes(), h);


    // Update the entry to remove one or all of the shared secret values.
    final String totpSharedSecret = request.getTOTPSharedSecret();
    if (totpSharedSecret == null)
    {
      h.modifyEntry(authEntry.getDN(),
           Collections.singletonList(new Modification(ModificationType.REPLACE,
                "ds-auth-totp-shared-secret")));
    }
    else
    {
      h.modifyEntry(authEntry.getDN(),
           Collections.singletonList(new Modification(ModificationType.DELETE,
                "ds-auth-totp-shared-secret", totpSharedSecret)));
    }


    // Return a successful response.
    return new ExtendedResult(r.getLastMessageID(), ResultCode.SUCCESS, null,
         null, null, null, null, null);
  }



  /**
   * Retrieves the entry for the provided authentication ID.  If a static
   * password is also provided then it will be verified.
   *
   * @param  authID    The authentication ID for the target user.
   * @param  staticPW  An optional static password to be verified.
   * @param  h         The associated in-memory request handler.
   *
   * @return  The entry for the given authentication ID.
   *
   * @throws  LDAPException  If a problem is encountered during processing.
   */
  private static Entry getAuthEntry(final String authID, final byte[] staticPW,
                                    final InMemoryRequestHandler h)
          throws LDAPException
  {
    final ResultCode failureResultCode =
         (staticPW == null)
              ? ResultCode.NO_SUCH_OBJECT
              : ResultCode.INVALID_CREDENTIALS;


    // Identify the entry from the authentication ID.
    final Entry authEntry;
    if (authID == null)
    {
      final DN authDN = h.getAuthenticatedDN();
      if (authDN == null)
      {
        throw new LDAPException(failureResultCode,
             "No authentication ID specified on an unauthenticated connection");
      }

      authEntry = h.getEntry(authDN);
      if (authEntry == null)
      {
        throw new LDAPException(failureResultCode,
             "The connection is authenticated as '" + authDN +
                  "' but that entry doesn't actually exist.");
      }
    }
    else if (authID.startsWith("dn:"))
    {
      authEntry = h.getEntry(authID.substring(3));
      if (authEntry == null)
      {
        throw new LDAPException(failureResultCode,
             "No entry for authentication identity DN '" + authID.substring(3) +
                  "'.");
      }
    }
    else if (authID.startsWith("u:"))
    {
      final List<ReadOnlyEntry> entries = h.search("", SearchScope.SUB,
           Filter.createEqualityFilter("uid", authID.substring(2)));
      if (entries.isEmpty())
      {
        throw new LDAPException(failureResultCode,
             "No entry with uid '" + authID.substring(2) + "'.");
      }
      else if (entries.size() > 1)
      {
        throw new LDAPException(failureResultCode,
             entries.size() + " entries have uid '" + authID.substring(2) +
                  "'.");
      }
      authEntry = entries.get(0);
    }
    else
    {
      throw new LDAPException(failureResultCode,
           "Unrecognized authID format '" + authID + "' doesn't start with " +
                "'dn:' or 'u:'.");
    }


    // If a static password was provided, then verify it.
    if (staticPW != null)
    {
      if (! authEntry.hasAttributeValue("userPassword", staticPW,
                 OctetStringMatchingRule.getInstance()))
      {
        throw new LDAPException(ResultCode.INVALID_CREDENTIALS,
             "Wrong static password");
      }
    }


    return authEntry;
  }



  /**
   * Sets the result that should be returned for all subsequent generate TOTP
   * shared secret requests that are received.
   *
   * @param  r  The canned result to return for all subsequent generate TOTP
   *            shared secret extended requests, or {@code null} if the handler
   *            should generate an appropriate result.
   */
  public void setCannedGenerateResult(
                   final GenerateTOTPSharedSecretExtendedResult r)
  {
    nextGenerateResult.set(r);
  }



  /**
   * Sets the result that should be returned for all subsequent revoke TOTP
   * shared secret requests that are received.
   *
   * @param  r  The canned result to return for all subsequent revoke TOTP
   *            shared secret extended requests, or {@code null} if the handler
   *            should generate an appropriate result.
   */
  public void setCannedRevokeResult(final ExtendedResult r)
  {
    nextRevokeResult.set(r);
  }



  /**
   * Retrieves an in-memory directory server instance that is configured to
   * support this extended operation.  It will be listening for connections
   * on an automatically-determined connections.  It will use a base DN of
   * "dc=example,dc=com" but will not have any entries.
   *
   * @return  The in-memory directory server instance that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  public static InMemoryDirectoryServer getDSWithSupport()
         throws Exception
  {
    final Schema defaultSchema = Schema.getDefaultStandardSchema();

    final Schema sharedSecretSchema = new Schema(new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschema",
         "attributeTypes: ( 1.3.6.1.4.1.30221.2.1.896 " +
              "NAME 'ds-auth-totp-shared-secret' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 " +
              "USAGE directoryOperation " +
              "X-ORIGIN 'UnboundID Directory Server' )"));

    final Schema mergedSchema =
         Schema.mergeSchemas(defaultSchema, sharedSecretSchema);

    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.addExtendedOperationHandler(
         new TestTOTPSharedSecretExtendedOperationHandler());
    dsConfig.setSchema(mergedSchema);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsConfig);
    ds.startListening();

    return ds;
  }
}
