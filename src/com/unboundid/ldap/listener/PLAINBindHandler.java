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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class defines a SASL bind handler which may be used to provide support
 * for the SASL PLAIN mechanism (as defined in RFC 4616) in the in-memory
 * directory server.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PLAINBindHandler
       extends InMemorySASLBindHandler
{
  /**
   * Creates a new instance of this SASL bind handler.
   */
  public PLAINBindHandler()
  {
    // No initialization is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return "PLAIN";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public BindResult processSASLBind(
                         @NotNull final InMemoryRequestHandler handler,
                         final int messageID, @NotNull final DN bindDN,
                         @Nullable final ASN1OctetString credentials,
                         @NotNull final List<Control> controls)
  {
    // Process the provided request controls.
    final Map<String,Control> controlMap;
    try
    {
      controlMap = RequestControlPreProcessor.processControls(
           LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST, controls);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return  new BindResult(messageID, le.getResultCode(),
           le.getMessage(), le.getMatchedDN(), le.getReferralURLs(),
           le.getResponseControls());
    }


    // Parse the credentials, which should be in the form:
    //      [authzid] UTF8NUL authcid UTF8NUL passwd
    if (credentials == null)
    {
      return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
           ERR_PLAIN_BIND_NO_CREDENTIALS.get(), null, null, null);
    }

    int firstNullPos  = -1;
    int secondNullPos = -1;
    final byte[] credBytes = credentials.getValue();
    for (int i=0; i < credBytes.length; i++)
    {
      if (credBytes[i] == 0x00)
      {
        if (firstNullPos < 0)
        {
          firstNullPos = i;
        }
        else
        {
          secondNullPos = i;
          break;
        }
      }
    }

    if (secondNullPos < 0)
    {
      return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
           ERR_PLAIN_BIND_MALFORMED_CREDENTIALS.get(), null, null, null);
    }


    // There must have been at least an authentication identity.  Verify that it
    // is valid.
    final String authzID;
    final String authcID = StaticUtils.toUTF8String(credBytes, (firstNullPos+1),
         (secondNullPos-firstNullPos-1));
    if (firstNullPos == 0)
    {
      authzID = null;
    }
    else
    {
      authzID = StaticUtils.toUTF8String(credBytes, 0, firstNullPos);
    }

    DN authDN;
    try
    {
      authDN = handler.getDNForAuthzID(authcID);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
           le.getMessage(), le.getMatchedDN(), le.getReferralURLs(),
           le.getResponseControls());
    }


    // Verify that the password is correct.
    final byte[] bindPWBytes = new byte[credBytes.length - secondNullPos - 1];
    System.arraycopy(credBytes, secondNullPos+1, bindPWBytes, 0,
         bindPWBytes.length);

    final boolean passwordValid;
    if (authDN.isNullDN())
    {
      // For an anonymous bind, the password must be empty, and no authorization
      // ID may have been provided.
      passwordValid = ((bindPWBytes.length == 0) && (authzID == null));
    }
    else
    {
      // Determine the password for the target user, which may be an actual
      // entry or be included in the additional bind credentials.
      final Entry authEntry = handler.getEntry(authDN);
      if (authEntry == null)
      {
        final byte[] userPWBytes = handler.getAdditionalBindCredentials(authDN);
        passwordValid =  Arrays.equals(bindPWBytes, userPWBytes);
      }
      else
      {
        final List<InMemoryDirectoryServerPassword> passwordList =
             handler.getPasswordsInEntry(authEntry,
                  new ASN1OctetString(bindPWBytes));
        passwordValid = (! passwordList.isEmpty());
      }
    }

    if (! passwordValid)
    {
      return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
           null, null, null, null);
    }


    // The server doesn't really distinguish between authID and authzID, so
    // if an authzID was provided then we'll just behave as if the user
    // specified as the authzID had bound.
    if (authzID != null)
    {
      try
      {
        authDN = handler.getDNForAuthzID(authzID);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
             le.getMessage(), le.getMatchedDN(), le.getReferralURLs(),
             le.getResponseControls());
      }
    }

    handler.setAuthenticatedDN(authDN);
    final Control[] responseControls;
    if (controlMap.containsKey(AuthorizationIdentityRequestControl.
             AUTHORIZATION_IDENTITY_REQUEST_OID))
    {
      if (authDN == null)
      {
        responseControls = new Control[]
        {
          new AuthorizationIdentityResponseControl("")
        };
      }
      else
      {
        responseControls = new Control[]
        {
          new AuthorizationIdentityResponseControl("dn:" + authDN.toString())
        };
      }
    }
    else
    {
      responseControls = null;
    }

    return new BindResult(messageID, ResultCode.SUCCESS, null, null, null,
         responseControls);
  }
}
