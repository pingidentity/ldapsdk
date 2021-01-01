/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.Arrays;
import java.util.List;

import com.unboundid.ldap.listener.InMemoryExtendedOperationHandler;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            DeliverPasswordResetTokenExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            DeliverPasswordResetTokenExtendedResult;
import com.unboundid.util.ObjectPair;



/**
 * This class provides an implementation of an extended operation handler for
 * the in-memory directory server that claims to provide support for the
 * deliver password reset token extended operation, but really just returns a
 * bogus response.
 */
final class TestDeliverPasswordResetTokenExtendedOperationHandler
      extends InMemoryExtendedOperationHandler
{
  /**
   * Creates a new instance of this extended operation handler.
   */
  TestDeliverPasswordResetTokenExtendedOperationHandler()
  {
    // No implementation required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedOperationHandlerName()
  {
    return "Deliver Password Reset Token";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Arrays.asList(
         DeliverPasswordResetTokenExtendedRequest.
              DELIVER_PW_RESET_TOKEN_REQUEST_OID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult processExtendedOperation(
                             final InMemoryRequestHandler handler,
                             final int messageID, final ExtendedRequest request)
  {
    try
    {
      final DeliverPasswordResetTokenExtendedRequest r =
           new DeliverPasswordResetTokenExtendedRequest(request);
      if ((r.getPreferredDeliveryMechanisms() == null) ||
          r.getPreferredDeliveryMechanisms().isEmpty())
      {
        return new DeliverPasswordResetTokenExtendedResult(messageID,
             ResultCode.SUCCESS, null, null, null, "Mental Telepathy",
             null, "The password has been implanted in the recipient's brain");
      }
      else
      {
        for (final ObjectPair<String,String> p :
             r.getPreferredDeliveryMechanisms())
        {
          if (p.getFirst().equals("SMS"))
          {
            return new DeliverPasswordResetTokenExtendedResult(messageID,
                 ResultCode.SUCCESS, null, null, null, "SMS", "123-456-7890",
                 null);
          }
        }

        return new DeliverPasswordResetTokenExtendedResult(messageID,
             ResultCode.UNWILLING_TO_PERFORM,
             "No supported delivery mechanisms were requested", null, null,
             null, null, null);
      }
    }
    catch (final LDAPException le)
    {
      return new ExtendedResult(le);
    }
  }
}
