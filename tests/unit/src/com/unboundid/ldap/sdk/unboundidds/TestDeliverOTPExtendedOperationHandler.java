/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2018 Ping Identity Corporation
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
            DeliverOneTimePasswordExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            DeliverOneTimePasswordExtendedResult;



/**
 * This class provides an implementation of an extended operation handler for
 * the in-memory directory server that claims to provide support for the
 * deliver one-time password extended operation, but really just returns a
 * bogus response.
 */
final class TestDeliverOTPExtendedOperationHandler
      extends InMemoryExtendedOperationHandler
{
  /**
   * Creates a new instance of this extended operation handler.
   */
  TestDeliverOTPExtendedOperationHandler()
  {
    // No implementation required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedOperationHandlerName()
  {
    return "Deliver One-Time Password";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Arrays.asList(
         DeliverOneTimePasswordExtendedRequest.DELIVER_OTP_REQUEST_OID);
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
      final DeliverOneTimePasswordExtendedRequest r =
           new DeliverOneTimePasswordExtendedRequest(request);
      if ((r.getPreferredDeliveryMechanisms() == null) ||
          r.getPreferredDeliveryMechanisms().isEmpty())
      {
        return new DeliverOneTimePasswordExtendedResult(messageID,
             ResultCode.SUCCESS, null, null, null, "Mental Telepathy",
             "uid=test,ou=People,dc=example,dc=com", null,
             "The password has been implanted in the recipient's brain");
      }
      else if (r.getPreferredDeliveryMechanisms().contains("SMS"))
      {
        return new DeliverOneTimePasswordExtendedResult(messageID,
             ResultCode.SUCCESS, null, null, null, "SMS",
             "uid=test,ou=People,dc=example,dc=com", "123-456-7890", null);
      }
      else
      {
        return new DeliverOneTimePasswordExtendedResult(messageID,
             ResultCode.UNWILLING_TO_PERFORM,
             "No supported delivery mechanisms were requested", null, null,
             null, null, null, null);
      }
    }
    catch (final LDAPException le)
    {
      return new ExtendedResult(le);
    }
  }
}
