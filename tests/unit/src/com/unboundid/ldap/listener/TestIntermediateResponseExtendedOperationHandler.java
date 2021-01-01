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
package com.unboundid.ldap.listener;



import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.IntermediateResponseProtocolOp;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;



/**
 * This class provides an implementation of an extended operation handler that
 * generates intermediate responses before the extended result.
 *
 * This class provides an implementation of an extended operation handler.
 */
public final class TestIntermediateResponseExtendedOperationHandler
       extends InMemoryExtendedOperationHandler
{
  // The number of intermediate responses to return that include a value.
  private final int numIntermediateResponsesWithValue;

  // The number of intermediate responses to return that do not include a value.
  private final int numIntermediateResponsesWithoutValue;

  // The OID for the intermediate response.
  private final String intermediateRepsonseOID;

  // The OID for the extended request.
  private final String requestOID;

  // The OID for the extended result.
  private final String resultOID;



  /**
   * Creates a new instance of this extended operation handler with the
   * provided information.
   *
   * @param  requestOID
   *              The OID for the extended request.
   * @param  intermediateResponseOID
   *              The OID for the intermediate response.
   * @param  resultOID
   *              The OID for the extended result.
   * @param  numIntermediateResponsesWithValue
   *              The number of intermediate responses to return that include a
   *              value.
   * @param  numIntermediateResponsesWithoutValue
   *              The number of intermediate responses to return that do not
   *              include a value.
   */
  public TestIntermediateResponseExtendedOperationHandler(
              final String requestOID, final String intermediateResponseOID,
              final String resultOID,
              final int numIntermediateResponsesWithValue,
              final int numIntermediateResponsesWithoutValue)
  {
    this.requestOID = requestOID;
    this.resultOID = resultOID;
    this.intermediateRepsonseOID = intermediateResponseOID;
    this.numIntermediateResponsesWithValue = numIntermediateResponsesWithValue;
    this.numIntermediateResponsesWithoutValue =
         numIntermediateResponsesWithoutValue;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedOperationHandlerName()
  {
    return "Test Intermediate Response";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Collections.singletonList(requestOID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult processExtendedOperation(
                             final InMemoryRequestHandler handler,
                             final int messageID,
                             final ExtendedRequest request)
  {
    for (int i=0; i < numIntermediateResponsesWithValue; i++)
    {
      try
      {
        handler.getClientConnection().sendIntermediateResponse(messageID,
             new IntermediateResponseProtocolOp(intermediateRepsonseOID,
                  new ASN1OctetString("Value " + (i+1))));
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        return new ExtendedResult(messageID, e.getResultCode(),
             "Unable to send an intermediate response with a value:  " +
                  StaticUtils.getExceptionMessage(e),
             null, null, resultOID, null, null);
      }
    }

    for (int i=0; i < numIntermediateResponsesWithoutValue; i++)
    {
      try
      {
        handler.getClientConnection().sendIntermediateResponse(messageID,
             new IntermediateResponseProtocolOp(intermediateRepsonseOID, null));
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        return new ExtendedResult(messageID, e.getResultCode(),
             "Unable to send an intermediate response without a value:  " +
                  StaticUtils.getExceptionMessage(e),
             null, null, resultOID, null, null);
      }
    }

    return new ExtendedResult(messageID, ResultCode.SUCCESS, null,
         null, null, resultOID, null, null);
  }
}
