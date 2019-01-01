/*
 * Copyright 2011-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2019 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides an implementation of an extended operation handler.
 */
public final class TestExtendedOperationHandler
       extends InMemoryExtendedOperationHandler
{
  /**
   * Creates a new instance of this extended operation handler.
   */
  public TestExtendedOperationHandler()
  {
    // No implementation required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedOperationHandlerName()
  {
    return "Test";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Arrays.asList("1.2.3.4");
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
    return new ExtendedResult(messageID, ResultCode.SUCCESS, null,
         null, null, "1.2.3.5", null, null);
  }
}
