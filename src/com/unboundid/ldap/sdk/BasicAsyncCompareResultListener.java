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
package com.unboundid.ldap.sdk;



import java.io.Serializable;

import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a basic implementation of the
 * {@link AsyncCompareResultListener} interface that will merely set the
 * result object to a local variable that can be accessed through a getter
 * method.  It provides a listener that may be easily used when processing
 * an asynchronous compare operation using the {@link AsyncRequestID} as a
 * {@code java.util.concurrent.Future} object.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class BasicAsyncCompareResultListener
       implements AsyncCompareResultListener, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8119461093491566432L;



  // The compare result that has been received for the associated compare
  // operation.
  @Nullable private volatile CompareResult compareResult;



  /**
   * Creates a new instance of this class for use in processing a single
   * compare operation.  A single basic async compare result listener object
   * may not be used for multiple operations.
   */
  public BasicAsyncCompareResultListener()
  {
    compareResult = null;
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void compareResultReceived(@NotNull final AsyncRequestID requestID,
                                    @NotNull final CompareResult compareResult)
  {
    this.compareResult = compareResult;
  }



  /**
   * Retrieves the result that has been received for the associated asynchronous
   * compare operation, if it has been received.
   *
   * @return  The result that has been received for the associated asynchronous
   *          compare operation, or {@code null} if no response has been
   *          received yet.
   */
  @Nullable()
  public CompareResult getCompareResult()
  {
    return compareResult;
  }
}
