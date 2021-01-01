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



import com.unboundid.util.NotNull;



/**
 * This interface defines a set of methods that all async helper classes will
 * implement.
 */
interface CommonAsyncHelper
          extends ResponseAcceptor
{
  /**
   * Retrieves the async request ID created for the associated operation.
   *
   * @return  The async request ID created for the associated operation.
   */
  @NotNull()
  AsyncRequestID getAsyncRequestID();



  /**
   * Retrieves the connection with which the request is associated.
   *
   * @return  The connection with which the request is associated.
   */
  @NotNull()
  LDAPConnection getConnection();



  /**
   * Retrieves the time (in nanoseconds) at which the associated helper was
   * created.
   *
   * @return  The time (in nanoseconds) at which the associated helper was
   *          created.
   */
  long getCreateTimeNanos();



  /**
   * Retrieves the operation type for the associated operation.
   *
   * @return  The operation type for the associated operation.
   */
  @NotNull()
  OperationType getOperationType();
}
