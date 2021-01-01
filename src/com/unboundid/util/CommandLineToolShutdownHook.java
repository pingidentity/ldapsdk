/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides an implementation of a thread that will be invoked as a
 * command-line tool shutdown hook for tools in which the
 * {@link CommandLineTool#registerShutdownHook()} method is overridden to
 * return {@code true}.  It will simply invoke the tool's
 * {@link CommandLineTool#doShutdownHookProcessing(ResultCode)} method.
 */
final class CommandLineToolShutdownHook
      extends Thread
{
  // A reference to the result code that will be returned by the tool (if set).
  @NotNull private final AtomicReference<ResultCode> resultCodeRef;

  // The tool whose doShutdownHookProcessing method will be invoked.
  @NotNull private final CommandLineTool tool;



  /**
   * Creates a new instance of this shutdown hook with the provided information.
   *
   * @param  tool           The tool whose {@code doShutdownHookProcessing}
   *                        method will be called when this shutdown hook is
   *                        invoked.
   * @param  resultCodeRef  A reference to the result code that will be returned
   *                        by the tool.
   */
  CommandLineToolShutdownHook(@NotNull final CommandLineTool tool,
       @NotNull final AtomicReference<ResultCode> resultCodeRef)
  {
    this.tool          = tool;
    this.resultCodeRef = resultCodeRef;
  }



  /**
   * Invokes the associated tool's {@code doShutdownHookProcessing} method.
   */
  @Override()
  public void run()
  {
    tool.doShutdownHookProcessing(resultCodeRef.get());
  }
}
