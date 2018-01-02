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
  private final AtomicReference<ResultCode> resultCodeRef;

  // The tool whose doShutdownHookProcessing method will be invoked.
  private final CommandLineTool tool;



  /**
   * Creates a new instance of this shutdown hook with the provided information.
   *
   * @param  tool           The tool whose {@code doShutdownHookProcessing}
   *                        method will be called when this shutdown hook is
   *                        invoked.
   * @param  resultCodeRef  A reference to the result code that will be returned
   *                        by the tool.
   */
  CommandLineToolShutdownHook(final CommandLineTool tool,
                              final AtomicReference<ResultCode> resultCodeRef)
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
