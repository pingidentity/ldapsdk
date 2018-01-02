/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
package com.unboundid.util.parallel;



import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * Processes the result of an invocation of {@code Processor#process()}.
 * <p/>
 * When used in the AsynchronousParallelProcessor class, implementing classes
 * do not have to be thread-safe--only a single thread will invoke the
 * {@code processResult} method at a time.
 * <p/>
 * This class is intended to only be used internally by the SDK.
 */
@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface ResultProcessor<I, O>
{
  /**
   * Processes the result of an invocation of {@code Processor#process()}.
   * This method will be called in order for each result item.
   *
   * @param result  The result of an invocation of {@code Processor#process()}.
   *
   * @throws Exception  If there is any Exception during processing.
   *                    Implementing classes should throw an Exception only if
   *                    all processing by the AsynchronousParallelProcessor
   *                    should be aborted.
   */
  void processResult(Result<I, O> result)
       throws Exception;
}
