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
 * Encapsulates the input value, result, and any exception thrown by
 * {@code Processor#process()}.
 * <p/>
 * This class is intended to only be used internally by the SDK.
 *
 * @param <I>  The type of the input item.
 * @param <O>  The type of the output item.
 */
@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface Result<I, O>
{
  /**
   * Return the input item that was passed into {@code Processor#process()}.
   *
   * @return  The input item.
   */
  I getInput();



  /**
   * Return the input item that was passed into {@code Processor#process()}.
   *
   * @return  The output item.  This will be {@code null} if
   *          {@code Processor#process()} returned null or threw an exception.
   */
  O getOutput();



  /**
   * Return the exception thrown by {@code Processor#process()} or {@code null}
   * if none was thrown.
   *
   * @return  The exception thrown by {@code Processor#process()} or
   *          {@code null} if none was thrown.
   */
  Throwable getFailureCause();
}
