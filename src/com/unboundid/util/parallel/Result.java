/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * Encapsulates the input value, result, and any exception thrown by
 * {@code Processor#process()}.
 * <BR><BR>
 * This class is intended to only be used internally by the SDK.
 *
 * @param <I>  The type of the input item.
 * @param <O>  The type of the output item.
 */
@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface Result<I,O>
{
  /**
   * Return the input item that was passed into {@code Processor#process()}.
   *
   * @return  The input item.
   */
  @NotNull()
  I getInput();



  /**
   * Return the input item that was passed into {@code Processor#process()}.
   *
   * @return  The output item.  This will be {@code null} if
   *          {@code Processor#process()} returned null or threw an exception.
   */
  @Nullable()
  O getOutput();



  /**
   * Return the exception thrown by {@code Processor#process()} or {@code null}
   * if none was thrown.
   *
   * @return  The exception thrown by {@code Processor#process()} or
   *          {@code null} if none was thrown.
   */
  @Nullable()
  Throwable getFailureCause();
}
