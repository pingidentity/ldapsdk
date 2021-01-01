/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



/**
 * This enumeration defines a set of thread safety levels that may be used to
 * indicate whether the associated code is safe to be accessed concurrently
 * by multiple threads.
 */
public enum ThreadSafetyLevel
{
  /**
   * The associated code is completely threadsafe and may be accessed
   * concurrently by any number of threads, subject to the constraints described
   * in the {@link ThreadSafety} documentation.
   */
  COMPLETELY_THREADSAFE,



  /**
   * The associated code is mostly threadsafe, but there may be some methods
   * which are not safe to be invoked when multiple threads are accessing an
   * instance concurrently.  The class-level documentation for a class including
   * this thread safety level should include comments indicating which methods
   * are not threadsafe, and those methods should also be marked with their own
   * {@code ThreadSafety} annotations using the {@link #METHOD_NOT_THREADSAFE}
   * level.
   */
  MOSTLY_THREADSAFE,



  /**
   * The associated code is mostly not threadsafe, but there may be some methods
   * which are safe to be invoked concurrently by multiple threads.  The
   * class-level documentation for a class including this thread safety level
   * should include comments indicating which methods are threadsafe, and those
   * methods should also be marked with their own {@code ThreadSafety}
   * annotations using the {@link #METHOD_THREADSAFE} level.
   */
  MOSTLY_NOT_THREADSAFE,



  /**
   * The associated code is not threadsafe.  Unless otherwise noted, multiple
   * threads may not attempt to invoke methods on the same instance of objects
   * of this type without external synchronization.
   */
  NOT_THREADSAFE,



  /**
   * Methods declared in the associated interface or abstract class must be
   * threadsafe in classes which implement that interface or extend that
   * abstract class.  No guarantees will be made about the thread safety of
   * other methods contained in that class which are not declared in the parent
   * interface or superclass.
   */
  INTERFACE_THREADSAFE,



  /**
   * Methods declared in the associated interface or abstract class are not
   * required to be threadsafe and classes which call them must not rely on the
   * ability to concurrently invoke those methods on the same object instance
   * without any external synchronization.
   */
  INTERFACE_NOT_THREADSAFE,



  /**
   * The associated method may be considered threadsafe and may be invoked
   * concurrently by multiple threads, subject to the constraints described in
   * the {@link ThreadSafety} documentation, and in any additional notes
   * contained in the method-level javadoc.
   */
  METHOD_THREADSAFE,



  /**
   * The associated method may not be considered threadsafe and should not be
   * invoked concurrently by multiple threads.
   */
  METHOD_NOT_THREADSAFE;



  /**
   * Retrieves the thread safety level with the specified name.
   *
   * @param  name  The name of the thread safety level to retrieve.  It must not
   *               be {@code null}.
   *
   * @return  The requested thread safety level, or {@code null} if no such
   *          level is defined.
   */
  @Nullable()
  public static ThreadSafetyLevel forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "completelythreadsafe":
      case "completely-threadsafe":
      case "completely_threadsafe":
        return COMPLETELY_THREADSAFE;
      case "mostlythreadsafe":
      case "mostly-threadsafe":
      case "mostly_threadsafe":
        return MOSTLY_THREADSAFE;
      case "mostlynotthreadsafe":
      case "mostly-not-threadsafe":
      case "mostly_not_threadsafe":
        return MOSTLY_NOT_THREADSAFE;
      case "notthreadsafe":
      case "not-threadsafe":
      case "not_threadsafe":
        return NOT_THREADSAFE;
      case "interfacethreadsafe":
      case "interface-threadsafe":
      case "interface_threadsafe":
        return INTERFACE_THREADSAFE;
      case "interfacenotthreadsafe":
      case "interface-not-threadsafe":
      case "interface_not_threadsafe":
        return INTERFACE_NOT_THREADSAFE;
      case "methodthreadsafe":
      case "method-threadsafe":
      case "method_threadsafe":
        return METHOD_THREADSAFE;
      case "methodnotthreadsafe":
      case "method-not-threadsafe":
      case "method_not_threadsafe":
        return METHOD_NOT_THREADSAFE;
      default:
        return null;
    }
  }
}
