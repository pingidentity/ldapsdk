/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
  METHOD_NOT_THREADSAFE
}
