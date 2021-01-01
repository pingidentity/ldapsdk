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



import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;



/**
 * This annotation type may be used to indicate the level of thread safety for a
 * class or method.  Any class or interface which does not include the
 * {@code ThreadSafety} annotation should be assumed to be not threadsafe unless
 * otherwise specified in the documentation for that class or interface.
 * <BR><BR>
 * If the {@code ThreadSafety} annotation is applied to a method, then it will
 * override the class-level annotation for the scope of that method.  That is,
 * if a class is declared to be {@code ThreadSafetyLevel.MOSTLY_NOT_THREADSAFE}
 * but a method within that class is declared to be
 * {@code ThreadSafetyLevel.METHOD_THREADSAFE}, then that method may be invoked
 * concurrently by multiple threads against the same instance.  If a class is
 * declared to be {@code ThreadSafetyLevel.MOSTLY_THREADSAFE} but a method
 * within that class is declared to be
 * {@code ThreadSafetyLevel.METHOD_NOT_THREADSAFE}, then that method must not be
 * invoked on an instance while any other thread is attempting to access the
 * same instance.  Methods within a class may only be annotated with either the
 * {@code ThreadSafetyLevel.METHOD_THREADSAFE} or
 * {@code ThreadSafetyLevel.METHOD_NOT_THREADSAFE} level, and only if the class
 * is annotated with one of the {@code ThreadSafetyLevel.MOSTLY_THREADSAFE},
 * {@code ThreadSafetyLevel.MOSTLY_NOT_THREADSAFE}, or
 * {@code ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE} level.  Classes annotated
 * with either the {@code ThreadSafetyLevel.COMPLETELY_THREADSAFE} or
 * {@code ThreadSafetyLevel.NOT_THREADSAFE} levels must not provide alternate
 * method-level {@code ThreadSafety} annotations.
 * <BR><BR>
 * Note that there are some caveats regarding thread safety and immutability of
 * elements in the LDAP SDK that are true regardless of the stated thread safety
 * level:
 * <UL>
 *   <LI>
 *     If an array is provided as an argument to a constructor or a method, then
 *     that array must not be referenced or altered by the caller at any time
 *     after that point unless it is clearly noted that it is acceptable to do
 *     so.
 *     <BR><BR>
 *   </LI>
 *
 *   <LI>
 *     If an array is returned by a method, then the contents of that array must
 *     not be altered unless it is clearly noted that it is acceptable to do so.
 *     <BR><BR>
 *   </LI>
 *
 *   <LI>
 *     If a method is intended to alter the state of an argument (e.g.,
 *     appending to a {@code StringBuilder} or {@code ByteBuffer} or
 *     {@code ByteStringBuffer}, reading from a {@code Reader} or an
 *     {@code InputStream}, or writing to a {@code Writer} or
 *     {@code OutputStream}), then that object provided as an argument must not
 *     be accessed by any other thread while that method is active unless it is
 *     clearly noted that it is acceptable to do so.
 *     <BR><BR>
 *   </LI>
 *
 *   <LI>
 *     Unless otherwise noted, public static methods may be assumed to be
 *     threadsafe independent of the thread safety level for the class that
 *     contains them.
 *     <BR><BR>
 *   </LI>
 * </UL>
 */
@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD })
public @interface ThreadSafety
{
  /**
   * The thread safety level for the associated class, interface, enum, or
   * method.
   *
   * @return  The thread safety level for the associated class, interface, enum,
   *          or method.
   */
  @NotNull()
  ThreadSafetyLevel level();
}
