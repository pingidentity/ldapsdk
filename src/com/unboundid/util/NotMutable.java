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
 * This annotation type is used to indicate that instances of the associated
 * class may not be altered after they have been created.  Note that this may or
 * may not indicate strict immutability, as some classes marked with this
 * annotation type may have their internal state altered in some way that is not
 * externally visible.  In addition, the following caveats must be observed for
 * classes containing this annotation type, and for all other classes in the
 * LDAP SDK:
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
 * </UL>
 * <BR><BR>
 * It will only be used for classes which are primarily used as data structures
 * and will not be included in classes whose primary purpose is something other
 * than as a data type.  It will also not be used for interfaces, abstract
 * classes, or enums.
 * <BR><BR>
 * This annotation type will appear in the generated Javadoc documentation for
 * classes and interfaces that include it.
 *
 * @see  Mutable
 */
@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE })
public @interface NotMutable
{
}
