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



/**
 * This package provides an API which intends to make it easy to interact with
 * directory data using Java objects.  It is primarily a persistence framework,
 * which includes the ability to convert between Java objects and LDAP entries,
 * but it also provides a means of performing LDAP operations (add, delete,
 * modify, and search) with that data.
 * <BR><BR>
 * At the heart of the LDAP persistence framework is a set of annotation types
 * that can be used to mark source code to indicate how it should be stored in
 * the LDAP directory server.  Those annotations include:
 * <UL>
 *   <LI>{@code LDAPObject} -- This annotation type is used to mark the class
 *       for objects that may be stored in an LDAP directory server.  It
 *       provides information about the structural and auxiliary object classes
 *       that should be used in the LDAP representation of the data.</LI>
 *   <LI>{@code LDAPField} -- This annotation type is used to mark fields in
 *       classes for objects that should be stored in an LDAP directory server.
 *       It provides information about the LDAP attribute that should be used to
 *       store the information for that field, and to identify constraints on
 *       how that field may be used.</LI>
 *   <LI>{@code LDAPGetter} and {@code LDAPSetter} -- These annotation
 *       types provide an alternative to the {@code LDAPField} annotation.
 *       Rather than marking fields, they should be used to mark getter and
 *       setter methods that can be used to retrieve and update the associated
 *       value.</LI>
 *   <LI>{@code LDAPDNField} -- This annotation type should be used to mark at
 *       most one field in a Java class whose value should be the DN of the LDAP
 *       entry with which the object instance is associated.</LI>
 *   <LI>{@code LDAPEntryField} -- This annotation type should be used to mark
 *       at most one field in a Java class whose value should be a read-only
 *       representation of the LDAP entry with which the object instance is
 *       associated.</LI>
 * </UL>
 * <BR><BR>
 * The {@code LDAPObjectHandler} class provides the primary interface for
 * interacting with objects of a specified type and converting between the Java
 * and LDAP representations of that data.  The {@code ObjectEncoder} class
 * provides an API that may be used to convert between Java and LDAP
 * representations for object values.
 */
package com.unboundid.ldap.sdk.persist;
