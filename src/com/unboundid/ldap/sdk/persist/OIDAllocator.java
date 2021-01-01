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
package com.unboundid.ldap.sdk.persist;



import java.io.Serializable;

import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a mechanism that can be used for generating object
 * identifiers (OIDs) for use in attribute type and object class definitions
 * constructed for use in representing an object in the directory.
 * <BR><BR>
 * Note that OIDs generated are not necessarily required to be valid, nor are
 * they required to be unique.  As such, OIDs included in generated attribute
 * type and object class definitions may need to be edited before the
 * definitions can be added to the directory server.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class OIDAllocator
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2031217984148568974L;



  /**
   * Allocates an OID for the attribute type with the specified name.
   *
   * @param  name  The name of the attribute type for which to generate an OID.
   *               It must not be {@code null} or empty.
   *
   * @return  The OID to use for the attribute type definition.
   */
  @NotNull()
  public abstract String allocateAttributeTypeOID(@NotNull String name);



  /**
   * Allocates an OID for the object class with the specified name.
   *
   * @param  name  The name of the object class for which to generate an OID.
   *               It must not be {@code null} or empty.
   *
   * @return  The OID to use for the object class definition.
   */
  @NotNull()
  public abstract String allocateObjectClassOID(@NotNull String name);
}
