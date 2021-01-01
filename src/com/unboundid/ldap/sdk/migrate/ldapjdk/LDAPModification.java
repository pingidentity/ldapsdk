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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that represents an LDAP modification.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the {@link Modification} class
 * should be used instead.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPModification
       implements Serializable
{
  /**
   * The modification type that indicates that one or more values should be
   * added to the target attribute.
   */
  public static final int ADD = ModificationType.ADD_INT_VALUE;



  /**
   * The modification type that indicates that one or more values should be
   * removed from the target attribute.
   */
  public static final int DELETE = ModificationType.DELETE_INT_VALUE;



  /**
   * The modification type that indicates that one or more values should be
   * replaced in target attribute.
   */
  public static final int REPLACE = ModificationType.REPLACE_INT_VALUE;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4385895404606128438L;



  // The modification object for this LDAP modification.
  @NotNull private final Modification modification;



  /**
   * Creates a new LDAP modification with the provided information.
   *
   * @param  op    The type of modification to perform.
   * @param  attr  The attribute to use for the modification.
   */
  public LDAPModification(final int op, @NotNull final LDAPAttribute attr)
  {
    modification = new Modification(ModificationType.valueOf(op),
         attr.getName(), attr.getByteValueArray());
  }



  /**
   * Creates a new LDAP modification from the provided {@link Modification}
   * object.
   *
   * @param  modification  The {@code Modification} object to use to create this
   *                       LDAP modification.
   */
  public LDAPModification(@NotNull final Modification modification)
  {
    this.modification = modification;
  }



  /**
   * Retrieves the modification type for this LDAP modification.
   *
   * @return  The modification type for this LDAP modification.
   */
  public int getOp()
  {
    return modification.getModificationType().intValue();
  }



  /**
   * Retrieves the attribute to include in this modification.
   *
   * @return  The attribute to include in this modification.
   */
  @NotNull()
  public LDAPAttribute getAttribute()
  {
    return new LDAPAttribute(modification.getAttribute());
  }



  /**
   * Retrieves a {@link Modification} object that is the equivalent of this LDAP
   * modification.
   *
   * @return  A {@code Modification} object that is the equivalent of this LDAP
   *          modification.
   */
  @NotNull()
  public Modification toModification()
  {
    return modification;
  }



  /**
   * Retrieves a string representation of this LDAP modification.
   *
   * @return  A string representation of this LDAP modification.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return modification.toString();
  }
}
