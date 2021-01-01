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
import java.util.ArrayList;
import java.util.Iterator;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that represents a set of LDAP
 * modifications.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, an array or collection of
 * {@link com.unboundid.ldap.sdk.Modification} objects should be used instead.
 */
@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPModificationSet
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1789929614205832665L;



  // The list of modifications.
  @NotNull private final ArrayList<LDAPModification> mods;



  /**
   * Creates an empty set of modifications.
   */
  public LDAPModificationSet()
  {
    mods = new ArrayList<>(1);
  }



  /**
   * Adds a modification to this modification set.
   *
   * @param  op    The modification type for the modification.
   * @param  attr  The attribute for the modification.
   */
  public void add(final int op, @NotNull final LDAPAttribute attr)
  {
    mods.add(new LDAPModification(op, attr));
  }



  /**
   * Retrieves the LDAP modification at the specified position in this
   * modification set.
   *
   * @param  index  The position of the LDAP modification to retrieve.
   *
   * @return  The requested modification.
   *
   * @throws  IndexOutOfBoundsException  If the provided index is invalid.
   */
  @NotNull()
  public LDAPModification elementAt(final int index)
         throws IndexOutOfBoundsException
  {
    return mods.get(index);
  }



  /**
   * Removes the LDAP modification at the specified position in this
   * modification set.
   *
   * @param  index  The position of the LDAP modification to remove.
   *
   * @throws  IndexOutOfBoundsException  If the provided index is invalid.
   */
  public void removeElementAt(final int index)
         throws IndexOutOfBoundsException
  {
    mods.remove(index);
  }



  /**
   * Removes the first LDAP modification in this set targeting the specified
   * attribute.
   *
   * @param  name  The name of the attribute to remove.
   */
  public void remove(@NotNull final String name)
  {
    final Iterator<LDAPModification> iterator = mods.iterator();
    while (iterator.hasNext())
    {
      final LDAPModification mod = iterator.next();
      if (mod.getAttribute().getName().equalsIgnoreCase(name))
      {
        iterator.remove();
        return;
      }
    }
  }



  /**
   * Retrieves the number of modifications in this modification set.
   *
   * @return  The number of modifications in this modification set.
   */
  public int size()
  {
    return mods.size();
  }



  /**
   * Retrieves the contents of this set as an array of LDAP modifications.
   *
   * @return  An array of the LDAP modifications contained in this set.
   */
  @NotNull()
  public LDAPModification[] toArray()
  {
    final LDAPModification[] modArray = new LDAPModification[mods.size()];
    return mods.toArray(modArray);
  }



  /**
   * Retrieves a string representation of this modification set.
   *
   * @return  A string representation of this modification set.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return mods.toString();
  }
}
