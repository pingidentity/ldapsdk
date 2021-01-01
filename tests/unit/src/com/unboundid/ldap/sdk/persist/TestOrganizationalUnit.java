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



import com.unboundid.ldap.sdk.ReadOnlyEntry;



/**
 * This class provides an implementation of an object that can be used to
 * represent organizationalUnit objects in the directory.  It is intended only
 * for testing purposes, and exposes only a subset of the attributes and has
 * a different set of required attributes.
 */
@LDAPObject(structuralClass="organizationalUnit",
     defaultParentDN="dc=example,dc=com")
public class TestOrganizationalUnit
{
  // A copy of the directory entry associated with this object.
  @LDAPEntryField()
  private ReadOnlyEntry ldapEntry;

  // The description for the organizational unit.  It will be considered
  // required for testing purposes.
  @LDAPField(attribute="description", requiredForDecode=true,
       requiredForEncode=true)
  private String description;

  // The name for the organizational unit.
  @LDAPField(attribute="ou", inRDN=true, filterUsage=FilterUsage.ALWAYS_ALLOWED,
       requiredForDecode=true, requiredForEncode=true)
  private String name;

  // The value of the entryUUID operational attribute.
  @LDAPField()
  private String entryUUID;



  /**
   * Creates a new organizational unit object without any fields set.
   */
  public TestOrganizationalUnit()
  {
    // No implementation required.
  }



  /**
   * Retrieves the name for this organizational unit.
   *
   * @return  The name for this organizational unit.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Sets the name for this organizational unit.
   *
   * @param  name  The name for this organizational unit.
   */
  public void setName(final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the description for this organizational unit.
   *
   * @return  The description for this organizational unit.
   */
  public String getDescription()
  {
    return description;
  }



  /**
   * Sets the description for this organizational unit.
   *
   * @param  description  The description for this organizational unit.
   */
  public void setDescription(final String description)
  {
    this.description = description;
  }



  /**
   * Retrieves the entryUUID value for this organizational unit.
   *
   * @return  The entryUUID value for this organizational unit.
   */
  public String getEntryUUID()
  {
    return entryUUID;
  }



  /**
   * Retrieves a read-only copy of the LDAP entry associated with this object,
   * if it is available.  It will only be available if this object has been
   * read from or written to the directory server.
   *
   * @return  A read-only copy of the LDAP entry associated with this object,
   *          or {@code null} if it is not available.
   */
  public ReadOnlyEntry getLDAPEntry()
  {
    return ldapEntry;
  }



  /**
   * Sets a read-only copy of the LDAP entry associated with this object, if it
   * is available.  It will only be available if this object has been read from
   * or written to the directory server.
   *
   * @param  ldapEntry  A read-only copy of the LDAP entry associated with this
   *                    object, or {@code null} if it is not available.
   */
  public void setLDAPEntry(final ReadOnlyEntry ldapEntry)
  {
    this.ldapEntry = ldapEntry;
  }
}
