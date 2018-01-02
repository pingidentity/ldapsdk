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
package com.unboundid.ldap.sdk.persist;



import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an OID allocator implementation that will generate OIDs
 * which are equal to the lowercase name of the associated attribute type or
 * object class followed by "-oid".  This will not result in an OID that is
 * technically valid, but is accepted by several directory servers.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DefaultOIDAllocator
       extends OIDAllocator
{
  /**
   * The singleton instance of this OID allocator.
   */
  private static final DefaultOIDAllocator INSTANCE = new DefaultOIDAllocator();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4815405566303309719L;



  /**
   * Creates a new instance of this OID allocator.
   */
  private DefaultOIDAllocator()
  {
    // No implementation required.
  }



  /**
   * Retrieves the singleton instance of this OID allocator.
   *
   * @return  The singleton instance of this OID allocator.
   */
  public static DefaultOIDAllocator getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String allocateAttributeTypeOID(final String name)
  {
    return StaticUtils.toLowerCase(name) + "-oid";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String allocateObjectClassOID(final String name)
  {
    return StaticUtils.toLowerCase(name) + "-oid";
  }
}
