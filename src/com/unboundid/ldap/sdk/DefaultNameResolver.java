/*
 * Copyright 2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a default implementation of a {@link NameResolver} that
 * simply uses the JVM-default name resolution functionality.
 */
@ThreadSafety(level= ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DefaultNameResolver
       extends NameResolver
{
  /**
   * The singleton instance of this default name resolver.
   */
  private static final DefaultNameResolver INSTANCE = new DefaultNameResolver();



  /**
   * Prevents this class from being externally instantiated.
   */
  private DefaultNameResolver()
  {
    super();
  }



  /**
   * Retrieves the singleton instance of this default name resolver.
   *
   * @return  The singleton instance of this default name resolver.
   */
  public static DefaultNameResolver getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("DefaultNameResolver()");
  }
}
