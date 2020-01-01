/*
 * Copyright 2018-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018-2020 Ping Identity Corporation
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



import java.util.UUID;



/**
 * This class defines a value pattern component whose values will be randomly
 * generated UUIDs as described in
 * <A HREF="http://www.ietf.org/rfc/rfc4122.txt">RFC 4122</A>.
 */
final class UUIDValuePatternComponent
      extends ValuePatternComponent
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5006381863724555309L;



  /**
   * Creates a new instance of this UUID value pattern component.
   */
  UUIDValuePatternComponent()
  {
    // No initialization is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  void append(final StringBuilder buffer)
  {
    buffer.append(UUID.randomUUID().toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  boolean supportsBackReference()
  {
    return true;
  }
}
