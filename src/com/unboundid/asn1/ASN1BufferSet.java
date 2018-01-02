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
package com.unboundid.asn1;



import java.io.Serializable;

import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure which is used in the course of writing
 * an ASN.1 set to an ASN.1 buffer.  It keeps track of the position at which the
 * set value begins so that the appropriate length may be inserted
 * after all embedded elements have been added.  The {@link #end} method must be
 * called after all elements have been added to ensure that the length is
 * properly computed and inserted into the associated buffer.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ASN1BufferSet
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6686782295672518084L;



  // The ASN.1 buffer with which the set is associated.
  private final ASN1Buffer buffer;

  // The position in the ASN.1 buffer at which the first set value begins.
  private final int valueStartPos;



  /**
   * Creates a new instance of this class for the provided ASN.1 buffer.
   *
   * @param  buffer  The ASN.1 buffer with which this object will be associated.
   */
  ASN1BufferSet(final ASN1Buffer buffer)
  {
    this.buffer = buffer;

    valueStartPos = buffer.length();
  }



  /**
   * Updates the associated ASN.1 buffer to indicate that all sequence elements
   * have been added and that the appropriate length should be inserted.
   */
  public void end()
  {
    buffer.endSequenceOrSet(valueStartPos);
  }
}
