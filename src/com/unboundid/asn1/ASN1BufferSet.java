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
package com.unboundid.asn1;



import java.io.Serializable;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
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
  @NotNull
  private final ASN1Buffer buffer;

  // The position in the ASN.1 buffer at which the first set value begins.
  private final int valueStartPos;



  /**
   * Creates a new instance of this class for the provided ASN.1 buffer.
   *
   * @param  buffer  The ASN.1 buffer with which this object will be associated.
   */
  ASN1BufferSet(@NotNull final ASN1Buffer buffer)
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
