/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.security.MessageDigest;

import com.unboundid.util.ByteStringBuffer;



/**
 * This class provides an instance of a {@code MessageDigest} that simply
 * passes through the source content without alteration.
 */
public final class TestPassThroughMessageDigest
       extends MessageDigest
{
  // The byte-string buffer that holds the data being digested.
  private final ByteStringBuffer buffer;



  /**
   * Creates a new instance of this message digest.
   */
  public TestPassThroughMessageDigest()
  {
    super("CLEAR");

    buffer = new ByteStringBuffer();
  }



  /**
   * Retrieves the length of the message digest.  This method always returns
   * zero since the digest length isn't fixed.
   *
   * @return  Zero, indicating that the digest length isn't fixed.
   */
  @Override()
  protected int engineGetDigestLength()
  {
    return 0;
  }



  /**
   * Adds the provided byte of input to the digest engine.
   *
   * @param  input  The byte of input to add to the digest engine.
   */
  @Override()
  protected void engineUpdate(final byte input)
  {
    buffer.append(input);
  }



  /**
   * Adds the provided data to the digest engine.
   *
   * @param  input   The byte array containing the input.
   * @param  offset  The position in the array at which the data begins.
   * @param  length  The number of bytes of data to take.
   */
  @Override()
  protected void engineUpdate(final byte[] input, final int offset,
                              final int length)
  {
    buffer.append(input, offset, length);
  }



  /**
   * Computes the digest based on the information provided so far.  This will
   * also reset the digest.
   *
   * @return  The computed message digest.
   */
  @Override()
  protected byte[] engineDigest()
  {
    final byte[] digestBytes = buffer.toByteArray();
    buffer.clear();
    return digestBytes;
  }



  /**
   * Resets the message digest back to its original state.
   */
  @Override()
  protected void engineReset()
  {
    buffer.clear();
  }
}
