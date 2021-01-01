/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.transformations;



import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotNull;



/**
 * This class provides an implementation of an entry that has a pre-encoded
 * LDIF representation.
 */
final class PreEncodedLDIFEntry
      extends Entry
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6342345192453693575L;



  // The bytes that comprise the LDIF representation of this entry.
  @NotNull private final byte[] ldifBytes;



  /**
   * Creates a new pre-encoded LDIF entry with the provided information.
   *
   * @param  entry      The entry to wrap.
   * @param  ldifBytes  The bytes that comprise the pre-encoded LDIF
   *                    representation of the entry.
   */
  PreEncodedLDIFEntry(@NotNull final Entry entry,
                      @NotNull final byte[] ldifBytes)
  {
    super(entry);

    this.ldifBytes = ldifBytes;
  }



  /**
   * Retrieves the bytes that comprise the pre-encoded LDIF representation of
   * the entry.
   *
   * @return  The bytes that comprise the pre-encoded LDIF representation of the
   *          entry.
   */
  @NotNull()
  byte[] getLDIFBytes()
  {
    return ldifBytes;
  }
}
