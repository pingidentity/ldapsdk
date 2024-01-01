/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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
package com.unboundid.ldap.matchingrules;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the policy that the {@link TelephoneNumberMatchingRule}
 * should use when comparing two values in accordance with this syntax.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum TelephoneNumberComparisonPolicy
{
  /**
   * A policy that indicates that all non-numeric characters should be ignored
   * when comparing values.
   */
  IGNORE_ALL_NON_NUMERIC_CHARACTERS,



  /**
   * A policy that indicates that only spaces and hyphens should be ignored when
   * comparing values.
   */
  IGNORE_ONLY_SPACES_AND_DASHES;



  /**
   * Normalizes the provided value in accordance with this policy.  This method
   * does not perform any validation on the provided value.
   *
   * @param  value  The value to be normalized.  It must not be {@code null}.
   *
   * @return  The normalized representation of the provided value.
   */
  @NotNull()
  public ASN1OctetString normalizeValue(@NotNull final ASN1OctetString value)
  {
    final String valueString = StaticUtils.toLowerCase(value.stringValue());
    final ByteStringBuffer buffer = new ByteStringBuffer(valueString.length());
    for (int i=0; i < valueString.length(); i++)
    {
      final char c = valueString.charAt(i);
      switch (c)
      {
        case ' ':
        case '-':
          // These will always be excluded from the normalized representation.
          break;

        case '+':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
          // These will always be included in the normalized representation.
          buffer.append(c);
          break;

        default:
          // If we only ignore dashes and spaces, then all other characters will
          // be included in the normalized representation.  Otherwise, they will
          // be excluded.
          if (this == IGNORE_ONLY_SPACES_AND_DASHES)
          {
            buffer.append(c);
          }
          break;
      }
    }

    return new ASN1OctetString(buffer.toByteArray());
  }
}
