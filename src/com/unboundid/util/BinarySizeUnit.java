/*
 * Copyright 2023-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2024 Ping Identity Corporation
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
 * Copyright (C) 2023-2024 Ping Identity Corporation
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



import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This enum defines a set of size units that can be used to represent data
 * sizes in varying units (bytes, kilobytes, megabytes, gigabytes, etc.).  This
 * class uses binary-based values rather than decimal-based values, so each
 * unit is 1024 times larger than the previous (for example, one kilobyte is
 * interpreted as 1024 bytes rather than 1000 bytes).
 */
public enum BinarySizeUnit
{
  /**
   * The size unit that represents bytes.
   */
  BYTES(BigInteger.valueOf(1L),
       INFO_SIZE_UNIT_BYTES_SINGULAR.get(),
       INFO_SIZE_UNIT_BYTES_PLURAL.get(),
       INFO_SIZE_UNIT_BYTES_ABBREVIATION.get()),



  /**
   * The size unit that represents kilobytes.  Each kilobyte is 1024 bytes.
   */
  KILOBYTES(BigInteger.valueOf(1_024L),
       INFO_SIZE_UNIT_KILOBYTES_SINGULAR.get(),
       INFO_SIZE_UNIT_KILOBYTES_PLURAL.get(),
       INFO_SIZE_UNIT_KILOBYTES_ABBREVIATION.get()),



  /**
   * The size unit that represents megabytes.  Each megabyte is 1024 kilobytes.
   */
  MEGABYTES(BigInteger.valueOf(1_048_576L),
       INFO_SIZE_UNIT_MEGABYTES_SINGULAR.get(),
       INFO_SIZE_UNIT_MEGABYTES_PLURAL.get(),
       INFO_SIZE_UNIT_MEGABYTES_ABBREVIATION.get()),



  /**
   * The size unit that represents gigabytes.  Each gigabyte is 1024 megabytes.
   */
  GIGABYTES(BigInteger.valueOf(1_073_741_824L),
       INFO_SIZE_UNIT_GIGABYTES_SINGULAR.get(),
       INFO_SIZE_UNIT_GIGABYTES_PLURAL.get(),
       INFO_SIZE_UNIT_GIGABYTES_ABBREVIATION.get()),



  /**
   * The size unit that represents terabytes.  Each terabyte is 1024 gigabytes.
   */
  TERABYTES(BigInteger.valueOf(1_099_511_627_776L),
       INFO_SIZE_UNIT_TERABYTES_SINGULAR.get(),
       INFO_SIZE_UNIT_TERABYTES_PLURAL.get(),
       INFO_SIZE_UNIT_TERABYTES_ABBREVIATION.get()),



  /**
   * The size unit that represents petabyte.  Each petabyte is 1024 terabytes.
   */
  PETABYTES(BigInteger.valueOf(1_125_899_906_842_624L),
       INFO_SIZE_UNIT_PETABYTES_SINGULAR.get(),
       INFO_SIZE_UNIT_PETABYTES_PLURAL.get(),
       INFO_SIZE_UNIT_PETABYTES_ABBREVIATION.get()),



  /**
   * The size unit that represents exabytes.  Each exabyte is 1024 petabytes.
   */
  EXABYTES(new BigInteger("1152921504606846976"),
       INFO_SIZE_UNIT_EXABYTES_SINGULAR.get(),
       INFO_SIZE_UNIT_EXABYTES_PLURAL.get(),
       INFO_SIZE_UNIT_EXABYTES_ABBREVIATION.get()),



  /**
   * The size unit that represents zettabytes.  Each zettabyte is 1024 exabytes.
   */
  ZETTABYTES(new BigInteger("1180591620717411303424"),
       INFO_SIZE_UNIT_ZETTABYTES_SINGULAR.get(),
       INFO_SIZE_UNIT_ZETTABYTES_PLURAL.get(),
       INFO_SIZE_UNIT_ZETTABYTES_ABBREVIATION.get()),



  /**
   * The size unit that represents yottabytes.  Each yottabyte is 1024
   * zettabytes.
   */
  YOTTABYTES(new BigInteger("1208925819614629174706176"),
       INFO_SIZE_UNIT_YOTTABYTES_SINGULAR.get(),
       INFO_SIZE_UNIT_YOTTABYTES_PLURAL.get(),
       INFO_SIZE_UNIT_YOTTABYTES_ABBREVIATION.get());



  // The number of bytes per single instance of this unit.
  @NotNull private final BigInteger numBytesPerUnit;

  // The abbreviation for the unit.
  @NotNull private final String abbreviation;

  // The plural name for the unit.
  @NotNull private final String pluralName;

  // The singular name for the unit.
  @NotNull private final String singularName;



  /**
   * Creates a new size unit with the provided information.
   *
   * @param  numBytesPerUnit  The number of bytes per single instance of this
   *                          size unit.  It must not be {@code null}.
   * @param  singularName     The name for a single instance of this size unit.
   *                          It must not be {@code null}.
   * @param  pluralName       The name for multiple instances of this size unit.
   *                          It must not be {@code null}.
   * @param  abbreviation     The abbreviation for multiple instances of this
   *                          size unit.  It must not be {@code null}.
   */
  BinarySizeUnit(@NotNull final BigInteger numBytesPerUnit,
                 @NotNull final String singularName,
                 @NotNull final String pluralName,
                 @NotNull final String abbreviation)
  {
    this.numBytesPerUnit = numBytesPerUnit;
    this.singularName = singularName;
    this.pluralName = pluralName;
    this.abbreviation = abbreviation;
  }



  /**
   * Retrieves the number of bytes per single instance of this size unit.
   *
   * @return  The number of bytes per single instance of this size unit.
   */
  @NotNull()
  public BigInteger getNumBytesPerUnit()
  {
    return numBytesPerUnit;
  }



  /**
   * Retrieves the singular name for this size unit.
   *
   * @return  The singular name for this size unit.
   */
  @NotNull()
  public String getSingularName()
  {
    return singularName;
  }



  /**
   * Retrieves the plural name for this size unit.
   *
   * @return  The plural name for this size unit.
   */
  @NotNull()
  public String getPluralName()
  {
    return pluralName;
  }



  /**
   * Retrieves the abbreviation for this size unit.
   *
   * @return  The abbreviation for this size unit.
   */
  @NotNull()
  public String getAbbreviation()
  {
    return abbreviation;
  }



  /**
   * Retrieves the number of bytes in the specified number of instances of this
   * size unit.
   *
   * @param  value  The number of instances of this unit to convert to bytes.
   *
   * @return  The number of bytes in the specified number of instances of this
   *          size unit.
   */
  @NotNull()
  public BigInteger toBytes(final long value)
  {
    return toBytes(BigInteger.valueOf(value));
  }



  /**
   * Retrieves the number of bytes in the specified number of instances of this
   * size unit.
   *
   * @param  value  The number of instances of this unit to convert to bytes.
   *                It must not be {@code null}.
   *
   * @return  The number of bytes in the specified number of instances of this
   *          size unit.
   */
  @NotNull()
  public BigInteger toBytes(@NotNull final BigInteger value)
  {
    return numBytesPerUnit.multiply(value);
  }



  /**
   * Retrieves the number of bytes in the specified number of instances of this
   * size unit, rounded to the nearest integer.
   *
   * @param  value  The number of instances of this unit to convert to bytes.
   *
   * @return  The number of bytes in the specified number of instances of this
   *          size unit.
   */
  @NotNull()
  public BigInteger toBytes(final double value)
  {
    return toBytes(BigDecimal.valueOf(value));
  }



  /**
   * Retrieves the number of bytes in the specified number of instances of this
   * size unit, rounded to the nearest integer.
   *
   * @param  value  The number of instances of this unit to convert to bytes.
   *                It must not be {@code null}.
   *
   * @return  The number of bytes in the specified number of instances of this
   *          size unit.
   */
  @NotNull()
  public BigInteger toBytes(@NotNull final BigDecimal value)
  {
    final BigDecimal numBytesPerUnitAsBigDecimal =
         new BigDecimal(numBytesPerUnit);
    final BigDecimal numBytesBigDecimal =
         numBytesPerUnitAsBigDecimal.multiply(value);
    final BigDecimal roundedBigDecimal =
         numBytesBigDecimal.setScale(0, RoundingMode.HALF_UP);
    return roundedBigDecimal.toBigInteger();
  }



  /**
   * Retrieves the number of instances of this unit represented by the
   * specified number of bytes.
   *
   * @param  numBytes  The number of bytes to use to make the determination.
   *
   * @return  The number of instances of this unit represented by the specified
   *          number of bytes.
   */
  @NotNull()
  public BigDecimal fromBytes(final long numBytes)
  {
    return fromBytes(BigInteger.valueOf(numBytes));
  }



  /**
   * Retrieves the number of instances of this unit represented by the
   * specified number of bytes.
   *
   * @param  numBytes  The number of bytes to use to make the determination.  It
   *                   must not be {@code null}.
   *
   * @return  The number of instances of this unit represented by the specified
   *          number of bytes.
   */
  @NotNull()
  public BigDecimal fromBytes(@NotNull final BigInteger numBytes)
  {
    final BigDecimal numBytesPerUnitAsBigDecimal =
         new BigDecimal(numBytesPerUnit);
    final BigDecimal numBytesAsBigDecimal = new BigDecimal(numBytes);
    return numBytesAsBigDecimal.divide(numBytesPerUnitAsBigDecimal);
  }



  /**
   * Retrieves a string that represents a human-readable representation of the
   * specified number of bytes.  The string representation will be constructed
   * in accordance with the following rules:
   * <UL>
   *   <LI>
   *     The string representation will use the abbreviation for the unit (e.g.,
   *     "b" instead of "bytes", "KB" instead of kilobytes, etc.)
   *   </LI>
   *   <LI>
   *     If the provided value represents an exact multiple of the number of
   *     bytes for a given unit, then the string representation will be an
   *     integer followed by the abbreviation for the unit (e.g., a value of
   *     123 will result in a string representation of "123b", a value of
   *     524880 will result in a string representation of "5MB", a value of
   *     7516192768 will result in a string representation of "7GB", etc.).
   *   </LI>
   *   <LI>
   *     If the provided value does not represent an exact multiple of the
   *     number of bytes for the given unit, then the string representation will
   *     use a floating-point number with two digits behind the decimal point.
   *     It will select the unit so that when possible, there will be between
   *     1 and 3 digits before the decimal point (e.g., a value of 12345 will
   *     result in a string representation of "12.06KB", a value of
   *     9876543210 will result in a string representation of "9.20GB", etc.).
   *   </LI>
   * </UL>
   *
   * @param  numBytes  The number of bytes to represent as a human-readable
   *                   size.  It must be greater than or equal to zero.
   *
   * @return  A string that represents a human-readable representation of the
   *          specified number of bytes.
   */
  @NotNull()
  public static String bytesToHumanReadableSize(final long numBytes)
  {
    return bytesToHumanReadableSize(BigInteger.valueOf(numBytes));
  }



  /**
   * Retrieves a string that represents a human-readable representation of the
   * specified number of bytes.  The string representation will be constructed
   * in accordance with the following rules:
   * <UL>
   *   <LI>
   *     The string representation will use the abbreviation for the unit (e.g.,
   *     "B" instead of "bytes", "KB" instead of kilobytes, etc.)
   *   </LI>
   *   <LI>
   *     The string representation
   *     The string representation will use the abbreviation for the unit (e.g.,
   *     "B" instead of "bytes", "KB" instead of kilobytes, etc.)
   *   </LI>
   *   <LI>
   *     If the provided value represents an exact multiple of the number of
   *     bytes for the selected unit, then the string representation will be an
   *     integer followed by the abbreviation for the unit (e.g., a value of
   *     123 will result in a string representation of "123B", a value of
   *     524880 will result in a string representation of "5MB", a value of
   *     7516192768 will result in a string representation of "7GB", etc.).
   *   </LI>
   *   <LI>
   *     If the provided value does not represent an exact multiple of the
   *     number of bytes for the selected unit, then the string representation
   *     will use a floating-point number with two digits behind the decimal
   *     point (e.g., a value of 12345 will result in a string representation of
   *     "12.06KB", a value of 9876543210 will result in a string representation
   *     of "9.20GB", etc.).
   *   </LI>
   * </UL>
   *
   * @param  numBytes  The number of bytes to represent as a human-readable
   *                   size.  It must not be {@code null}, and it must represent
   *                   a value that is greater than or equal to zero.
   *
   * @return  A string that represents a human-readable representation of the
   *          specified number of bytes.
   */
  @NotNull()
  public static String bytesToHumanReadableSize(
              @NotNull final BigInteger numBytes)
  {
    Validator.ensureTrue((numBytes.compareTo(BigInteger.ZERO) >= 0),
         "BinarySizeUnits.bytesToHumanReadableSize.numBytes must be greater " +
              "than or equal to zero.");


    // Find the smallest unit whose numBytesPerUnit is greater than or equal
    // to the given value.
    BinarySizeUnit selectedUnit = null;
    final BinarySizeUnit[] values = values();
    for (int i=(values.length - 1); i >= 0; i--)
    {
      final BinarySizeUnit unit = values[i];
      if (numBytes.compareTo(unit.numBytesPerUnit) >= 0)
      {
        selectedUnit = unit;
        break;
      }
    }


    // Check to see if we ended up without a selected unit (which should only
    // happen if the provided unit was zero).  In that case, we'll default to
    // a unit of bytes.
    if (selectedUnit == null)
    {
      return numBytes + BYTES.abbreviation;
    }


    // Check to see if the provided value is an exact multiple of the number of
    // bytes per instance of the selected unit.  If so, then represent the value
    // as an integer followed by the unit abbreviation.
    if (numBytes.remainder(selectedUnit.numBytesPerUnit).equals(
         BigInteger.ZERO))
    {
      return numBytes.divide(selectedUnit.numBytesPerUnit) +
           selectedUnit.abbreviation;
    }


    // Compute the number of instances of the given unit needed to represent
    // the provided value.
    final BigDecimal numBytesAsBigDecimal = new BigDecimal(numBytes);
    final BigDecimal numBytesPerUnitAsBigDecimal =
         new BigDecimal(selectedUnit.numBytesPerUnit);
    final BigDecimal numUnitsPerValueAsBigDecimal =
         numBytesAsBigDecimal.divide(numBytesPerUnitAsBigDecimal, 2,
              RoundingMode.HALF_UP);
    return numUnitsPerValueAsBigDecimal.toString() + selectedUnit.abbreviation;
  }



  /**
   * Retrieves the binary size unit value that has the given name as either its
   * singular name, plural name, or abbreviation, in a case-insensitive manner.
   *
   *
   * @param  name  The name for which to retrieve the binary size unit value.
   *               It must not be {@code null}.
   *
   * @return  The binary size unit value for the given name, or {@code null} if
   *          no value has a singular name, plural name, or abbreviation that
   *          matches the provided name in a case-insensitive manner.
   */
  @Nullable()
  public static BinarySizeUnit forName(@NotNull final String name)
  {
    for (final BinarySizeUnit unit : values())
    {
      if (name.equalsIgnoreCase(unit.name()) ||
           name.equalsIgnoreCase(unit.singularName) ||
           name.equalsIgnoreCase(unit.pluralName) ||
           name.equalsIgnoreCase(unit.abbreviation))
      {
        return unit;
      }
    }

    return null;
  }
}
