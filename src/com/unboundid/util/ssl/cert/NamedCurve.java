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
package com.unboundid.util.ssl.cert;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines a set of OIDs that are known to be associated with elliptic
 * curve keys.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum NamedCurve
{
  /**
   * The brainpoolP256r1 curve.
   */
  BRAINPOOLP256R1("1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1"),



  /**
   * The brainpoolP384r1 curve.
   */
  BRAINPOOLP384R1("1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1"),



  /**
   * The brainpoolP512r1 curve.
   */
  BRAINPOOLP512R1("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1"),



  /**
   * The secP160k1 curve.
   */
  SECP160K1("1.3.132.0.9", "secP160k1"),



  /**
   * The secP160r1 curve.
   */
  SECP160R1("1.3.132.0.8", "secP160r1"),



  /**
   * The secP160r2 curve.
   */
  SECP160R2("1.3.132.0.30", "secP160r2"),



  /**
   * The secP192k1 curve.
   */
  SECP192K1("1.3.132.0.31", "secP192k1"),



  /**
   * The secP192r1 curve (also known as nistP192).
   */
  SECP192R1("1.2.840.10045.3.1.1", "secP192r1"),



  /**
   * The secP224k1 curve.
   */
  SECP224K1("1.3.132.0.32", "secP224k1"),



  /**
   * The secP224r1 curve (also known as nistP224).
   */
  SECP224R1("1.3.132.0.33", "secP224r1"),



  /**
   * The secP256k1 curve.
   */
  SECP256K1("1.3.132.0.10", "secP256k1"),



  /**
   * The secP256r1 curve (also known as nistP256).
   */
  SECP256R1("1.2.840.10045.3.1.7", "secP256r1"),



  /**
   * The secP384r1 curve (also known as nistP384).
   */
  SECP384R1("1.3.132.0.34", "secP384r1"),



  /**
   * The secP521r1 curve (also known as nistP521).
   */
  SECP521R1("1.3.132.0.35", "secP521r1"),



  /**
   * The secT163k1 curve.
   */
  SECT163K1("1.3.132.0.1", "secT163k1"),



  /**
   * The secT163r2 curve.
   */
  SECT163R2("1.3.132.0.15", "secT163r2"),



  /**
   * The secT233k1 curve.
   */
  SECT233K1("1.3.132.0.26", "secT233k1"),



  /**
   * The secT233r1 curve.
   */
  SECT233R1("1.3.132.0.27", "secT233r1"),



  /**
   * The secT283k1 curve.
   */
  SECT283K1("1.3.132.0.16", "secT283k1"),



  /**
   * The secT283r1 curve.
   */
  SECT283R1("1.3.132.0.17", "secT283r1"),



  /**
   * The secT409k1 curve.
   */
  SECT409K1("1.3.132.0.36", "secT409k1"),



  /**
   * The secT409r1 curve.
   */
  SECT409R1("1.3.132.0.37", "secT409r1"),



  /**
   * The secT571k1 curve.
   */
  SECT571K1("1.3.132.0.38", "secT571k1"),



  /**
   * The secT571r1 curve.
   */
  SECT571R1("1.3.132.0.39", "secT571r1");



  // The OID for this extended key usage ID value.
  @NotNull private final OID oid;

  // The name for this extended key usage ID value.
  @NotNull private final String name;



  /**
   * Creates a new named curve value with the provided information.
   *
   * @param  oidString  The string representation of the OID for this named
   *                    curve value.
   * @param  name       The name for this named curve value.
   */
  NamedCurve(@NotNull final String oidString, @NotNull final String name)
  {
    this.name = name;

    oid = new OID(oidString);
  }



  /**
   * Retrieves the OID for this named curve value.
   *
   * @return  The OID for this named curve value.
   */
  @NotNull()
  public OID getOID()
  {
    return oid;
  }



  /**
   * Retrieves the name for this named curve value.
   *
   * @return  The name for this named curve value.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the named curve value with the specified OID.
   *
   * @param  oid  The OID of the named curve value to retrieve.  It must not be
   *              {@code null}.
   *
   * @return  The named curve value with the specified OID, or {@code null} if
   *          there is no value with the specified OID.
   */
  @Nullable()
  public static NamedCurve forOID(@NotNull final OID oid)
  {
    for (final NamedCurve curve : values())
    {
      if (curve.oid.equals(oid))
      {
        return curve;
      }
    }

    return null;
  }



  /**
   * Retrieves the name for the named curve value with the provided OID, or a
   * string representation of the OID if there is no value with that OID.
   *
   * @param  oid  The OID for the named curve to retrieve.
   *
   * @return  The name for the named curve value with the provided OID, or a
   *          string representation of the OID if there is no value with that
   *          OID.
   */
  @NotNull()
  public static String getNameOrOID(@NotNull final OID oid)
  {
    final NamedCurve curve = forOID(oid);
    if (curve == null)
    {
      return oid.toString();
    }
    else
    {
      return curve.name;
    }
  }



  /**
   * Retrieves the named curve with the specified name.
   *
   * @param  name  The name of the named curve to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The requested named curve, or {@code null} if no such curve is
   *          defined.
   */
  @Nullable()
  public static NamedCurve forName(@NotNull final String name)
  {
    for (final NamedCurve namedCurve : values())
    {
      if (namedCurve.name.equalsIgnoreCase(name) ||
           namedCurve.name().equalsIgnoreCase(name))
      {
        return namedCurve;
      }
    }

    return null;
  }
}
