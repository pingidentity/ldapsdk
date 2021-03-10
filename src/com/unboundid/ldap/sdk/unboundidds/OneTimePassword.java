/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.text.DecimalFormat;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides support for a number of one-time password algorithms.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * Supported algorithms include:
 * <UL>
 *   <LI>HOTP -- The HMAC-based one-time password algorithm described in
 *       <A HREF="http://www.ietf.org/rfc/rfc4226.txt">RFC 4226</A>.</LI>
 *   <LI>TOTP -- The time-based one-time password algorithm described in
 *       <A HREF="http://www.ietf.org/rfc/rfc6238.txt">RFC 6238</A>.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class OneTimePassword
{
  /**
   * The default number of digits to include in generated HOTP passwords.
   */
  public static final int DEFAULT_HOTP_NUM_DIGITS = 6;



  /**
   * The default time interval (in seconds) to use when generating TOTP
   * passwords.
   */
  public static final int DEFAULT_TOTP_INTERVAL_DURATION_SECONDS = 30;



  /**
   * The default number of digits to include in generated TOTP passwords.
   */
  public static final int DEFAULT_TOTP_NUM_DIGITS = 6;



  /**
   * The name of the MAC algorithm that will be used to perform HMAC-SHA-1
   * processing.
   */
  @NotNull private static final String HMAC_ALGORITHM_SHA_1 = "HmacSHA1";



  /**
   * The name of the secret key spec algorithm that will be used to construct a
   * secret key from the raw bytes that comprise it.
   */
  @NotNull private static final String KEY_ALGORITHM_RAW = "RAW";



  /**
   * Prevent this utility class from being instantiated.
   */
  private OneTimePassword()
  {
    // No implementation required.
  }



  /**
   * Generates a six-digit HMAC-based one-time-password using the provided
   * information.
   *
   * @param  sharedSecret  The secret key shared by both parties that will be
   *                       using the generated one-time password.
   * @param  counter       The counter value that will be used in the course of
   *                       generating the one-time password.
   *
   * @return  The zero-padded string representation of the resulting HMAC-based
   *          one-time password.
   *
   * @throws  LDAPException  If an unexpected problem is encountered while
   *                         attempting to generate the one-time password.
   */
  @NotNull()
  public static String hotp(@NotNull final byte[] sharedSecret,
                            final long counter)
         throws LDAPException
  {
    return hotp(sharedSecret, counter, DEFAULT_HOTP_NUM_DIGITS);
  }



  /**
   * Generates an HMAC-based one-time-password using the provided information.
   *
   * @param  sharedSecret  The secret key shared by both parties that will be
   *                       using the generated one-time password.
   * @param  counter       The counter value that will be used in the course of
   *                       generating the one-time password.
   * @param  numDigits     The number of digits that should be included in the
   *                       generated one-time password.  It must be greater than
   *                       or equal to six and less than or equal to eight.
   *
   * @return  The zero-padded string representation of the resulting HMAC-based
   *          one-time password.
   *
   * @throws  LDAPException  If an unexpected problem is encountered while
   *                         attempting to generate the one-time password.
   */
  @NotNull()
  public static String hotp(@NotNull final byte[] sharedSecret,
                            final long counter, final int numDigits)
         throws LDAPException
  {
    try
    {
      // Ensure that the number of digits is between 6 and 8, inclusive, and
      // get the appropriate modulus and decimal formatters to use.
      final int modulus;
      final DecimalFormat decimalFormat;
      switch (numDigits)
      {
        case 6:
          modulus = 1_000_000;
          decimalFormat = new DecimalFormat("000000");
          break;
        case 7:
          modulus = 10_000_000;
          decimalFormat = new DecimalFormat("0000000");
          break;
        case 8:
          modulus = 100_000_000;
          decimalFormat = new DecimalFormat("00000000");
          break;
        default:
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_HOTP_INVALID_NUM_DIGITS.get(numDigits));
      }


      // Convert the provided counter to a 64-bit value.
      final byte[] counterBytes = new byte[8];
      counterBytes[0] = (byte) ((counter >> 56) & 0xFFL);
      counterBytes[1] = (byte) ((counter >> 48) & 0xFFL);
      counterBytes[2] = (byte) ((counter >> 40) & 0xFFL);
      counterBytes[3] = (byte) ((counter >> 32) & 0xFFL);
      counterBytes[4] = (byte) ((counter >> 24) & 0xFFL);
      counterBytes[5] = (byte) ((counter >> 16) & 0xFFL);
      counterBytes[6] = (byte) ((counter >> 8) & 0xFFL);
      counterBytes[7] = (byte) (counter & 0xFFL);


      // Generate an HMAC-SHA-1 of the given counter using the provided key.
      final SecretKey k = new SecretKeySpec(sharedSecret, KEY_ALGORITHM_RAW);
      final Mac m = CryptoHelper.getMAC(HMAC_ALGORITHM_SHA_1);
      m.init(k);
      final byte[] hmacBytes = m.doFinal(counterBytes);


      // Generate a dynamic truncation of the resulting HMAC-SHA-1.
      final int dtOffset = hmacBytes[19] & 0x0F;
      final int dtValue  = (((hmacBytes[dtOffset] & 0x7F) << 24) |
           ((hmacBytes[dtOffset+1] & 0xFF) << 16) |
           ((hmacBytes[dtOffset+2] & 0xFF) << 8) |
           (hmacBytes[dtOffset+3] & 0xFF));


      // Use a modulus operation to convert the value into one that has at most
      // the desired number of digits.
      return decimalFormat.format(dtValue % modulus);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_HOTP_ERROR_GENERATING_PW.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Generates a six-digit time-based one-time-password using the provided
   * information and a 30-second time interval.
   *
   * @param  sharedSecret  The secret key shared by both parties that will be
   *                       using the generated one-time password.
   *
   * @return  The zero-padded string representation of the resulting time-based
   *          one-time password.
   *
   * @throws  LDAPException  If an unexpected problem is encountered while
   *                         attempting to generate the one-time password.
   */
  @NotNull()
  public static String totp(@NotNull final byte[] sharedSecret)
         throws LDAPException
  {
    return totp(sharedSecret, System.currentTimeMillis(),
         DEFAULT_TOTP_INTERVAL_DURATION_SECONDS, DEFAULT_TOTP_NUM_DIGITS);
  }



  /**
   * Generates a six-digit time-based one-time-password using the provided
   * information.
   *
   * @param  sharedSecret             The secret key shared by both parties that
   *                                  will be using the generated one-time
   *                                  password.
   * @param  authTime                 The time (in milliseconds since the epoch,
   *                                  as reported by
   *                                  {@code System.currentTimeMillis} or
   *                                  {@code Date.getTime}) at which the
   *                                  authentication attempt occurred.
   * @param  intervalDurationSeconds  The duration of the time interval, in
   *                                  seconds, that should be used when
   *                                  performing the computation.
   * @param  numDigits                The number of digits that should be
   *                                  included in the generated one-time
   *                                  password.  It must be greater than or
   *                                  equal to six and less than or equal to
   *                                  eight.
   *
   * @return  The zero-padded string representation of the resulting time-based
   *          one-time password.
   *
   * @throws  LDAPException  If an unexpected problem is encountered while
   *                         attempting to generate the one-time password.
   */
  @NotNull()
  public static String totp(@NotNull final byte[] sharedSecret,
                            final long authTime,
                            final int intervalDurationSeconds,
                            final int numDigits)
         throws LDAPException
  {
    // Make sure that the specified number of digits is between 6 and 8,
    // inclusive.
    if ((numDigits < 6) || (numDigits > 8))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_TOTP_INVALID_NUM_DIGITS.get(numDigits));
    }

    try
    {
      final long timeIntervalNumber = authTime / 1000 / intervalDurationSeconds;
      return hotp(sharedSecret, timeIntervalNumber, numDigits);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_TOTP_ERROR_GENERATING_PW.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }
}
