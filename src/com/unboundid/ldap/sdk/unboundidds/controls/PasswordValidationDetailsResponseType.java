/*
 * Copyright 2015-2016 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2016 UnboundID Corp.
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This enum defines the set of response types that can be used in the
 * password validation details response control.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum PasswordValidationDetailsResponseType
{
  /**
   * The response type that indicates that the server was able to perform
   * validation against the proposed password, and that the response includes
   * a set of validation results.
   */
  VALIDATION_DETAILS((byte) 0xA0),



  /**
   * The response type that indicates that the server was unable to provide
   * validation results because the associated request did not include any
   * password.
   */
  NO_PASSWORD_PROVIDED((byte) 0x81),



  /**
   * The response type that indicates that the server was unable to provide
   * validation results because the associated request included multiple
   * passwords.
   */
  MULTIPLE_PASSWORDS_PROVIDED((byte) 0x82),



  /**
   * The response type that indicates that the server encountered a problem with
   * the request that caused processing to end before any password validation
   * was attempted.
   */
  NO_VALIDATION_ATTEMPTED((byte) 0x83);



  // The BER type that will be used for this response type in an encoded
  // password validation details response control.
  private final byte berType;



  /**
   * Creates a new password validation details response type with the provided
   * BER type.
   *
   * @param  berType  The BER type that will be used for this response type in
   *                  an encoded password validation details response control.
   */
  private PasswordValidationDetailsResponseType(final byte berType)
  {
    this.berType = berType;
  }



  /**
   * Retrieves the BER type that will be used for this response type in an
   * encoded password validation details response control.
   *
   * @return  The BER type that will be used for this response type in an
   *          encoded password validation details response control.
   */
  public byte getBERType()
  {
    return berType;
  }



  /**
   * Retrieves the password validation details response type with the specified
   * BER type.
   *
   * @param  berType  The BER type for the password validation details response
   *                  type to retrieve.
   *
   * @return  The password validation details response type with the specified
   *          BER type, or {@code null} if there is no response type with the
   *          specified BER type.
   */
  public static PasswordValidationDetailsResponseType
                     forBERType(final byte berType)
  {
    for (final PasswordValidationDetailsResponseType t : values())
    {
      if (t.berType == berType)
      {
        return t;
      }
    }

    return null;
  }
}
