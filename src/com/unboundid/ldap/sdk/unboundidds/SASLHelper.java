/*
 * Copyright 2012-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2017 UnboundID Corp.
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



import java.util.Map;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SASLBindRequest;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.SASLMechanismInfo;
import com.unboundid.util.SASLOption;
import com.unboundid.util.SASLUtils;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class will be used by the {@link SASLUtils} class to provide support for
 * SASL mechanisms which only exist in the Commercial Edition of the LDAP SDK.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLHelper
{
  /**
   * The name of the SASL option that specifies a one-time password.  It may be
   * used in conjunction with the UNBOUNDID-DELIVERED-OTP and
   * UNBOUNDID-YUBIKEY-OTP mechanisms.
   */
  public static final String SASL_OPTION_OTP = "otp";



  /**
   * The name of the SASL option that may be used to indicate whether to
   * prompt for a static password.  It may be used in conjunction with the
   * UNBOUNDID-TOTP and UNBOUNDID-YUBIKEY-OTP mechanisms.
   */
  public static final String SASL_OPTION_PROMPT_FOR_STATIC_PW =
       "promptForStaticPassword";



  /**
   * The name of the SASL option that specifies the TOTP authentication code.
   * It may be used in conjunction with the UNBOUNDID-TOTP mechanism.
   */
  public static final String SASL_OPTION_TOTP_PASSWORD = "totpPassword";



  /**
   * Prevent this utility class from being instantiated.
   */
  private SASLHelper()
  {
    // No implementation required.
  }



  /**
   * Add information to the provided map about SASL mechanisms supported by the
   * Commercial Edition of the LDAP SDK.
   *
   * @param  saslMap  A map from the SASL mechanism name to information about
   *                  that SASL mechanism and the options it supports.
   */
  @InternalUseOnly()
  public static void addCESASLInfo(final Map<String,SASLMechanismInfo> saslMap)
  {
    saslMap.put(
         StaticUtils.toLowerCase(
              UnboundIDDeliveredOTPBindRequest.
                   UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME),
         new SASLMechanismInfo(
              UnboundIDDeliveredOTPBindRequest.
                   UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME,
              INFO_SASL_UNBOUNDID_DELIVERED_OTP_DESCRIPTION.get(), false, false,
              new SASLOption(SASLUtils.SASL_OPTION_AUTH_ID,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASLUtils.SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_AUTHZ_ID.get(), false,
                   false),
              new SASLOption(SASL_OPTION_OTP,
                   INFO_SASL_UNBOUNDID_DELIVERED_OTP_OPTION_OTP.get(), true,
                   false)));

    saslMap.put(
         StaticUtils.toLowerCase(
              UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME),
         new SASLMechanismInfo(
              UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME,
              INFO_SASL_UNBOUNDID_TOTP_DESCRIPTION.get(), true, false,
              new SASLOption(SASLUtils.SASL_OPTION_AUTH_ID,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASLUtils.SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_AUTHZ_ID.get(), false,
                   false),
              new SASLOption(SASL_OPTION_PROMPT_FOR_STATIC_PW,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_PROMPT_FOR_PW.get(), false,
                   false),
              new SASLOption(SASL_OPTION_TOTP_PASSWORD,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_TOTP_PASSWORD.get(), true,
                   false)));

    saslMap.put(
         StaticUtils.toLowerCase(
              UnboundIDYubiKeyOTPBindRequest.
                   UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME),
         new SASLMechanismInfo(
              UnboundIDYubiKeyOTPBindRequest.
                   UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME,
              INFO_SASL_UNBOUNDID_YUBIKEY_OTP_DESCRIPTION.get(), true, false,
              new SASLOption(SASLUtils.SASL_OPTION_AUTH_ID,
                   INFO_SASL_UNBOUNDID_YUBIKEY_OTP_OPTION_AUTH_ID.get(), true,
                   false),
              new SASLOption(SASLUtils.SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_UNBOUNDID_YUBIKEY_OTP_OPTION_AUTHZ_ID.get(), false,
                   false),
              new SASLOption(SASL_OPTION_OTP,
                   INFO_SASL_UNBOUNDID_YUBIKEY_OTP_OPTION_OTP.get(), true,
                   false),
              new SASLOption(SASL_OPTION_PROMPT_FOR_STATIC_PW,
                   INFO_SASL_UNBOUNDID_YUBIKEY_OTP_OPTION_PROMPT_FOR_PW.get(),
                   false, false)));
  }



  /**
   * Creates a new SASL bind request  using the provided information.  Note that
   * this method may only be used for SASL mechanisms available exclusively in
   * the Commercial Edition.
   *
   * @param  bindDN     The bind DN to use for the SASL bind request.  For most
   *                    SASL mechanisms, this should be {@code null}, since the
   *                    identity of the target user should be specified in some
   *                    other way (e.g., via an "authID" SASL option).
   * @param  password   The password to use for the SASL bind request.  It may
   *                    be {@code null} if no password is required for the
   *                    desired SASL mechanism.
   * @param  mechanism  The name of the SASL mechanism to use.  It must not be
   *                    {@code null}.
   * @param  tool       The command-line tool whose input and output streams
   *                    should be used when prompting for the bind password.  It
   *                    may be {@code null} if {@code promptForPassword} is
   *                    {@code false}.
   * @param  options    The set of SASL options to use when creating the bind
   *                    request, mapped from option name to option value.  It
   *                    must not be {@code null}, but may be empty if no options
   *                    were provided.
   * @param  controls   The set of controls to include in the request.
   *
   * @return  The SASL bind request created using the provided information, or
   *           {@code null} if the specified mechanism is not defined in or
   *           specific to the Commercial Edition of the LDAP SDK.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @InternalUseOnly()
  public static SASLBindRequest createBindRequest(final String bindDN,
                                     final byte[] password,
                                     final String mechanism,
                                     final CommandLineTool tool,
                                     final Map<String,String> options,
                                     final Control... controls)
         throws LDAPException
  {
    if (mechanism.equalsIgnoreCase(UnboundIDDeliveredOTPBindRequest.
             UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME))
    {
      return createUNBOUNDIDDeliveredOTPBindRequest(password, options,
           controls);
    }
    else if (mechanism.equalsIgnoreCase(
             UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME))
    {
      return createUNBOUNDIDTOTPBindRequest(password, tool, options, controls);
    }
    else if (mechanism.equalsIgnoreCase(
         UnboundIDYubiKeyOTPBindRequest.UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME))
    {
      return createUNBOUNDIDYUBIKEYOTPBindRequest(password, tool, options,
           controls);
    }
    else
    {
      return null;
    }
  }



  /**
   * Creates a SASL UNBOUNDID-DELIVERED-OTP bind request using the provided
   * password and set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL UNBOUNDID-DELIVERED-OTP bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  private static UnboundIDDeliveredOTPBindRequest
                      createUNBOUNDIDDeliveredOTPBindRequest(
                           final byte[] password,
                           final Map<String,String> options,
                           final Control... controls)
          throws LDAPException
  {
    if (password != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_DOESNT_ACCEPT_PASSWORD.get(
                UnboundIDDeliveredOTPBindRequest.
                     UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME));
    }

    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASLUtils.SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASLUtils.SASL_OPTION_AUTH_ID,
                UnboundIDDeliveredOTPBindRequest.
                     UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME));
    }

    // The OTP option is required.
    final String otp = options.remove(StaticUtils.toLowerCase(SASL_OPTION_OTP));
    if (otp == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_OTP,
                UnboundIDDeliveredOTPBindRequest.
                     UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME));
    }

    // The authzID option is optional.
    final String authzID = options.remove(StaticUtils.toLowerCase(
         SASLUtils.SASL_OPTION_AUTHZ_ID));

    // Ensure no unsupported options were provided.
    SASLUtils.ensureNoUnsupportedOptions(options,
         UnboundIDDeliveredOTPBindRequest.
              UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME);

    return new UnboundIDDeliveredOTPBindRequest(authID, authzID, otp, controls);
  }



  /**
   * Creates a SASL UNBOUNDID-TOTP bind request using the provided password and
   * set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  tool      The command-line tool whose input and output streams
   *                   should be used when prompting for the bind password.  It
   *                   may be {@code null} if {@code promptForPassword} is
   *                   {@code false}.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL UNBOUNDID-TOTP bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  private static SingleUseTOTPBindRequest createUNBOUNDIDTOTPBindRequest(
                                               final byte[] password,
                                               final CommandLineTool tool,
                                               final Map<String,String> options,
                                               final Control... controls)
          throws LDAPException
  {
    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASLUtils.SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASLUtils.SASL_OPTION_AUTH_ID,
                UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME));
    }

    // The TOTP password option is required.
    final String totpPassword =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_TOTP_PASSWORD));
    if (totpPassword == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_TOTP_PASSWORD,
                UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME));
    }

    // The authzID option is optional.
    byte[] pwBytes = password;
    final String authzID = options.remove(StaticUtils.toLowerCase(
         SASLUtils.SASL_OPTION_AUTHZ_ID));

    // The promptForStaticPassword option is optional.
    final String promptStr = options.remove(StaticUtils.toLowerCase(
         SASL_OPTION_PROMPT_FOR_STATIC_PW));
    if (promptStr != null)
    {
      if (promptStr.equalsIgnoreCase("true"))
      {
        if (pwBytes == null)
        {
          tool.getOriginalOut().print(INFO_SASL_ENTER_STATIC_PW.get());
          pwBytes = PasswordReader.readPassword();
          tool.getOriginalOut().println();
        }
        else
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_SASL_PROMPT_FOR_PROVIDED_PW.get(
                    SASL_OPTION_PROMPT_FOR_STATIC_PW));
        }
      }
      else if (! promptStr.equalsIgnoreCase("false"))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_PROMPT_FOR_STATIC_PW_BAD_VALUE.get(
                  SASL_OPTION_PROMPT_FOR_STATIC_PW));
      }
    }

    // Ensure no unsupported options were provided.
    SASLUtils.ensureNoUnsupportedOptions(options,
         UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME);

    return new SingleUseTOTPBindRequest(authID, authzID, totpPassword, pwBytes,
         controls);
  }



  /**
   * Creates a SASL UNBOUNDID-YUBIKEY-OTP bind request using the provided
   * password and set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  tool      The command-line tool whose input and output streams
   *                   should be used when prompting for the bind password.  It
   *                   may be {@code null} if {@code promptForPassword} is
   *                   {@code false}.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL UNBOUNDID-YUBIKEY-OTP bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  private static UnboundIDYubiKeyOTPBindRequest
                      createUNBOUNDIDYUBIKEYOTPBindRequest(
                           final byte[] password, final CommandLineTool tool,
                           final Map<String,String> options,
                           final Control... controls)
          throws LDAPException
  {
    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASLUtils.SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASLUtils.SASL_OPTION_AUTH_ID,
                UnboundIDYubiKeyOTPBindRequest.
                     UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME));
    }

    // The otp option is required.
    final String otp = options.remove(StaticUtils.toLowerCase(SASL_OPTION_OTP));
    if (otp == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_OTP,
                UnboundIDYubiKeyOTPBindRequest.
                     UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME));
    }

    // The authzID option is optional.
    final String authzID = options.remove(StaticUtils.toLowerCase(
         SASLUtils.SASL_OPTION_AUTHZ_ID));

    // The promptForStaticPassword option is optional.
    byte[] pwBytes = password;
    final String promptStr = options.remove(StaticUtils.toLowerCase(
         SASL_OPTION_PROMPT_FOR_STATIC_PW));
    if (promptStr != null)
    {
      if (promptStr.equalsIgnoreCase("true"))
      {
        if (pwBytes == null)
        {
          tool.getOriginalOut().print(INFO_SASL_ENTER_STATIC_PW.get());
          pwBytes = PasswordReader.readPassword();
          tool.getOriginalOut().println();
        }
        else
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_SASL_PROMPT_FOR_PROVIDED_PW.get(
                    SASL_OPTION_PROMPT_FOR_STATIC_PW));
        }
      }
      else if (! promptStr.equalsIgnoreCase("false"))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_PROMPT_FOR_STATIC_PW_BAD_VALUE.get(
                  SASL_OPTION_PROMPT_FOR_STATIC_PW));
      }
    }

    // Ensure no unsupported options were provided.
    SASLUtils.ensureNoUnsupportedOptions(options,
         UnboundIDYubiKeyOTPBindRequest.UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME);

    return new UnboundIDYubiKeyOTPBindRequest(authID, authzID, pwBytes, otp,
         controls);
  }
}
