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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.OutputStream;
import java.util.LinkedHashMap;

import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GenerateTOTPSharedSecretExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GenerateTOTPSharedSecretExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            RevokeTOTPSharedSecretExtendedRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a tool that can be used to generate a TOTP shared secret
 * for a user.  That shared secret may be used to generate TOTP authentication
 * codes for the purpose of authenticating with the UNBOUNDID-TOTP SASL
 * mechanism, or as a form of step-up authentication for external applications
 * using the validate TOTP password extended operation.
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
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class GenerateTOTPSharedSecret
       extends LDAPCommandLineTool
{
  // Indicates that the tool should interactively prompt for the static password
  // for the user for whom the TOTP secret is to be generated.
  @Nullable private BooleanArgument promptForUserPassword = null;

  // Indicates that the tool should revoke all existing TOTP shared secrets for
  // the user.
  @Nullable private BooleanArgument revokeAll = null;

  // The path to a file containing the static password for the user for whom the
  // TOTP secret is to be generated.
  @Nullable private FileArgument userPasswordFile = null;

  // The username for the user for whom the TOTP shared secret is to be
  // generated.
  @Nullable private StringArgument authenticationID = null;

  // The TOTP shared secret to revoke.
  @Nullable private StringArgument revoke = null;

  // The static password for the user for whom the TOTP shared sec ret is to be
  // generated.
  @Nullable private StringArgument userPassword = null;



  /**
   * Invokes the tool with the provided set of arguments.
   *
   * @param  args  The command-line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Invokes the tool with the provided set of arguments.
   *
   * @param  out   The output stream to use for standard out.  It may be
   *               {@code null} if standard out should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  A result code with the status of the tool processing.  Any result
   *          code other than {@link ResultCode#SUCCESS} should be considered a
   *          failure.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final GenerateTOTPSharedSecret tool =
         new GenerateTOTPSharedSecret(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided arguments.
   *
   * @param  out  The output stream to use for standard out.  It may be
   *              {@code null} if standard out should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public GenerateTOTPSharedSecret(@Nullable final OutputStream out,
                                  @Nullable final OutputStream err)
  {
    super(out, err);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "generate-totp-shared-secret";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_GEN_TOTP_SECRET_TOOL_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsAuthentication()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean defaultToPromptForBindPassword()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsSASLHelp()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean includeAlternateLongIdentifiers()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsSSLDebugging()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean logToolInvocationByDefault()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    // Create the authentication ID argument, which will identify the target
    // user.
    authenticationID = new StringArgument(null, "authID", true, 1,
         INFO_GEN_TOTP_SECRET_PLACEHOLDER_AUTH_ID.get(),
         INFO_GEN_TOTP_SECRET_DESCRIPTION_AUTH_ID.get());
    authenticationID.addLongIdentifier("authenticationID", true);
    authenticationID.addLongIdentifier("auth-id", true);
    authenticationID.addLongIdentifier("authentication-id", true);
    parser.addArgument(authenticationID);


    // Create the arguments that may be used to obtain the static password for
    // the target user.
    userPassword = new StringArgument(null, "userPassword", false, 1,
         INFO_GEN_TOTP_SECRET_PLACEHOLDER_USER_PW.get(),
         INFO_GEN_TOTP_SECRET_DESCRIPTION_USER_PW.get(
              authenticationID.getIdentifierString()));
    userPassword.setSensitive(true);
    userPassword.addLongIdentifier("user-password", true);
    parser.addArgument(userPassword);

    userPasswordFile = new FileArgument(null, "userPasswordFile", false, 1,
         null,
         INFO_GEN_TOTP_SECRET_DESCRIPTION_USER_PW_FILE.get(
              authenticationID.getIdentifierString()),
         true, true, true, false);
    userPasswordFile.addLongIdentifier("user-password-file", true);
    parser.addArgument(userPasswordFile);

    promptForUserPassword = new BooleanArgument(null, "promptForUserPassword",
         INFO_GEN_TOTP_SECRET_DESCRIPTION_PROMPT_FOR_USER_PW.get(
              authenticationID.getIdentifierString()));
    promptForUserPassword.addLongIdentifier("prompt-for-user-password", true);
    parser.addArgument(promptForUserPassword);


    // Create the arguments that may be used to revoke shared secrets rather
    // than generate them.
    revoke = new StringArgument(null, "revoke", false, 1,
         INFO_GEN_TOTP_SECRET_PLACEHOLDER_SECRET.get(),
         INFO_GEN_TOTP_SECRET_DESCRIPTION_REVOKE.get());
    parser.addArgument(revoke);

    revokeAll = new BooleanArgument(null, "revokeAll", 1,
         INFO_GEN_TOTP_SECRET_DESCRIPTION_REVOKE_ALL.get());
    revokeAll.addLongIdentifier("revoke-all", true);
    parser.addArgument(revokeAll);


    // At most one of the userPassword, userPasswordFile, and
    // promptForUserPassword arguments must be present.
    parser.addExclusiveArgumentSet(userPassword, userPasswordFile,
         promptForUserPassword);


    // If any of the userPassword, userPasswordFile, or promptForUserPassword
    // arguments is present, then the authenticationID argument must also be
    // present.
    parser.addDependentArgumentSet(userPassword, authenticationID);
    parser.addDependentArgumentSet(userPasswordFile, authenticationID);
    parser.addDependentArgumentSet(promptForUserPassword, authenticationID);


    // At most one of the revoke and revokeAll arguments may be provided.
    parser.addExclusiveArgumentSet(revoke, revokeAll);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Establish a connection to the Directory Server.
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
           ERR_GEN_TOTP_SECRET_CANNOT_CONNECT.get(
                StaticUtils.getExceptionMessage(le)));
      return le.getResultCode();
    }

    try
    {
      // Get the authentication ID and static password to include in the
      // request.
      final String authID = authenticationID.getValue();

      final byte[] staticPassword;
      if (userPassword.isPresent())
      {
        staticPassword = StaticUtils.getBytes(userPassword.getValue());
      }
      else if (userPasswordFile.isPresent())
      {
        try
        {
          final char[] pwChars = getPasswordFileReader().readPassword(
               userPasswordFile.getValue());
          staticPassword = StaticUtils.getBytes(new String(pwChars));
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               ERR_GEN_TOTP_SECRET_CANNOT_READ_PW_FROM_FILE.get(
                    userPasswordFile.getValue().getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
          return ResultCode.LOCAL_ERROR;
        }
      }
      else if (promptForUserPassword.isPresent())
      {
        try
        {
          getOut().print(INFO_GEN_TOTP_SECRET_ENTER_PW.get(authID));
          staticPassword = PasswordReader.readPassword();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               ERR_GEN_TOTP_SECRET_CANNOT_READ_PW_FROM_STDIN.get(
                    StaticUtils.getExceptionMessage(e)));
          return ResultCode.LOCAL_ERROR;
        }
      }
      else
      {
        staticPassword = null;
      }


      // Create and send the appropriate request based on whether we should
      // generate or revoke a TOTP shared secret.
      ExtendedResult result;
      if (revoke.isPresent())
      {
        final RevokeTOTPSharedSecretExtendedRequest request =
             new RevokeTOTPSharedSecretExtendedRequest(authID, staticPassword,
                  revoke.getValue());
        try
        {
          result = conn.processExtendedOperation(request);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          result = new ExtendedResult(le);
        }

        if (result.getResultCode() == ResultCode.SUCCESS)
        {
          wrapOut(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               INFO_GEN_TOTP_SECRET_REVOKE_SUCCESS.get(revoke.getValue()));
        }
        else
        {
          wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               ERR_GEN_TOTP_SECRET_REVOKE_FAILURE.get(revoke.getValue()));
        }
      }
      else if (revokeAll.isPresent())
      {
        final RevokeTOTPSharedSecretExtendedRequest request =
             new RevokeTOTPSharedSecretExtendedRequest(authID, staticPassword,
                  null);
        try
        {
          result = conn.processExtendedOperation(request);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          result = new ExtendedResult(le);
        }

        if (result.getResultCode() == ResultCode.SUCCESS)
        {
          wrapOut(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               INFO_GEN_TOTP_SECRET_REVOKE_ALL_SUCCESS.get());
        }
        else
        {
          wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               ERR_GEN_TOTP_SECRET_REVOKE_ALL_FAILURE.get());
        }
      }
      else
      {
        final GenerateTOTPSharedSecretExtendedRequest request =
             new GenerateTOTPSharedSecretExtendedRequest(authID,
                  staticPassword);
        try
        {
          result = conn.processExtendedOperation(request);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          result = new ExtendedResult(le);
        }

        if (result.getResultCode() == ResultCode.SUCCESS)
        {
          wrapOut(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               INFO_GEN_TOTP_SECRET_GEN_SUCCESS.get(
                    ((GenerateTOTPSharedSecretExtendedResult) result).
                         getTOTPSharedSecret()));
        }
        else
        {
          wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               ERR_GEN_TOTP_SECRET_GEN_FAILURE.get());
        }
      }


      // If the result is a failure result, then present any additional details
      // to the user.
      if (result.getResultCode() != ResultCode.SUCCESS)
      {
        wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
             ERR_GEN_TOTP_SECRET_RESULT_CODE.get(
                  String.valueOf(result.getResultCode())));

        final String diagnosticMessage = result.getDiagnosticMessage();
        if (diagnosticMessage != null)
        {
          wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               ERR_GEN_TOTP_SECRET_DIAGNOSTIC_MESSAGE.get(diagnosticMessage));
        }

        final String matchedDN = result.getMatchedDN();
        if (matchedDN != null)
        {
          wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               ERR_GEN_TOTP_SECRET_MATCHED_DN.get(matchedDN));
        }

        for (final String referralURL : result.getReferralURLs())
        {
          wrapErr(0, StaticUtils.TERMINAL_WIDTH_COLUMNS,
               ERR_GEN_TOTP_SECRET_REFERRAL_URL.get(referralURL));
        }
      }

      return result.getResultCode();
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));

    examples.put(
         new String[]
         {
           "--hostname", "ds.example.com",
           "--port", "389",
           "--authID", "u:john.doe",
           "--promptForUserPassword",
         },
         INFO_GEN_TOTP_SECRET_GEN_EXAMPLE.get());

    examples.put(
         new String[]
         {
           "--hostname", "ds.example.com",
           "--port", "389",
           "--authID", "u:john.doe",
           "--userPasswordFile", "password.txt",
           "--revokeAll"
         },
         INFO_GEN_TOTP_SECRET_REVOKE_ALL_EXAMPLE.get());

    return examples;
  }
}
