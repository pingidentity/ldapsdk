/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            DeliverPasswordResetTokenExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            DeliverPasswordResetTokenExtendedResult;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides a utility that may be used to request that the Directory
 * Server deliver a single-use password reset token to a user through some
 * out-of-band mechanism.
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
public final class DeliverPasswordResetToken
       extends LDAPCommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5793619963770997266L;



  // The DN of the user to whom the password reset token should be sent.
  @Nullable private DNArgument userDN;

  // The text to include after the password reset token in the "compact"
  // message.
  @Nullable private StringArgument compactTextAfterToken;

  // The text to include before the password reset token in the "compact"
  // message.
  @Nullable private StringArgument compactTextBeforeToken;

  // The name of the mechanism through which the one-time password should be
  // delivered.
  @Nullable private StringArgument deliveryMechanism;

  // The text to include after the password reset token in the "full" message.
  @Nullable private StringArgument fullTextAfterToken;

  // The text to include before the password reset token in the "full" message.
  @Nullable private StringArgument fullTextBeforeToken;

  // The subject to use for the message containing the delivered token.
  @Nullable private StringArgument messageSubject;



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(args, System.out, System.err);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args       The command line arguments provided to this program.
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   *
   * @return  A result code indicating whether the processing was successful.
   */
  @NotNull()
  public static ResultCode main(@NotNull final String[] args,
                                @Nullable final OutputStream outStream,
                                @Nullable final OutputStream errStream)
  {
    final DeliverPasswordResetToken tool =
         new DeliverPasswordResetToken(outStream, errStream);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool.
   *
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   */
  public DeliverPasswordResetToken(@Nullable final OutputStream outStream,
                                   @Nullable final OutputStream errStream)
  {
    super(outStream, errStream);

    userDN                 = null;
    compactTextAfterToken  = null;
    compactTextBeforeToken = null;
    deliveryMechanism      = null;
    fullTextAfterToken     = null;
    fullTextBeforeToken    = null;
    messageSubject         = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "deliver-password-reset-token";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_DELIVER_PW_RESET_TOKEN_TOOL_DESCRIPTION.get();
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
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    userDN = new DNArgument('b', "userDN", true, 1,
         INFO_DELIVER_PW_RESET_TOKEN_PLACEHOLDER_DN.get(),
         INFO_DELIVER_PW_RESET_TOKEN_DESCRIPTION_USER_DN.get());
    userDN.setArgumentGroupName(INFO_DELIVER_PW_RESET_TOKEN_GROUP_ID.get());
    userDN.addLongIdentifier("user-dn", true);
    parser.addArgument(userDN);

    deliveryMechanism = new StringArgument('m', "deliveryMechanism", false, 0,
         INFO_DELIVER_PW_RESET_TOKEN_PLACEHOLDER_NAME.get(),
         INFO_DELIVER_PW_RESET_TOKEN_DESCRIPTION_MECH.get());
    deliveryMechanism.setArgumentGroupName(
         INFO_DELIVER_PW_RESET_TOKEN_GROUP_DELIVERY_MECH.get());
    deliveryMechanism.addLongIdentifier("delivery-mechanism", true);
    parser.addArgument(deliveryMechanism);

    messageSubject = new StringArgument('s', "messageSubject", false, 1,
         INFO_DELIVER_PW_RESET_TOKEN_PLACEHOLDER_SUBJECT.get(),
         INFO_DELIVER_PW_RESET_TOKEN_DESCRIPTION_SUBJECT.get());
    messageSubject.setArgumentGroupName(
         INFO_DELIVER_PW_RESET_TOKEN_GROUP_DELIVERY_MECH.get());
    messageSubject.addLongIdentifier("message-subject", true);
    parser.addArgument(messageSubject);

    fullTextBeforeToken = new StringArgument('f', "fullTextBeforeToken", false,
         1, INFO_DELIVER_PW_RESET_TOKEN_PLACEHOLDER_FULL_BEFORE.get(),
         INFO_DELIVER_PW_RESET_TOKEN_DESCRIPTION_FULL_BEFORE.get());
    fullTextBeforeToken.setArgumentGroupName(
         INFO_DELIVER_PW_RESET_TOKEN_GROUP_DELIVERY_MECH.get());
    fullTextBeforeToken.addLongIdentifier("full-text-before-token", true);
    parser.addArgument(fullTextBeforeToken);

    fullTextAfterToken = new StringArgument('F', "fullTextAfterToken", false,
         1, INFO_DELIVER_PW_RESET_TOKEN_PLACEHOLDER_FULL_AFTER.get(),
         INFO_DELIVER_PW_RESET_TOKEN_DESCRIPTION_FULL_AFTER.get());
    fullTextAfterToken.setArgumentGroupName(
         INFO_DELIVER_PW_RESET_TOKEN_GROUP_DELIVERY_MECH.get());
    fullTextAfterToken.addLongIdentifier("full-text-after-token", true);
    parser.addArgument(fullTextAfterToken);

    compactTextBeforeToken = new StringArgument('c', "compactTextBeforeToken",
         false, 1, INFO_DELIVER_PW_RESET_TOKEN_PLACEHOLDER_COMPACT_BEFORE.get(),
         INFO_DELIVER_PW_RESET_TOKEN_DESCRIPTION_COMPACT_BEFORE.get());
    compactTextBeforeToken.setArgumentGroupName(
         INFO_DELIVER_PW_RESET_TOKEN_GROUP_DELIVERY_MECH.get());
    compactTextBeforeToken.addLongIdentifier("compact-text-before-token", true);
    parser.addArgument(compactTextBeforeToken);

    compactTextAfterToken = new StringArgument('C', "compactTextAfterToken",
         false, 1, INFO_DELIVER_PW_RESET_TOKEN_PLACEHOLDER_COMPACT_AFTER.get(),
         INFO_DELIVER_PW_RESET_TOKEN_DESCRIPTION_COMPACT_AFTER.get());
    compactTextAfterToken.setArgumentGroupName(
         INFO_DELIVER_PW_RESET_TOKEN_GROUP_DELIVERY_MECH.get());
    compactTextAfterToken.addLongIdentifier("compact-text-after-token", true);
    parser.addArgument(compactTextAfterToken);
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
  protected boolean supportsOutputFile()
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
   * Indicates whether this tool supports the use of a properties file for
   * specifying default values for arguments that aren't specified on the
   * command line.
   *
   * @return  {@code true} if this tool supports the use of a properties file
   *          for specifying default values for arguments that aren't specified
   *          on the command line, or {@code false} if not.
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * Indicates whether the LDAP-specific arguments should include alternate
   * versions of all long identifiers that consist of multiple words so that
   * they are available in both camelCase and dash-separated versions.
   *
   * @return  {@code true} if this tool should provide multiple versions of
   *          long identifiers for LDAP-specific arguments, or {@code false} if
   *          not.
   */
  @Override()
  protected boolean includeAlternateLongIdentifiers()
  {
    return true;
  }



  /**
   * Indicates whether this tool should provide a command-line argument that
   * allows for low-level SSL debugging.  If this returns {@code true}, then an
   * "--enableSSLDebugging}" argument will be added that sets the
   * "javax.net.debug" system property to "all" before attempting any
   * communication.
   *
   * @return  {@code true} if this tool should offer an "--enableSSLDebugging"
   *          argument, or {@code false} if not.
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
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Get the set of preferred delivery mechanisms.
    final ArrayList<ObjectPair<String,String>> preferredDeliveryMechanisms;
    if (deliveryMechanism.isPresent())
    {
      final List<String> dmList = deliveryMechanism.getValues();
      preferredDeliveryMechanisms = new ArrayList<>(dmList.size());
      for (final String s : dmList)
      {
        preferredDeliveryMechanisms.add(new ObjectPair<String,String>(s, null));
      }
    }
    else
    {
      preferredDeliveryMechanisms = null;
    }


    // Get a connection to the directory server.
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      err(ERR_DELIVER_PW_RESET_TOKEN_CANNOT_GET_CONNECTION.get(
           StaticUtils.getExceptionMessage(le)));
      return le.getResultCode();
    }

    try
    {
      // Create and send the extended request
      final DeliverPasswordResetTokenExtendedRequest request =
           new DeliverPasswordResetTokenExtendedRequest(userDN.getStringValue(),
                messageSubject.getValue(), fullTextBeforeToken.getValue(),
                fullTextAfterToken.getValue(),
                compactTextBeforeToken.getValue(),
                compactTextAfterToken.getValue(), preferredDeliveryMechanisms);
      final DeliverPasswordResetTokenExtendedResult result;
      try
      {
        result = (DeliverPasswordResetTokenExtendedResult)
             conn.processExtendedOperation(request);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err(ERR_DELIVER_PW_RESET_TOKEN_ERROR_PROCESSING_EXTOP.get(
             StaticUtils.getExceptionMessage(le)));
        return le.getResultCode();
      }

      if (result.getResultCode() == ResultCode.SUCCESS)
      {
        final String mechanism = result.getDeliveryMechanism();
        final String id = result.getRecipientID();
        if (id == null)
        {
          out(INFO_DELIVER_PW_RESET_TOKEN_SUCCESS_RESULT_WITHOUT_ID.get(
               mechanism));
        }
        else
        {
          out(INFO_DELIVER_PW_RESET_TOKEN_SUCCESS_RESULT_WITH_ID.get(mechanism,
               id));
        }

        final String message = result.getDeliveryMessage();
        if (message != null)
        {
          out(INFO_DELIVER_PW_RESET_TOKEN_SUCCESS_MESSAGE.get(message));
        }
      }
      else
      {
        if (result.getDiagnosticMessage() == null)
        {
          err(ERR_DELIVER_PW_RESET_TOKEN_ERROR_RESULT_NO_MESSAGE.get(
               String.valueOf(result.getResultCode())));
        }
        else
        {
          err(ERR_DELIVER_PW_RESET_TOKEN_ERROR_RESULT.get(
               String.valueOf(result.getResultCode()),
               result.getDiagnosticMessage()));
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
    final LinkedHashMap<String[],String> exampleMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

    final String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--bindDN", "uid=password.admin,ou=People,dc=example,dc=com",
      "--bindPassword", "password",
      "--userDN", "uid=test.user,ou=People,dc=example,dc=com",
      "--deliveryMechanism", "SMS",
      "--deliveryMechanism", "E-Mail",
      "--messageSubject", "Your password reset token",
      "--fullTextBeforeToken", "Your single-use password reset token is '",
      "--fullTextAfterToken", "'.",
      "--compactTextBeforeToken", "Your single-use password reset token is '",
      "--compactTextAfterToken", "'.",
    };
    exampleMap.put(args,
         INFO_DELIVER_PW_RESET_TOKEN_EXAMPLE.get());

    return exampleMap;
  }
}
