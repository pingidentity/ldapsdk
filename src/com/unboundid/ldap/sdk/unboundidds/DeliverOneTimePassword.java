/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
            DeliverOneTimePasswordExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            DeliverOneTimePasswordExtendedResult;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides a utility that may be used to request that the Directory
 * Server deliver a one-time password to a user through some out-of-band
 * mechanism.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class DeliverOneTimePassword
       extends LDAPCommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7414730592661321416L;



  // Indicates that the tool should interactively prompt the user for their
  // bind password.
  private BooleanArgument promptForBindPassword;

  // The DN for the user to whom the one-time password should be delivered.
  private DNArgument bindDN;

  // The path to a file containing the static password for the user to whom the
  // one-time password should be delivered.
  private FileArgument bindPasswordFile;

  // The text to include after the one-time password in the "compact" message.
  private StringArgument compactTextAfterOTP;

  // The text to include before the one-time password in the "compact" message.
  private StringArgument compactTextBeforeOTP;

  // The name of the mechanism through which the one-time password should be
  // delivered.
  private StringArgument deliveryMechanism;

  // The text to include after the one-time password in the "full" message.
  private StringArgument fullTextAfterOTP;

  // The text to include before the one-time password in the "full" message.
  private StringArgument fullTextBeforeOTP;

  // The subject to use for the message containing the delivered token.
  private StringArgument messageSubject;

  // The username for the user to whom the one-time password should be
  // delivered.
  private StringArgument userName;

  // The static password for the user to whom the one-time password should be
  // delivered.
  private StringArgument bindPassword;



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(final String... args)
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
  public static ResultCode main(final String[] args,
                                final OutputStream outStream,
                                final OutputStream errStream)
  {
    final DeliverOneTimePassword tool =
         new DeliverOneTimePassword(outStream, errStream);
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
  public DeliverOneTimePassword(final OutputStream outStream,
                                final OutputStream errStream)
  {
    super(outStream, errStream);

    promptForBindPassword = null;
    bindDN                = null;
    bindPasswordFile      = null;
    bindPassword          = null;
    compactTextAfterOTP   = null;
    compactTextBeforeOTP  = null;
    deliveryMechanism     = null;
    fullTextAfterOTP      = null;
    fullTextBeforeOTP     = null;
    messageSubject        = null;
    userName              = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolName()
  {
    return "deliver-one-time-password";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolDescription()
  {
    return INFO_DELIVER_OTP_TOOL_DESCRIPTION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    bindDN = new DNArgument('D', "bindDN", false, 1,
         INFO_DELIVER_OTP_PLACEHOLDER_DN.get(),
         INFO_DELIVER_OTP_DESCRIPTION_BIND_DN.get());
    bindDN.setArgumentGroupName(INFO_DELIVER_OTP_GROUP_ID_AND_AUTH.get());
    bindDN.addLongIdentifier("bind-dn", true);
    parser.addArgument(bindDN);

    userName = new StringArgument('n', "userName", false, 1,
         INFO_DELIVER_OTP_PLACEHOLDER_USERNAME.get(),
         INFO_DELIVER_OTP_DESCRIPTION_USERNAME.get());
    userName.setArgumentGroupName(INFO_DELIVER_OTP_GROUP_ID_AND_AUTH.get());
    userName.addLongIdentifier("user-name", true);
    parser.addArgument(userName);

    bindPassword = new StringArgument('w', "bindPassword", false, 1,
         INFO_DELIVER_OTP_PLACEHOLDER_PASSWORD.get(),
         INFO_DELIVER_OTP_DESCRIPTION_BIND_PW.get());
    bindPassword.setSensitive(true);
    bindPassword.setArgumentGroupName(INFO_DELIVER_OTP_GROUP_ID_AND_AUTH.get());
    bindPassword.addLongIdentifier("bind-password", true);
    parser.addArgument(bindPassword);

    bindPasswordFile = new FileArgument('j', "bindPasswordFile", false, 1,
         INFO_DELIVER_OTP_PLACEHOLDER_PATH.get(),
         INFO_DELIVER_OTP_DESCRIPTION_BIND_PW_FILE.get(), true, true, true,
         false);
    bindPasswordFile.setArgumentGroupName(
         INFO_DELIVER_OTP_GROUP_ID_AND_AUTH.get());
    bindPasswordFile.addLongIdentifier("bind-password-file", true);
    parser.addArgument(bindPasswordFile);

    promptForBindPassword = new BooleanArgument(null, "promptForBindPassword",
         1, INFO_DELIVER_OTP_DESCRIPTION_BIND_PW_PROMPT.get());
    promptForBindPassword.setArgumentGroupName(
         INFO_DELIVER_OTP_GROUP_ID_AND_AUTH.get());
    promptForBindPassword.addLongIdentifier("prompt-for-bind-password", true);
    parser.addArgument(promptForBindPassword);

    deliveryMechanism = new StringArgument('m', "deliveryMechanism", false, 0,
         INFO_DELIVER_OTP_PLACEHOLDER_NAME.get(),
         INFO_DELIVER_OTP_DESCRIPTION_MECH.get());
    deliveryMechanism.setArgumentGroupName(
         INFO_DELIVER_OTP_GROUP_DELIVERY_MECH.get());
    deliveryMechanism.addLongIdentifier("delivery-mechanism", true);
    parser.addArgument(deliveryMechanism);

    messageSubject = new StringArgument('s', "messageSubject", false, 1,
         INFO_DELIVER_OTP_PLACEHOLDER_SUBJECT.get(),
         INFO_DELIVER_OTP_DESCRIPTION_SUBJECT.get());
    messageSubject.setArgumentGroupName(
         INFO_DELIVER_OTP_GROUP_DELIVERY_MECH.get());
    messageSubject.addLongIdentifier("message-subject", true);
    parser.addArgument(messageSubject);

    fullTextBeforeOTP = new StringArgument('f', "fullTextBeforeOTP", false,
         1, INFO_DELIVER_OTP_PLACEHOLDER_FULL_BEFORE.get(),
         INFO_DELIVER_OTP_DESCRIPTION_FULL_BEFORE.get());
    fullTextBeforeOTP.setArgumentGroupName(
         INFO_DELIVER_OTP_GROUP_DELIVERY_MECH.get());
    fullTextBeforeOTP.addLongIdentifier("full-text-before-otp", true);
    parser.addArgument(fullTextBeforeOTP);

    fullTextAfterOTP = new StringArgument('F', "fullTextAfterOTP", false,
         1, INFO_DELIVER_OTP_PLACEHOLDER_FULL_AFTER.get(),
         INFO_DELIVER_OTP_DESCRIPTION_FULL_AFTER.get());
    fullTextAfterOTP.setArgumentGroupName(
         INFO_DELIVER_OTP_GROUP_DELIVERY_MECH.get());
    fullTextAfterOTP.addLongIdentifier("full-text-after-otp", true);
    parser.addArgument(fullTextAfterOTP);

    compactTextBeforeOTP = new StringArgument('c', "compactTextBeforeOTP",
         false, 1, INFO_DELIVER_OTP_PLACEHOLDER_COMPACT_BEFORE.get(),
         INFO_DELIVER_OTP_DESCRIPTION_COMPACT_BEFORE.get());
    compactTextBeforeOTP.setArgumentGroupName(
         INFO_DELIVER_OTP_GROUP_DELIVERY_MECH.get());
    compactTextBeforeOTP.addLongIdentifier("compact-text-before-otp", true);
    parser.addArgument(compactTextBeforeOTP);

    compactTextAfterOTP = new StringArgument('C', "compactTextAfterOTP",
         false, 1, INFO_DELIVER_OTP_PLACEHOLDER_COMPACT_AFTER.get(),
         INFO_DELIVER_OTP_DESCRIPTION_COMPACT_AFTER.get());
    compactTextAfterOTP.setArgumentGroupName(
         INFO_DELIVER_OTP_GROUP_DELIVERY_MECH.get());
    compactTextAfterOTP.addLongIdentifier("compact-text-after-otp", true);
    parser.addArgument(compactTextAfterOTP);


    // Either the bind DN or username must have been provided.
    parser.addRequiredArgumentSet(bindDN, userName);

    // Only one option may be used for specifying the user identity.
    parser.addExclusiveArgumentSet(bindDN, userName);

    // Only one option may be used for specifying the bind password.
    parser.addExclusiveArgumentSet(bindPassword, bindPasswordFile,
         promptForBindPassword);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsAuthentication()
  {
    return false;
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
  public ResultCode doToolProcessing()
  {
    // Construct the authentication identity.
    final String authID;
    if (bindDN.isPresent())
    {
      authID = "dn:" + bindDN.getValue();
    }
    else
    {
      authID = "u:" + userName.getValue();
    }


    // Get the bind password.
    final String pw;
    if (bindPassword.isPresent())
    {
      pw = bindPassword.getValue();
    }
    else if (bindPasswordFile.isPresent())
    {
      try
      {
        pw = bindPasswordFile.getNonBlankFileLines().get(0);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err(ERR_DELIVER_OTP_CANNOT_READ_BIND_PW.get(
             StaticUtils.getExceptionMessage(e)));
        return ResultCode.LOCAL_ERROR;
      }
    }
    else
    {
      try
      {
        getOut().print(INFO_DELIVER_OTP_ENTER_PW.get());
        pw = StaticUtils.toUTF8String(PasswordReader.readPassword());
        getOut().println();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err(ERR_DELIVER_OTP_CANNOT_READ_BIND_PW.get(
             StaticUtils.getExceptionMessage(e)));
        return ResultCode.LOCAL_ERROR;
      }
    }


    // Get the set of preferred delivery mechanisms.
    final ArrayList<ObjectPair<String,String>> preferredDeliveryMechanisms;
    if (deliveryMechanism.isPresent())
    {
      final List<String> dmList = deliveryMechanism.getValues();
      preferredDeliveryMechanisms =
           new ArrayList<ObjectPair<String,String>>(dmList.size());
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
      err(ERR_DELIVER_OTP_CANNOT_GET_CONNECTION.get(
           StaticUtils.getExceptionMessage(le)));
      return le.getResultCode();
    }

    try
    {
      // Create and send the extended request
      final DeliverOneTimePasswordExtendedRequest request =
           new DeliverOneTimePasswordExtendedRequest(authID, pw,
                messageSubject.getValue(), fullTextBeforeOTP.getValue(),
                fullTextAfterOTP.getValue(), compactTextBeforeOTP.getValue(),
                compactTextAfterOTP.getValue(), preferredDeliveryMechanisms);
      final DeliverOneTimePasswordExtendedResult result;
      try
      {
        result = (DeliverOneTimePasswordExtendedResult)
             conn.processExtendedOperation(request);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err(ERR_DELIVER_OTP_ERROR_PROCESSING_EXTOP.get(
             StaticUtils.getExceptionMessage(le)));
        return le.getResultCode();
      }

      if (result.getResultCode() == ResultCode.SUCCESS)
      {
        final String mechanism = result.getDeliveryMechanism();
        final String id = result.getRecipientID();
        if (id == null)
        {
          out(INFO_DELIVER_OTP_SUCCESS_RESULT_WITHOUT_ID.get(mechanism));
        }
        else
        {
          out(INFO_DELIVER_OTP_SUCCESS_RESULT_WITH_ID.get(mechanism, id));
        }

        final String message = result.getDeliveryMessage();
        if (message != null)
        {
          out(INFO_DELIVER_OTP_SUCCESS_MESSAGE.get(message));
        }
      }
      else
      {
        if (result.getDiagnosticMessage() == null)
        {
          err(ERR_DELIVER_OTP_ERROR_RESULT_NO_MESSAGE.get(
               String.valueOf(result.getResultCode())));
        }
        else
        {
          err(ERR_DELIVER_OTP_ERROR_RESULT.get(
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
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> exampleMap =
         new LinkedHashMap<String[],String>(2);

    String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--bindDN", "uid=test.user,ou=People,dc=example,dc=com",
      "--bindPassword", "password",
      "--messageSubject", "Your one-time password",
      "--fullTextBeforeOTP", "Your one-time password is '",
      "--fullTextAfterOTP", "'.",
      "--compactTextBeforeOTP", "Your OTP is '",
      "--compactTextAfterOTP", "'.",
    };
    exampleMap.put(args,
         INFO_DELIVER_OTP_EXAMPLE_1.get());

    args = new String[]
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--userName", "test.user",
      "--bindPassword", "password",
      "--deliveryMechanism", "SMS",
      "--deliveryMechanism", "E-Mail",
      "--messageSubject", "Your one-time password",
      "--fullTextBeforeOTP", "Your one-time password is '",
      "--fullTextAfterOTP", "'.",
      "--compactTextBeforeOTP", "Your OTP is '",
      "--compactTextAfterOTP", "'.",
    };
    exampleMap.put(args,
         INFO_DELIVER_OTP_EXAMPLE_2.get());

    return exampleMap;
  }
}
