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
package com.unboundid.util;



import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.LDAPConnectionHandlerConfiguration;
import com.unboundid.util.args.Argument;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentHelper;
import com.unboundid.util.args.ArgumentListArgument;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.BooleanValueArgument;
import com.unboundid.util.args.ControlArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.DurationArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.ScopeArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.args.SubCommand;
import com.unboundid.util.args.TimestampArgument;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class performs the appropriate processing to obtain values to use for
 * command-line arguments when a tool is invoked in interactive mode.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class CommandLineToolInteractiveModeProcessor
{
  /**
   * Indicates whether this processor is being run in a unit test environment.
   * If so, then we will read passwords in a way that is compatible with the
   * unit test framework.
   */
  private static volatile boolean IN_UNIT_TEST = false;



  // The argument parser for the command-line tool.
  @NotNull private final ArgumentParser parser;

  // The reader that may be used to read from standard input.
  @NotNull private final BufferedReader systemInReader;

  // The associated command-line tool.
  @NotNull private final CommandLineTool tool;

  // The maximum column length to use when wrapping long lines.
  private final int wrapColumn;



  /**
   * Creates a new instance of this command-line tool interactive mode
   * processor with the provided information.
   *
   * @param  tool    The command-line tool for which to perform interactive mode
   *                 processing.
   * @param  parser  The argument parser for the provided command-line tool.
   */
  CommandLineToolInteractiveModeProcessor(@NotNull final CommandLineTool tool,
                                          @NotNull final ArgumentParser parser)
  {
    this.tool   = tool;
    this.parser = parser;

    systemInReader = new BufferedReader(new InputStreamReader(System.in));
    wrapColumn = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;

    ArgumentHelper.reset(parser.getNamedArgument("interactive"));
  }



  /**
   * Performs the appropriate interactive mode processing for the tool.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  void doInteractiveModeProcessing()
       throws LDAPException
  {
    tool.wrapStandardOut(0, 0, wrapColumn, true,
         INFO_INTERACTIVE_LAUNCHING.get(tool.getToolName()));

    final List<String> allArgs = new ArrayList<>(10);

    final List<SubCommand> subCommands = parser.getSubCommands();
    if (! subCommands.isEmpty())
    {
      final SubCommand subcommand = promptForSubCommand();
      ArgumentHelper.setSelectedSubCommand(parser, subcommand);
      allArgs.add(subcommand.getPrimaryName());
    }

    final List<String> ldapArgs = new ArrayList<>(10);
    if (tool instanceof LDAPCommandLineTool)
    {
      promptForLDAPArguments(ldapArgs, true);
    }
    else if (tool instanceof MultiServerLDAPCommandLineTool)
    {
      promptForMultiServerLDAPArguments(ldapArgs, true);
    }

    allArgs.addAll(ldapArgs);

    final List<String> toolArgs = displayInteractiveMenu(ldapArgs);
    allArgs.addAll(toolArgs);

    tool.out();
    if (allArgs.isEmpty())
    {
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_RUNNING_WITH_NO_ARGS.get(tool.getToolName()));
    }
    else
    {
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_RUNNING_WITH_ARGS.get());
      printArgs(allArgs);
    }
    tool.out();
  }



  /**
   * Prints the provided arguments in a user-friendly way to standard output.
   *
   * @param  args  The arguments to be printed.
   */
  private void printArgs(@NotNull final List<String> args)
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append("     ");
    buffer.append(tool.getToolName());
    if (! args.isEmpty())
    {
      buffer.append(' ');
      buffer.append(StaticUtils.getCommandLineContinuationString());
    }
    tool.out(buffer);

    for (int i=0; i < args.size(); i++)
    {
      buffer.setLength(0);
      buffer.append("          ");

      final String arg = args.get(i);
      buffer.append(ExampleCommandLineArgument.getCleanArgument(
           arg).getLocalForm());

      if (arg.startsWith("-") && ((i+1) < args.size()))
      {
        final String nextArg = args.get(i+1);
        if (! nextArg.startsWith("-"))
        {
          buffer.append(' ');
          buffer.append(ExampleCommandLineArgument.getCleanArgument(
               nextArg).getLocalForm());
          i++;
        }
      }

      if (i < (args.size() - 1))
      {
        buffer.append(' ');
        buffer.append(StaticUtils.getCommandLineContinuationString());
      }

      tool.out(buffer);
    }
  }



  /**
   * Interactively prompts for the subcommand that should be used when running
   * the tool.
   *
   * @return  The selected subcommand.
   *
   * @throws  LDAPException  If a problem is encountered while determining which
   *                         subcommand to use.
   */
  @NotNull()
  private SubCommand promptForSubCommand()
          throws LDAPException
  {
    // Get all of the subcommands sorted by name.
    final List<SubCommand> subCommands = parser.getSubCommands();
    final TreeMap<String,SubCommand> subCommandsByName = new TreeMap<>();
    for (final SubCommand sc : subCommands)
    {
      subCommandsByName.put(sc.getPrimaryName(), sc);
    }


    // Create an array of the subcommand names we want to use.
    int index = 0;
    final String[] subCommandNames = new String[subCommandsByName.size()];
    for (final SubCommand sc : subCommandsByName.values())
    {
      subCommandNames[index++] = sc.getPrimaryName();
    }


    // Prompt the user to determine which subcommand to use, and associate that
    // with the target subcommand.
    final int selectedSubCommandNumber = getNumberedMenuChoice(
         INFO_INTERACTIVE_SUBCOMMAND_PROMPT.get(), false, null,
         subCommandNames);
    return parser.getSubCommand(subCommandNames[selectedSubCommandNumber]);
  }



  /**
   * Interactively prompts for the arguments used to connect and optionally
   * authenticate to the directory server.
   *
   * @param  argList  The list to which the string representations of all LDAP
   *                  arguments should be added.
   * @param  test     Indicates whether to attempt to use the arguments to
   *                  establish an LDAP connection.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForLDAPArguments(@NotNull final List<String> argList,
                                      final boolean test)
          throws LDAPException
  {
    final LDAPCommandLineTool ldapTool = (LDAPCommandLineTool) tool;
    argList.clear();


    // Get the address of the directory server.
    final String defaultHostname;
    final StringArgument hostnameArgument =
         parser.getStringArgument("hostname");
    if (hostnameArgument.isPresent())
    {
      defaultHostname = hostnameArgument.getValue();
    }
    else
    {
      defaultHostname = "localhost";
    }

    ArgumentHelper.reset(hostnameArgument);

    final String hostname = promptForString(
         INFO_INTERACTIVE_LDAP_PROMPT_HOST.get(), defaultHostname, true);
    ArgumentHelper.addValueSuppressException(hostnameArgument, hostname);

    argList.add("--hostname");
    argList.add(hostname);


    // If this tool is running with access to Directory Server data, and if the
    // selected hostname is "localhost" or a loopback address, then try to load
    // information about the server's connection handlers.
    List<LDAPConnectionHandlerConfiguration> serverListenerConfigs = null;
    final File dsInstanceRoot = InternalSDKHelper.getPingIdentityServerRoot();
    if (dsInstanceRoot != null)
    {
      final File configFile = StaticUtils.constructPath(dsInstanceRoot,
           "config", "config.ldif");
      if (configFile.exists() && configFile.isFile())
      {
        try
        {
          serverListenerConfigs = LDAPConnectionHandlerConfiguration.
               readConfiguration(configFile, true);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }


    // Determine the type of connection security to use.
    final BooleanArgument useSSLArgument = parser.getBooleanArgument("useSSL");
    final BooleanArgument useStartTLSArgument =
         parser.getBooleanArgument("useStartTLS");

    final String defaultSecurityChoice;
    if (useSSLArgument.isPresent())
    {
      defaultSecurityChoice = "1";
    }
    else if (useStartTLSArgument.isPresent())
    {
      defaultSecurityChoice = "3";
    }
    else if ((serverListenerConfigs != null) &&
         (! serverListenerConfigs.isEmpty()))
    {
      final LDAPConnectionHandlerConfiguration cfg =
           serverListenerConfigs.get(0);
      if (cfg.usesSSL())
      {
        defaultSecurityChoice = "1";
      }
      else if (cfg.supportsStartTLS())
      {
        defaultSecurityChoice = "3";
      }
      else
      {
        defaultSecurityChoice = "5";
      }
    }
    else
    {
      defaultSecurityChoice = "1";
    }

    ArgumentHelper.reset(useSSLArgument);
    ArgumentHelper.reset(useStartTLSArgument);

    final boolean useSSL;
    final boolean useStartTLS;
    final boolean defaultTrust;
    final int securityType = getNumberedMenuChoice(
         INFO_INTERACTIVE_LDAP_SECURITY_PROMPT.get(),
         false,
         defaultSecurityChoice,
         INFO_INTERACTIVE_LDAP_SECURITY_OPTION_SSL_DEFAULT.get(),
         INFO_INTERACTIVE_LDAP_SECURITY_OPTION_SSL_MANUAL.get(),
         INFO_INTERACTIVE_LDAP_SECURITY_OPTION_START_TLS_DEFAULT.get(),
         INFO_INTERACTIVE_LDAP_SECURITY_OPTION_START_TLS_MANUAL.get(),
         INFO_INTERACTIVE_LDAP_SECURITY_OPTION_NONE.get());
    switch (securityType)
    {
      case 0:
        useSSL = true;
        useStartTLS = false;
        defaultTrust = true;
        argList.add("--useSSL");
        ArgumentHelper.incrementOccurrencesSuppressException(useSSLArgument);
        break;
      case 1:
        useSSL = true;
        useStartTLS = false;
        defaultTrust = false;
        argList.add("--useSSL");
        ArgumentHelper.incrementOccurrencesSuppressException(useSSLArgument);
        break;
      case 2:
        useSSL = false;
        useStartTLS = true;
        defaultTrust = true;
        argList.add("--useStartTLS");
        ArgumentHelper.incrementOccurrencesSuppressException(
             useStartTLSArgument);
        break;
      case 3:
        useSSL = false;
        useStartTLS = true;
        defaultTrust = false;
        argList.add("--useStartTLS");
        ArgumentHelper.incrementOccurrencesSuppressException(
             useStartTLSArgument);
        break;
      case 4:
      default:
        useSSL = false;
        useStartTLS = false;
        defaultTrust = false;
        break;
    }


    // If we are to use security without default trust configuration, then
    // prompt for the appropriate settings.
    BindRequest bindRequest = null;
    boolean trustAll = false;
    byte[] keyStorePIN = null;
    byte[] trustStorePIN = null;
    File keyStorePath = null;
    File trustStorePath = null;
    String certificateNickname = null;
    String keyStoreFormat = null;
    String trustStoreFormat = null;
    final StringArgument keyStorePasswordArgument =
         parser.getStringArgument("keyStorePassword");
    final StringArgument trustStorePasswordArgument =
         parser.getStringArgument("trustStorePassword");
    final StringArgument saslOptionArgument =
         parser.getStringArgument("saslOption");
    if (! defaultTrust)
    {
      // If the user wants to connect securely, then get the appropriate set of
      // arguments pertaining to key and trust managers.
      ArgumentHelper.reset(keyStorePasswordArgument);
      ArgumentHelper.reset(trustStorePasswordArgument);
      ArgumentHelper.reset(parser.getNamedArgument("keyStorePasswordFile"));
      ArgumentHelper.reset(parser.getNamedArgument(
           "promptForKeyStorePassword"));
      ArgumentHelper.reset(parser.getNamedArgument("trustStorePasswordFile"));
      ArgumentHelper.reset(parser.getNamedArgument(
           "promptForTrustStorePassword"));

      if (useSSL || useStartTLS)
      {
        final StringArgument keyStorePathArgument =
             parser.getStringArgument("keyStorePath");
        final StringArgument keyStoreFormatArgument =
             parser.getStringArgument("keyStoreFormat");

        // Determine if a client certificate should be presented.
        final String defaultStoreTypeChoice;
        if (keyStoreFormatArgument.isPresent())
        {
          final String format = keyStoreFormatArgument.getValue();
          if (format.equalsIgnoreCase(CryptoHelper.KEY_STORE_TYPE_PKCS_12))
          {
            defaultStoreTypeChoice = "3";
          }
          else
          {
            defaultStoreTypeChoice = "2";
          }
        }
        else if (keyStorePathArgument.isPresent())
        {
          defaultStoreTypeChoice = "2";
        }
        else
        {
          defaultStoreTypeChoice = "1";
        }

        final String defaultKeyStorePath;
        if (keyStorePathArgument.isPresent())
        {
          defaultKeyStorePath = keyStorePathArgument.getValue();
        }
        else
        {
          defaultKeyStorePath = null;
        }

        final String defaultCertNickname;
        final StringArgument certNicknameArgument =
             parser.getStringArgument("certNickname");
        if (certNicknameArgument.isPresent())
        {
          defaultCertNickname = certNicknameArgument.getValue();
        }
        else
        {
          defaultCertNickname = null;
        }

        ArgumentHelper.reset(keyStorePathArgument);
        ArgumentHelper.reset(keyStoreFormatArgument);
        ArgumentHelper.reset(certNicknameArgument);

        final int keystoreType = getNumberedMenuChoice(
             INFO_INTERACTIVE_LDAP_CLIENT_CERT_PROMPT.get(),
             false,
             defaultStoreTypeChoice,
             INFO_INTERACTIVE_LDAP_CLIENT_CERT_OPTION_NO.get(),
             INFO_INTERACTIVE_LDAP_CLIENT_CERT_OPTION_JKS.get(),
             INFO_INTERACTIVE_LDAP_CLIENT_CERT_OPTION_PKCS12.get());
        ArgumentHelper.reset(keyStoreFormatArgument);

        switch (keystoreType)
        {
          case 1:
            keyStoreFormat = CryptoHelper.KEY_STORE_TYPE_JKS;
            break;
          case 2:
            keyStoreFormat = CryptoHelper.KEY_STORE_TYPE_PKCS_12;
            break;
          case 0:
          default:
            break;
        }

        if (keyStoreFormat != null)
        {
          ArgumentHelper.addValueSuppressException(keyStoreFormatArgument,
               keyStoreFormat);

          // Get the path to the keystore file.
          keyStorePath = promptForPath(
               INFO_INTERACTIVE_LDAP_KEYSTORE_PATH_PROMPT.get(),
               defaultKeyStorePath, true, true, true, true, false);
          argList.add("--keyStorePath");
          argList.add(keyStorePath.getAbsolutePath());
          ArgumentHelper.addValueSuppressException(keyStorePathArgument,
               keyStorePath.getAbsolutePath());

          // Get the PIN needed to access the keystore.
          keyStorePIN = promptForPassword(
               INFO_INTERACTIVE_LDAP_KEYSTORE_PIN_PROMPT.get(), null, false);
          if (keyStorePIN != null)
          {
            argList.add("--keyStorePassword");
            argList.add("***REDACTED***");
            ArgumentHelper.addValueSuppressException(keyStorePasswordArgument,
                 StaticUtils.toUTF8String(keyStorePIN));
          }

          argList.add("--keyStoreFormat");
          argList.add(keyStoreFormat);

          certificateNickname = promptForString(
               INFO_INTERACTIVE_LDAP_CERT_NICKNAME_PROMPT.get(),
               defaultCertNickname, false);
          if (certificateNickname != null)
          {
            argList.add("--certNickname");
            argList.add(certificateNickname);
            ArgumentHelper.addValueSuppressException(certNicknameArgument,
                 certificateNickname);
          }

          if (ldapTool.supportsAuthentication() && promptForYesNo(
               INFO_INTERACTIVE_LDAP_CERT_AUTH_PROMPT.get(), false, true))
          {
            bindRequest = new EXTERNALBindRequest();
            argList.add("--saslOption");
            argList.add("mech=EXTERNAL");

            ArgumentHelper.reset(saslOptionArgument);
            ArgumentHelper.addValueSuppressException(saslOptionArgument,
                 "mech=EXTERNAL");
          }
        }

        // Determine how to trust the server certificate.
        final BooleanArgument trustAllArgument =
             parser.getBooleanArgument("trustAll");
        final StringArgument trustStorePathArgument =
             parser.getStringArgument("trustStorePath");
        final StringArgument trustStoreFormatArgument =
             parser.getStringArgument("trustStoreFormat");

        final String defaultTrustTypeChoice;
        if (trustAllArgument.isPresent())
        {
          defaultTrustTypeChoice = "4";
        }
        else if (trustStoreFormatArgument.isPresent())
        {
          final String format = trustStoreFormatArgument.getValue();
          if (format.equalsIgnoreCase(CryptoHelper.KEY_STORE_TYPE_PKCS_12))
          {
            defaultTrustTypeChoice = "3";
          }
          else
          {
            defaultTrustTypeChoice = "2";
          }
        }
        else if (trustStorePathArgument.isPresent())
        {
          defaultTrustTypeChoice = "2";
        }
        else
        {
          defaultTrustTypeChoice = "1";
        }

        final String defaultTrustStorePath;
        if (trustStorePathArgument.isPresent())
        {
          defaultTrustStorePath = trustStorePathArgument.getValue();
        }
        else
        {
          defaultTrustStorePath = null;
        }
        ArgumentHelper.reset(trustAllArgument);
        ArgumentHelper.reset(trustStorePathArgument);
        ArgumentHelper.reset(trustStoreFormatArgument);

        final int trustType = getNumberedMenuChoice(
             INFO_INTERACTIVE_LDAP_TRUST_PROMPT.get(),
             false,
             defaultTrustTypeChoice,
             INFO_INTERACTIVE_LDAP_TRUST_OPTION_PROMPT.get(),
             INFO_INTERACTIVE_LDAP_TRUST_OPTION_JKS.get(),
             INFO_INTERACTIVE_LDAP_TRUST_OPTION_PKCS12.get(),
             INFO_INTERACTIVE_LDAP_TRUST_OPTION_BLIND.get());
        switch (trustType)
        {
          case 1:
            trustStoreFormat = CryptoHelper.KEY_STORE_TYPE_JKS;
            break;
          case 2:
            trustStoreFormat = CryptoHelper.KEY_STORE_TYPE_PKCS_12;
            break;
          case 3:
            trustAll = true;
            argList.add("--trustAll");
            ArgumentHelper.incrementOccurrencesSuppressException(
                 trustAllArgument);
            break;
          case 0:
          default:
            // We will interactively prompt the user about whether to trust the
            // certificate in the test section below.  However, to avoid
            // prompting the user twice, we will configure the tool behind the
            // scenes to trust all certificates.
            ArgumentHelper.incrementOccurrencesSuppressException(
                 trustAllArgument);
            break;
        }

        if (trustStoreFormat != null)
        {
          ArgumentHelper.addValueSuppressException(trustStoreFormatArgument,
               trustStoreFormat);

          // Get the path to the truststore file.
          trustStorePath = promptForPath(
               INFO_INTERACTIVE_LDAP_TRUSTSTORE_PATH_PROMPT.get(),
               defaultTrustStorePath, true, true, true, true, false);
          argList.add("--trustStorePath");
          argList.add(trustStorePath.getAbsolutePath());
          ArgumentHelper.addValueSuppressException(trustStorePathArgument,
               trustStorePath.getAbsolutePath());

          // Get the PIN needed to access the truststore.
          trustStorePIN = promptForPassword(
               INFO_INTERACTIVE_LDAP_TRUSTSTORE_PIN_PROMPT.get(), null, false);
          if (trustStorePIN != null)
          {
            argList.add("--trustStorePassword");
            argList.add("***REDACTED***");
            ArgumentHelper.addValueSuppressException(trustStorePasswordArgument,
                 StaticUtils.toUTF8String(trustStorePIN));
          }

          argList.add("--trustStoreFormat");
          argList.add(trustStoreFormat);
        }
      }
      else
      {
        ArgumentHelper.reset(parser.getNamedArgument("keyStorePath"));
        ArgumentHelper.reset(parser.getNamedArgument("keyStoreFormat"));
        ArgumentHelper.reset(parser.getNamedArgument("trustStorePath"));
        ArgumentHelper.reset(parser.getNamedArgument("trustStoreFormat"));
        ArgumentHelper.reset(parser.getNamedArgument("certNickname"));
      }
    }


    // Get the port of the directory server.
    int defaultPort;
    final IntegerArgument portArgument =
         parser.getIntegerArgument("port");
    if (portArgument.getNumOccurrences() > 0)
    {
      // Note -- We're using getNumOccurrences here because isPresent also
      // returns true if there is a default value, and that could be wrong in
      // this case because the default value doesn't know about SSL.
      defaultPort = portArgument.getValue();
    }
    else if (useSSL)
    {
      defaultPort = 636;
      if (serverListenerConfigs != null)
      {
        for (final LDAPConnectionHandlerConfiguration cfg :
             serverListenerConfigs)
        {
          if (cfg.usesSSL())
          {
            defaultPort = cfg.getPort();
            break;
          }
        }
      }
    }
    else if (useStartTLS)
    {
      defaultPort = 389;
      if (serverListenerConfigs != null)
      {
        for (final LDAPConnectionHandlerConfiguration cfg :
             serverListenerConfigs)
        {
          if (cfg.supportsStartTLS())
          {
            defaultPort = cfg.getPort();
            break;
          }
        }
      }
    }
    else
    {
      defaultPort = 389;
      if (serverListenerConfigs != null)
      {
        for (final LDAPConnectionHandlerConfiguration cfg :
             serverListenerConfigs)
        {
          if (! cfg.usesSSL())
          {
            defaultPort = cfg.getPort();
            break;
          }
        }
      }
    }
    ArgumentHelper.reset(portArgument);

    final int port = promptForInteger(INFO_INTERACTIVE_LDAP_PROMPT_PORT.get(),
         defaultPort, 1, 65_535, true);
    argList.add("--port");
    argList.add(String.valueOf(port));
    ArgumentHelper.addValueSuppressException(portArgument,
         String.valueOf(port));


    // Determine how to authenticate to the directory server.
    if (ldapTool.supportsAuthentication())
    {
      final DNArgument bindDNArgument =
           parser.getDNArgument("bindDN");
      final StringArgument bindPasswordArgument =
           parser.getStringArgument("bindPassword");

      ArgumentHelper.reset(bindPasswordArgument);
      ArgumentHelper.reset(parser.getNamedArgument("bindPasswordFile"));
      ArgumentHelper.reset(parser.getNamedArgument("promptForBindPassword"));

      if (bindRequest == null)
      {
        final String defaultAuthTypeChoice;
        final String defaultBindDN;
        if (saslOptionArgument.isPresent())
        {
          defaultAuthTypeChoice = "2";
          defaultBindDN = null;
        }
        else
        {
          defaultAuthTypeChoice = "1";
          if (bindDNArgument.isPresent())
          {
            defaultBindDN = bindDNArgument.getStringValue();
          }
          else
          {
            defaultBindDN = null;
          }
        }

        ArgumentHelper.reset(bindDNArgument);

        boolean useSimpleAuth = false;
        boolean useSASLAuth = false;
        final int authMethod = getNumberedMenuChoice(
             INFO_INTERACTIVE_LDAP_AUTH_PROMPT.get(),
             false,
             defaultAuthTypeChoice,
             INFO_INTERACTIVE_LDAP_AUTH_OPTION_SIMPLE.get(),
             INFO_INTERACTIVE_LDAP_AUTH_OPTION_SASL.get(),
             INFO_INTERACTIVE_LDAP_AUTH_OPTION_NONE.get());
        switch (authMethod)
        {
          case 0:
            useSimpleAuth = true;
            break;
          case 1:
            useSASLAuth = true;
            break;
          case 2:
          default:
            break;
        }

        if (useSimpleAuth)
        {
          ArgumentHelper.reset(saslOptionArgument);

          final DN bindDN = promptForDN(
               INFO_INTERACTIVE_LDAP_AUTH_BIND_DN_PROMPT.get(), defaultBindDN,
               true);
          if (bindDN.isNullDN())
          {
            bindRequest = new SimpleBindRequest();
            argList.add("--bindDN");
            argList.add("");
            argList.add("--bindPassword");
            argList.add("");

            ArgumentHelper.addValueSuppressException(bindDNArgument, "");
            ArgumentHelper.addValueSuppressException(bindPasswordArgument, "");
          }
          else
          {
            final byte[] bindPassword = promptForPassword(
                 INFO_INTERACTIVE_LDAP_AUTH_PW_PROMPT.get(), null, true);
            bindRequest = new SimpleBindRequest(bindDN, bindPassword);
            argList.add("--bindDN");
            argList.add(bindDN.toString());
            argList.add("--bindPassword");
            argList.add("***REDACTED***");

            ArgumentHelper.addValueSuppressException(bindDNArgument,
                 bindDN.toString());
            ArgumentHelper.addValueSuppressException(bindPasswordArgument,
                 StaticUtils.toUTF8String(bindPassword));
          }
        }
        else if (useSASLAuth)
        {
          String defaultMechChoice = null;
          String defaultAuthID = null;
          String defaultAuthzID = null;
          String defaultRealm = null;
          if (saslOptionArgument.isPresent())
          {
            for (final String saslOption : saslOptionArgument.getValues())
            {
              final String lowerOption = StaticUtils.toLowerCase(saslOption);
              if (lowerOption.equals("mech=cram-md5"))
              {
                defaultMechChoice = "1";
              }
              else if (lowerOption.equals("mech=digest-md5"))
              {
                defaultMechChoice = "2";
              }
              else if (lowerOption.equals("mech=plain"))
              {
                defaultMechChoice = "3";
              }
              else if (lowerOption.startsWith("authid="))
              {
                defaultAuthID = saslOption.substring(7);
              }
              else if (lowerOption.startsWith("authzid="))
              {
                defaultAuthzID = saslOption.substring(8);
              }
              else if (lowerOption.startsWith("realm="))
              {
                defaultRealm= saslOption.substring(6);
              }
            }
          }
          ArgumentHelper.reset(saslOptionArgument);

          final int mech = getNumberedMenuChoice(
               INFO_INTERACTIVE_LDAP_AUTH_SASL_PROMPT.get(),
               false,
               defaultMechChoice,
               INFO_INTERACTIVE_LDAP_SASL_OPTION_CRAM_MD5.get(),
               INFO_INTERACTIVE_LDAP_SASL_OPTION_DIGEST_MD5.get(),
               INFO_INTERACTIVE_LDAP_SASL_OPTION_PLAIN.get());
          switch (mech)
          {
            case 0:
              String authID = promptForString(
                   INFO_INTERACTIVE_LDAP_AUTH_AUTHID_PROMPT.get(),
                   defaultAuthID, true);
              byte[] pw = promptForPassword(
                   INFO_INTERACTIVE_LDAP_AUTH_PW_PROMPT.get(), null, true);
              bindRequest = new CRAMMD5BindRequest(authID, pw);

              argList.add("--saslOption");
              argList.add("mech=CRAM-MD5");
              argList.add("--saslOption");
              argList.add("authID=" + authID);
              argList.add("--bindPassword");
              argList.add("***REDACTED***");

              ArgumentHelper.addValueSuppressException(saslOptionArgument,
                   "mech=CRAM-MD5");
              ArgumentHelper.addValueSuppressException(saslOptionArgument,
                   "authID=" + authID);
              ArgumentHelper.addValueSuppressException(bindPasswordArgument,
                   StaticUtils.toUTF8String(pw));
              break;

            case 1:
              authID = promptForString(
                   INFO_INTERACTIVE_LDAP_AUTH_AUTHID_PROMPT.get(),
                   defaultAuthID, true);
              String authzID = promptForString(
                   INFO_INTERACTIVE_LDAP_AUTH_AUTHZID_PROMPT.get(),
                   defaultAuthzID, false);
              final String realm = promptForString(
                   INFO_INTERACTIVE_LDAP_AUTH_REALM_PROMPT.get(), defaultRealm,
                   false);
              pw = promptForPassword(INFO_INTERACTIVE_LDAP_AUTH_PW_PROMPT.get(),
                   null, true);
              bindRequest = new DIGESTMD5BindRequest(authID, authzID, pw,
                   realm);

              argList.add("--saslOption");
              argList.add("mech=DIGEST-MD5");
              argList.add("--saslOption");
              argList.add("authID=" + authID);
              ArgumentHelper.addValueSuppressException(saslOptionArgument,
                   "mech=DIGEST-MD5");
              ArgumentHelper.addValueSuppressException(saslOptionArgument,
                   "authID=" + authID);

              if (authzID != null)
              {
                argList.add("--saslOption");
                argList.add("authzID=" + authzID);
                ArgumentHelper.addValueSuppressException(saslOptionArgument,
                     "authzID=" + authzID);
              }

              if (realm != null)
              {
                argList.add("--saslOption");
                argList.add("realm=" + realm);
                ArgumentHelper.addValueSuppressException(saslOptionArgument,
                     "realm=" + realm);
              }

              argList.add("--bindPassword");
              argList.add("***REDACTED***");
              ArgumentHelper.addValueSuppressException(bindPasswordArgument,
                   StaticUtils.toUTF8String(pw));
              break;

            case 2:
              authID = promptForString(
                   INFO_INTERACTIVE_LDAP_AUTH_AUTHID_PROMPT.get(),
                   defaultAuthID, true);
              authzID = promptForString(
                   INFO_INTERACTIVE_LDAP_AUTH_AUTHZID_PROMPT.get(),
                   defaultAuthzID, false);
              pw = promptForPassword(INFO_INTERACTIVE_LDAP_AUTH_PW_PROMPT.get(),
                 null, true);
              bindRequest = new PLAINBindRequest(authID, authzID, pw);

              argList.add("--saslOption");
              argList.add("mech=PLAIN");
              argList.add("--saslOption");
              argList.add("authID=" + authID);
              ArgumentHelper.addValueSuppressException(saslOptionArgument,
                   "mech=PLAIN");
              ArgumentHelper.addValueSuppressException(saslOptionArgument,
                   "authID=" + authID);

              if (authzID != null)
              {
                argList.add("--saslOption");
                argList.add("authzID=" + authzID);
                ArgumentHelper.addValueSuppressException(saslOptionArgument,
                     "authzID=" + authzID);
              }

              argList.add("--bindPassword");
              argList.add("***REDACTED***");
              ArgumentHelper.addValueSuppressException(bindPasswordArgument,
                   StaticUtils.toUTF8String(pw));
              break;
          }
        }
      }
      else
      {
        ArgumentHelper.reset(bindDNArgument);
      }
    }

    if (test)
    {
      // Perform the necessary initialization for SSL/TLS communication.
      final SSLUtil sslUtil;
      if (useSSL || useStartTLS)
      {
        final KeyManager keyManager;
        if (keyStorePath == null)
        {
          keyManager = null;
        }
        else
        {
          final char[] pinChars;
          if (keyStorePIN == null)
          {
            pinChars = null;
          }
          else
          {
            final String pinString = StaticUtils.toUTF8String(keyStorePIN);
            pinChars = pinString.toCharArray();
          }

          try
          {
            keyManager = new KeyStoreKeyManager(keyStorePath, pinChars,
                 keyStoreFormat, certificateNickname, true);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            tool.wrapErr(0, wrapColumn,
                 ERR_INTERACTIVE_LDAP_CANNOT_CREATE_KEY_MANAGER.get(
                      StaticUtils.getExceptionMessage(e)));
            if (promptForYesNo(
                 INFO_INTERACTIVE_LDAP_RETRY_PROMPT.get(), true, true))
            {
              promptForLDAPArguments(argList, test);
              return;
            }
            else
            {
              throw new LDAPException(ResultCode.LOCAL_ERROR, "", e);
            }
          }
        }

        final TrustManager trustManager;
        if (trustAll)
        {
          trustManager = new TrustAllTrustManager();
        }
        else if (trustStorePath == null)
        {
          trustManager = InternalSDKHelper.getPreferredPromptTrustManagerChain(
               null);
        }
        else
        {
          final char[] pinChars;
          if (trustStorePIN == null)
          {
            pinChars = null;
          }
          else
          {
            final String pinString = StaticUtils.toUTF8String(trustStorePIN);
            pinChars = pinString.toCharArray();
          }

          try
          {
            trustManager = new TrustStoreTrustManager(trustStorePath, pinChars,
                 trustStoreFormat, true);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            tool.wrapErr(0, wrapColumn,
                 ERR_INTERACTIVE_LDAP_CANNOT_CREATE_TRUST_MANAGER.get(
                      StaticUtils.getExceptionMessage(e)));
            if (promptForYesNo(
                 INFO_INTERACTIVE_LDAP_RETRY_PROMPT.get(), true, true))
            {
              promptForLDAPArguments(argList, test);
              return;
            }
            else
            {
              throw new LDAPException(ResultCode.LOCAL_ERROR, "", e);
            }
          }
        }

        sslUtil = new SSLUtil(keyManager, trustManager);
      }
      else
      {
        sslUtil = null;
      }


      // Create and establish the connection.
      final LDAPConnection conn;
      if (useSSL)
      {
        try
        {
          conn = new LDAPConnection(sslUtil.createSSLSocketFactory());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_LDAP_CANNOT_CREATE_SOCKET_FACTORY.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
          if (promptForYesNo(
               INFO_INTERACTIVE_LDAP_RETRY_PROMPT.get(), true, true))
          {
            promptForLDAPArguments(argList, test);
            return;
          }
          else
          {
            throw new LDAPException(ResultCode.LOCAL_ERROR, "", e);
          }
        }
      }
      else
      {
        conn = new LDAPConnection();
      }

      try
      {
        try
        {
          conn.connect(hostname, port);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_LDAP_CANNOT_CONNECT.get(hostname, port,
                    le.getResultString()));
          if (promptForYesNo(
               INFO_INTERACTIVE_LDAP_RETRY_PROMPT.get(), true, true))
          {
            promptForLDAPArguments(argList, test);
            return;
          }
          else
          {
            throw new LDAPException(le.getResultCode(), "", le);
          }
        }


        // If we should use StartTLS to secure the connection, then do so now.
        if (useStartTLS)
        {
          try
          {
            final ExtendedResult startTLSResult = conn.processExtendedOperation(
                 new StartTLSExtendedRequest(sslUtil.createSSLContext()));
            if (startTLSResult.getResultCode() != ResultCode.SUCCESS)
            {
              throw new LDAPException(startTLSResult);
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);

            final String msg;
            if (e instanceof LDAPException)
            {
              msg = ((LDAPException) e).getResultString();
            }
            else
            {
              msg = StaticUtils.getExceptionMessage(e);
            }

            tool.wrapErr(0, wrapColumn,
                 ERR_INTERACTIVE_LDAP_CANNOT_PERFORM_STARTTLS.get(msg));
            if (promptForYesNo(
                 INFO_INTERACTIVE_LDAP_RETRY_PROMPT.get(), true, true))
            {
              promptForLDAPArguments(argList, test);
              return;
            }
            else
            {
              throw new LDAPException(ResultCode.LOCAL_ERROR, "", e);
            }
          }
        }


        // Authenticate the connection if appropriate.
        if (bindRequest != null)
        {
          try
          {
            conn.bind(bindRequest);
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            tool.wrapErr(0, wrapColumn,
                 ERR_INTERACTIVE_LDAP_CANNOT_AUTHENTICATE.get(
                      le.getResultString()));
            if (promptForYesNo(
                 INFO_INTERACTIVE_LDAP_RETRY_PROMPT.get(), true, true))
            {
              promptForLDAPArguments(argList, test);
              return;
            }
            else
            {
              throw new LDAPException(le.getResultCode(), "", le);
            }
          }
        }
      }
      finally
      {
        conn.close();
      }
    }
  }



  /**
   * Interactively prompts for the arguments used to connect and optionally
   * authenticate to multiple directory servers.
   *
   * @param  argList  The list to which the string representations of all LDAP
   *                  arguments should be added.
   * @param  test     Indicates whether to attempt to use the arguments to
   *                  establish an LDAP connection.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForMultiServerLDAPArguments(
                    @NotNull final List<String> argList, final boolean test)
          throws LDAPException
  {
    // FIXME -- Implement this.
    throw new LDAPException(ResultCode.LOCAL_ERROR,
         ERR_INTERACTIVE_MULTI_SERVER_LDAP_NOT_SUPPORTED.get());
  }



  /**
   * Displays a menu that allows the user to supply values for the command-line
   * arguments.  Note that this will not include arguments automatically added
   * by the {@link LDAPCommandLineTool} API.
   *
   * @param  ldapArgs  A list of the arguments used to connect and authenticate
   *                   to the LDAP server(s) in non-interactive mode.  The
   *                   contents of this list may be altered if the user opts to
   *                   change the LDAP connection settings.
   *
   * @return  The tool-specific arguments configured by the user.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  @NotNull()
  private List<String> displayInteractiveMenu(
                            @NotNull final List<String> ldapArgs)
          throws LDAPException
  {
    final ArrayList<Argument> args =
         new ArrayList<>(parser.getNamedArguments());

    if (parser.getSelectedSubCommand() != null)
    {
      args.addAll(parser.getSelectedSubCommand().getArgumentParser().
           getNamedArguments());
    }

    final Set<String> usageArguments =
         CommandLineTool.getUsageArgumentIdentifiers(tool);

    final Set<String> ldapArguments;
    if (tool instanceof LDAPCommandLineTool)
    {
      ldapArguments = LDAPCommandLineTool.getLongLDAPArgumentIdentifiers(
           ((LDAPCommandLineTool) tool));
    }
    else
    {
      ldapArguments = Collections.emptySet();
    }

    int maxIdentifierLength = 0;
    final String trailingArgsIdentifier =
         INFO_INTERACTIVE_MENU_TRAILING_ARGS_IDENTIFIER.get();
    if (parser.allowsTrailingArguments())
    {
      maxIdentifierLength = trailingArgsIdentifier.length();
    }

    final Iterator<Argument> argIterator = args.iterator();
    while (argIterator.hasNext())
    {
      final Argument a = argIterator.next();
      final String longID = a.getLongIdentifier();
      if (usageArguments.contains(longID) || ldapArguments.contains(longID))
      {
        argIterator.remove();
      }
      else
      {
        maxIdentifierLength = Math.max(maxIdentifierLength,
             a.getIdentifierString().length());
      }
    }

    if (args.isEmpty() && (! parser.allowsTrailingArguments()))
    {
      return Collections.emptyList();
    }
    else
    {
      // First, prompt for all required arguments that don't have a default
      // value.
      for (final Argument arg : args)
      {
        if (! arg.isRequired())
        {
          continue;
        }

        final List<String> valueStrings =
             arg.getValueStringRepresentations(true);
        if (! valueStrings.isEmpty())
        {
          continue;
        }

        promptForArgument(arg);
      }


      // If the tool requires trailing arguments, then prompt for them.
      if (parser.requiresTrailingArguments())
      {
        promptForTrailingArguments();
      }


argsLoop:
      while (true)
      {
        final int maxNumberLength = String.valueOf(args.size()).length();
        final int subsequentIndent = maxNumberLength + maxIdentifierLength + 4;

        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_MENU_PROMPT.get());

        int optionNumber = 1;
        for (final Argument arg : args)
        {
          List<String> valueStrings = arg.getValueStringRepresentations(true);
          if (arg.isSensitive())
          {
            final int size = valueStrings.size();
            switch (size)
            {
              case 0:
                // No need to do any thing.
                break;
              case 1:
                valueStrings = Collections.singletonList("***REDACTED***");
                break;
              default:
                valueStrings = new ArrayList<>(size);
                for (int i=0; i <= size; i++)
                {
                  valueStrings.add("***REDACTED" + i + "***");
                }
                break;
            }
          }

          switch (valueStrings.size())
          {
            case 0:
              tool.wrapStandardOut(0, subsequentIndent, wrapColumn, true,
                   rightAlign(String.valueOf(optionNumber), maxNumberLength),
                   ' ',
                   leftAlign(arg.getIdentifierString(), maxIdentifierLength),
                   " -");
              break;
            case 1:
              tool.wrapStandardOut(0, subsequentIndent, wrapColumn, true,
                   rightAlign(String.valueOf(optionNumber), maxNumberLength),
                   ' ',
                   leftAlign(arg.getIdentifierString(), maxIdentifierLength),
                   " - ", valueStrings.get(0));
              break;
            default:
              tool.wrapStandardOut(0, subsequentIndent, wrapColumn, true,
                   rightAlign(String.valueOf(optionNumber), maxNumberLength),
                   ' ',
                   leftAlign(arg.getIdentifierString(), maxIdentifierLength),
                   " - ", valueStrings.get(0));
              for (int i=1; i < valueStrings.size(); i++)
              {
                tool.wrapStandardOut(0, subsequentIndent, wrapColumn, true,
                     rightAlign("", maxNumberLength), ' ',
                     leftAlign("", maxIdentifierLength),
                     " - ", valueStrings.get(i));
              }
              break;
          }

          optionNumber++;
        }

        if (parser.allowsTrailingArguments())
        {
          final List<String> trailingArgs = parser.getTrailingArguments();
          switch(trailingArgs.size())
          {
            case 0:
              tool.wrapStandardOut(0, subsequentIndent, wrapColumn, true,
                   rightAlign("t", maxNumberLength),
                   ' ',
                   leftAlign(trailingArgsIdentifier, maxIdentifierLength),
                   " -");
              break;
            case 1:
              tool.wrapStandardOut(0, subsequentIndent, wrapColumn, true,
                   rightAlign("t", maxNumberLength), ' ',
                   leftAlign(trailingArgsIdentifier, maxIdentifierLength),
                   " - ", trailingArgs.get(0));
              break;
            default:
              tool.wrapStandardOut(0, subsequentIndent, wrapColumn, true,
                   rightAlign("t", maxNumberLength), ' ',
                   leftAlign(trailingArgsIdentifier, maxIdentifierLength),
                   " - ", trailingArgs.get(0));
              for (int i=1; i < trailingArgs.size(); i++)
              {
                tool.wrapStandardOut(0, subsequentIndent, wrapColumn, true,
                     rightAlign("", maxNumberLength), ' ',
                     leftAlign("", maxIdentifierLength),
                     " - ", trailingArgs.get(i));
              }
              break;
          }
        }

        tool.out();

        if (tool instanceof LDAPCommandLineTool)
        {
          final LDAPCommandLineTool ldapTool = (LDAPCommandLineTool) tool;
          if (ldapTool.supportsAuthentication())
          {
            tool.wrapStandardOut((maxNumberLength - 1), subsequentIndent,
                 wrapColumn, true, "l - ",
                 INFO_INTERACTIVE_MENU_OPTION_REPROMPT_FOR_CONN_AUTH_ARGS.
                      get());
          }
          else
          {
            tool.wrapStandardOut((maxNumberLength - 1), subsequentIndent,
                 wrapColumn, true, "l - ",
                 INFO_INTERACTIVE_MENU_OPTION_REPROMPT_FOR_CONN_ARGS.get());
          }
        }
        else if (tool instanceof MultiServerLDAPCommandLineTool)
        {
            tool.wrapStandardOut((maxNumberLength - 1), subsequentIndent,
                 wrapColumn, true, "l - ",
                 INFO_INTERACTIVE_MENU_OPTION_REPROMPT_FOR_CONN_AUTH_ARGS.
                      get());
        }

        tool.wrapStandardOut((maxNumberLength - 1), subsequentIndent,
             wrapColumn, true, "d - ",
             INFO_INTERACTIVE_MENU_OPTION_DISPLAY_ARGS.get(tool.getToolName()));
        tool.wrapStandardOut((maxNumberLength - 1), subsequentIndent,
             wrapColumn, true, "r - ",
             INFO_INTERACTIVE_MENU_OPTION_RUN.get(tool.getToolName()));
        tool.wrapStandardOut((maxNumberLength - 1), subsequentIndent,
             wrapColumn, true, "q - ", INFO_INTERACTIVE_MENU_OPTION_QUIT.get());
        tool.out();
        tool.getOut().print(
             INFO_INTERACTIVE_MENU_ENTER_CHOICE_WITHOUT_DEFAULT.get() + ' ');

        final Argument selectedArg;
        try
        {
          while (true)
          {
            final String line = systemInReader.readLine().trim();
            if (line.equalsIgnoreCase("t") &&
                (tool.getMaxTrailingArguments() != 0))
            {
              promptForTrailingArguments();
              continue argsLoop;
            }
            else if (line.equalsIgnoreCase("l"))
            {
              if (tool instanceof LDAPCommandLineTool)
              {
                promptForLDAPArguments(ldapArgs, true);
              }
              else if (tool instanceof MultiServerLDAPCommandLineTool)
              {
                promptForMultiServerLDAPArguments(ldapArgs, true);
              }
              else
              {
                tool.wrapErr(0, wrapColumn,
                     ERR_INTERACTIVE_ARG_MENU_INVALID_CHOICE.get());
                tool.getOut().print(
                     INFO_INTERACTIVE_MENU_ENTER_CHOICE_WITHOUT_DEFAULT.get() +
                     ' ');
              }

              continue argsLoop;
            }
            else if (line.equalsIgnoreCase("d"))
            {
              try
              {
                validateRequiredExclusiveAndDependentArgumentSets();
                tool.doExtendedArgumentValidation();

                final ArrayList<String> argStrings =
                     new ArrayList<>(2*args.size());

                final SubCommand subcommand = parser.getSelectedSubCommand();
                if (subcommand != null)
                {
                  argStrings.add(subcommand.getPrimaryName());
                }

                argStrings.addAll(ldapArgs);
                for (final Argument a : args)
                {
                  ArgumentHelper.addToCommandLine(a, argStrings);
                }
                argStrings.addAll(parser.getTrailingArguments());

                if (argStrings.isEmpty())
                {
                  tool.wrapStandardOut(0, 0, wrapColumn, true,
                       INFO_INTERACTIVE_MENU_NO_CURRENT_ARGS.get(
                            tool.getToolName()));
                }
                else
                {
                  tool.wrapStandardOut(0, 0, wrapColumn, true,
                       INFO_INTERACTIVE_MENU_CURRENT_ARGS_HEADER.get(
                            tool.getToolName()));
                  printArgs(argStrings);
                }
                tool.out();
                promptForString(
                     INFO_INTERACTIVE_MENU_PROMPT_PRESS_ENTER_TO_CONTINUE.get(),
                     null, false);
                continue argsLoop;
              }
              catch (final ArgumentException ae)
              {
                Debug.debugException(ae);
                tool.err();
                tool.wrapErr(0, wrapColumn,
                     ERR_INTERACTIVE_MENU_EXTENDED_VALIDATION_ERRORS.get(
                          ae.getMessage()));
                tool.err();
                tool.wrapErr(0, wrapColumn,
                     ERR_INTERACTIVE_MENU_CORRECT_VALIDATION_ERRORS.get());
                tool.err();
                promptForString(
                     INFO_INTERACTIVE_MENU_PROMPT_PRESS_ENTER_TO_CONTINUE.get(),
                     null, false);
                continue argsLoop;
              }
            }
            else if (line.equalsIgnoreCase("r"))
            {
              try
              {
                validateRequiredExclusiveAndDependentArgumentSets();
                tool.doExtendedArgumentValidation();
                break argsLoop;
              }
              catch (final ArgumentException ae)
              {
                Debug.debugException(ae);
                tool.err();
                tool.wrapErr(0, wrapColumn,
                     ERR_INTERACTIVE_MENU_EXTENDED_VALIDATION_ERRORS.get(
                          ae.getMessage()));
                tool.err();
                tool.wrapErr(0, wrapColumn,
                     ERR_INTERACTIVE_MENU_CORRECT_VALIDATION_ERRORS.get());
                tool.err();
                promptForString(
                     INFO_INTERACTIVE_MENU_PROMPT_PRESS_ENTER_TO_CONTINUE.get(),
                     null, false);
                continue argsLoop;
              }
            }
            else if (line.equalsIgnoreCase("q"))
            {
              throw new LDAPException(ResultCode.SUCCESS, "");
            }

            int selectedValue = -1;
            try
            {
              selectedValue = Integer.parseInt(line);
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
            }

            if ((selectedValue < 1) || (selectedValue > args.size()))
            {
              tool.wrapErr(0, wrapColumn,
                   ERR_INTERACTIVE_ARG_MENU_INVALID_CHOICE.get());
              tool.getOut().print(
                   INFO_INTERACTIVE_MENU_ENTER_CHOICE_WITHOUT_DEFAULT.get() +
                        ' ');
            }
            else
            {
              selectedArg = args.get(selectedValue - 1);
              break;
            }
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          throw le;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_INTERACTIVE_MENU_CANNOT_READ_CHOICE.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }

        promptForArgument(selectedArg);
      }

      final ArrayList<String> argStrings = new ArrayList<>(2*args.size());
      for (final Argument a : args)
      {
        ArgumentHelper.addToCommandLine(a, argStrings);
      }
      argStrings.addAll(parser.getTrailingArguments());

      return argStrings;
    }
  }



  /**
   * Prompts the user for the trailing argument value(s).
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForTrailingArguments()
          throws LDAPException
  {
    tool.out();

    ArgumentHelper.resetTrailingArguments(parser);

    if (parser.getMaxTrailingArguments() == 1)
    {
      if (parser.requiresTrailingArguments())
      {
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_TRAILING_DESC_SINGLE_REQUIRED.get(
                  tool.getToolName()));
      }
      else
      {
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_TRAILING_DESC_SINGLE_OPTIONAL.get(
                  tool.getToolName()));
      }
      tool.out("     ", tool.getTrailingArgumentsPlaceholder());

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_TRAILING_PROMPT_SINGLE.get());

      while (true)
      {
        final String trailingArgValue = promptForString(
             INFO_INTERACTIVE_TRAILING_ARG_PROMPT.get(), null, false);
        if (trailingArgValue == null)
        {
          return;
        }

        try
        {
          ArgumentHelper.addTrailingArgument(parser, trailingArgValue);
          return;
        }
        catch (final ArgumentException ae)
        {
          Debug.debugException(ae);
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_TRAILING_VALUE_INVALID.get(ae.getMessage()));
        }
      }
    }
    else
    {
      if (parser.requiresTrailingArguments())
      {
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_TRAILING_DESC_MULTIPLE_REQUIRED.get(
             tool.getToolName(), parser.getMinTrailingArguments()));
      }
      else
      {
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_TRAILING_DESC_MULTIPLE_OPTIONAL.get(
             tool.getToolName()));
      }
      tool.out("     ", tool.getTrailingArgumentsPlaceholder());

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_TRAILING_PROMPT_MULTIPLE.get());

      while (true)
      {
        final String trailingArgValue = promptForString(
             INFO_INTERACTIVE_TRAILING_ARG_PROMPT.get(), null, false);
        if (trailingArgValue == null)
        {
          return;
        }
        else
        {
          try
          {
            ArgumentHelper.addTrailingArgument(parser, trailingArgValue);
          }
          catch (final ArgumentException ae)
          {
            Debug.debugException(ae);
            tool.wrapErr(0, wrapColumn,
                 ERR_INTERACTIVE_TRAILING_VALUE_INVALID.get(ae.getMessage()));
          }
        }
      }
    }
  }



  /**
   * Prompts the user for the value(s) for the specified argument.
   *
   * @param  a  The argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForArgument(@NotNull final Argument a)
          throws LDAPException
  {
    tool.out();

    final int maxValues = a.getMaxOccurrences();
    if (maxValues == 1)
    {
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_SPECIFY_SINGLE_VALUE.get(
                a.getIdentifierString()));
    }
    else
    {
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_SPECIFY_MULTIPLE_VALUES.get(
                a.getIdentifierString()));
    }

    final String description = a.getDescription();
    if ((description != null) && (! description.isEmpty()))
    {
      tool.out();

      final String prompt = INFO_INTERACTIVE_ARG_PROMPT_DESCRIPTION.get();
      tool.wrapStandardOut(0, prompt.length(), wrapColumn, true, prompt,
           description);
    }

    final String constraints = a.getValueConstraints();
    if ((constraints != null) && (! constraints.isEmpty()))
    {
      tool.out();

      final String prompt = INFO_INTERACTIVE_ARG_PROMPT_CONSTRAINTS.get();
      tool.wrapStandardOut(0, prompt.length(), wrapColumn, true, prompt,
           constraints);

      if (a.isRequired())
      {
        if (maxValues == 1)
        {
          tool.wrapStandardOut(prompt.length(), prompt.length(), wrapColumn,
               true, INFO_INTERACTIVE_ARG_PROMPT_SINGLE_REQUIRED.get());
        }
        else
        {
          tool.wrapStandardOut(prompt.length(), prompt.length(), wrapColumn,
               true, INFO_INTERACTIVE_ARG_PROMPT_AT_LEAST_ONE_REQUIRED.get());
        }
      }
    }
    else if (a.isRequired())
    {
      tool.out();
      final String prompt = INFO_INTERACTIVE_ARG_PROMPT_CONSTRAINTS.get();

      if (maxValues == 1)
      {
        tool.wrapStandardOut(0, prompt.length(), wrapColumn, true, prompt,
             INFO_INTERACTIVE_ARG_PROMPT_SINGLE_REQUIRED.get());
      }
      else
      {
        tool.wrapStandardOut(0, prompt.length(), wrapColumn, true, prompt,
             INFO_INTERACTIVE_ARG_PROMPT_AT_LEAST_ONE_REQUIRED.get());
      }
    }

    if (a instanceof ArgumentListArgument)
    {
      promptForArgumentList((ArgumentListArgument) a);
    }
    else if (a instanceof BooleanArgument)
    {
      promptForBoolean((BooleanArgument) a);
    }
    else if (a instanceof BooleanValueArgument)
    {
      promptForBoolean((BooleanValueArgument) a);
    }
    else if (a instanceof ControlArgument)
    {
      promptForControl((ControlArgument) a);
    }
    else if (a instanceof DNArgument)
    {
      promptForDN((DNArgument) a);
    }
    else if (a instanceof DurationArgument)
    {
      promptForDuration((DurationArgument) a);
    }
    else if (a instanceof FileArgument)
    {
      promptForFile((FileArgument) a);
    }
    else if (a instanceof FilterArgument)
    {
      promptForFilter((FilterArgument) a);
    }
    else if (a instanceof IntegerArgument)
    {
      promptForInteger((IntegerArgument) a);
    }
    else if (a instanceof ScopeArgument)
    {
      promptForScope((ScopeArgument) a);
    }
    else if (a instanceof StringArgument)
    {
      promptForString((StringArgument) a);
    }
    else if (a instanceof TimestampArgument)
    {
      promptForTimestamp((TimestampArgument) a);
    }
    else
    {
      // This should never happen.
      throw new AssertionError("Unexpected argument type " +
           a.getClass().getName());
    }
  }



  /**
   * Prompts for one or more argument lists.
   *
   * @param  a  The argument list argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForArgumentList(@NotNull final ArgumentListArgument a)
          throws LDAPException
  {
    final List<String> values = a.getValueStrings();
    ArgumentHelper.reset(a);

    if (a.getMaxOccurrences() == 1)
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true, values.get(0));
      }

      while (true)
      {
        final String newValue = promptForString(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, a.isRequired());
        try
        {
          if (newValue != null)
          {
            ArgumentHelper.addValue(a, newValue);
          }
          return;
        }
        catch (final ArgumentException ae)
        {
          Debug.debugException(ae);
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_ARG_PROMPT_INVALID_VALUE.get(ae.getMessage()));
        }
      }
    }
    else
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUES.get());
        for (final String s : values)
        {
          tool.wrapStandardOut(5, 10, wrapColumn, true, s);
        }
      }

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUES.get());

      boolean first = true;
      while (true)
      {
        final String s = promptForString(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null,
             (first && a.isRequired()));
        if (s == null)
        {
          return;
        }

        try
        {
          ArgumentHelper.addValue(a, s);
          first = false;
        }
        catch (final ArgumentException ae)
        {
          Debug.debugException(ae);
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_ARG_PROMPT_INVALID_VALUE.get(ae.getMessage()));
        }
      }
    }
  }



  /**
   * Prompts for a Boolean value.
   *
   * @param  a  The Boolean argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForBoolean(@NotNull final BooleanArgument a)
          throws LDAPException
  {
    tool.out();
    tool.wrapStandardOut(0, 0, wrapColumn,true,
         INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
    tool.wrapStandardOut(5, 10, wrapColumn, true, a.isPresent());

    ArgumentHelper.reset(a);

    if (promptForBoolean(
         INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, true))
    {
      ArgumentHelper.incrementOccurrencesSuppressException(a);
    }
  }



  /**
   * Prompts for a Boolean value.
   *
   * @param  a  The Boolean argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForBoolean(@NotNull final BooleanValueArgument a)
          throws LDAPException
  {
    final Boolean value = a.getValue();
    ArgumentHelper.reset(a);

    final Boolean b = promptForBoolean(
         INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, a.isRequired());
    if (b != null)
    {
      ArgumentHelper.addValueSuppressException(a, String.valueOf(b));
    }
  }



  /**
   * Prompts for one or more control values.
   *
   * @param  a  The control argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForControl(@NotNull final ControlArgument a)
          throws LDAPException
  {
    final List<Control> values = a.getValues();
    ArgumentHelper.reset(a);

    if (a.getMaxOccurrences() == 1)
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true, values.get(0));
      }

      while (true)
      {
        final String newValue = promptForString(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, false);
        try
        {
          if (newValue == null)
          {
            ArgumentHelper.addValue(a, "");
          }
          else
          {
            ArgumentHelper.addValue(a, newValue);
          }
          return;
        }
        catch (final ArgumentException ae)
        {
          Debug.debugException(ae);
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_ARG_PROMPT_INVALID_VALUE.get(ae.getMessage()));
        }
      }
    }
    else
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUES.get());
        for (final Control c : values)
        {
          tool.wrapStandardOut(5, 10, wrapColumn, true, c);
        }
      }

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUES.get());

      boolean first = true;
      while (true)
      {
        final String s = promptForString(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null,
             (first && a.isRequired()));
        if (s == null)
        {
          return;
        }

        try
        {
          ArgumentHelper.addValue(a, s);
          first = false;
        }
        catch (final ArgumentException ae)
        {
          Debug.debugException(ae);
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_ARG_PROMPT_INVALID_VALUE.get(ae.getMessage()));
        }
      }
    }
  }



  /**
   * Prompts for one or more DN values.
   *
   * @param  a  The DN argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForDN(@NotNull final DNArgument a)
          throws LDAPException
  {
    final List<DN> values = a.getValues();
    ArgumentHelper.reset(a);

    if (a.getMaxOccurrences() == 1)
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true, values.get(0));
      }

      final DN dnValue = promptForDN(
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, true);
      ArgumentHelper.addValueSuppressException(a, String.valueOf(dnValue));
    }
    else
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUES.get());
        for (final DN dn : values)
        {
          tool.wrapStandardOut(5, 10, wrapColumn, true, dn);
        }
      }

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUES.get());

      boolean first = true;
      while (true)
      {
        final boolean allowNullDN;
        if (first)
        {
          first = false;
          allowNullDN = ! a.isRequired();
        }
        else
        {
          allowNullDN = true;
        }

        final DN dnValue = promptForDN(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, allowNullDN);
        if (dnValue.isNullDN())
        {
          return;
        }
        else
        {
          ArgumentHelper.addValueSuppressException(a, String.valueOf(dnValue));
        }
      }
    }
  }



  /**
   * Prompts for one or more duration values.
   *
   * @param  a  The duration argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForDuration(@NotNull final DurationArgument a)
          throws LDAPException
  {
    final List<String> values = a.getValueStringRepresentations(true);
    if (! values.isEmpty())
    {
      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
      tool.wrapStandardOut(5, 10, wrapColumn, true, values.get(0));
    }

    while (true)
    {
      final String newValue = promptForString(
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, a.isRequired());
      try
      {
        if (newValue != null)
        {
          ArgumentHelper.addValue(a, newValue);
        }
        return;
      }
      catch (final ArgumentException ae)
      {
        Debug.debugException(ae);
        tool.wrapErr(0, wrapColumn,
             ERR_INTERACTIVE_ARG_PROMPT_INVALID_VALUE.get(ae.getMessage()));
      }
    }
  }



  /**
   * Prompts for one or more path values.
   *
   * @param  a  The file argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForFile(@NotNull final FileArgument a)
          throws LDAPException
  {
    final List<File> values = a.getValues();
    ArgumentHelper.reset(a);

    if (a.getMaxOccurrences() == 1)
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true, values.get(0));
      }

      final File fileValue = promptForPath(
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, a.isRequired(),
           a.fileMustExist(), a.parentMustExist(), a.mustBeFile(),
           a.mustBeDirectory());
      if (fileValue != null)
      {
        ArgumentHelper.addValueSuppressException(a, fileValue.getPath());
      }
    }
    else
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUES.get());
        for (final File f : values)
        {
          tool.wrapStandardOut(5, 10, wrapColumn, true, f.getPath());
        }
      }

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUES.get());

      boolean first = true;
      while (true)
      {
        final boolean isRequired;
        if (first)
        {
          first = false;
          isRequired = a.isRequired();
        }
        else
        {
          isRequired = false;
        }

        final File fileValue = promptForPath(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, isRequired,
             a.fileMustExist(), a.parentMustExist(), a.mustBeFile(),
             a.mustBeDirectory());
        if (fileValue == null)
        {
          return;
        }
        else
        {
          ArgumentHelper.addValueSuppressException(a, fileValue.getPath());
        }
      }
    }
  }



  /**
   * Prompts for one or more filter values.
   *
   * @param  a  The filter argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForFilter(@NotNull final FilterArgument a)
          throws LDAPException
  {
    final List<Filter> values = a.getValues();
    ArgumentHelper.reset(a);

    if (a.getMaxOccurrences() == 1)
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true, values.get(0));
      }

      final Filter filterValue = promptForFilter(
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, a.isRequired());
      if (filterValue != null)
      {
        ArgumentHelper.addValueSuppressException(a, filterValue.toString());
      }
    }
    else
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUES.get());
        for (final Filter f : values)
        {
          tool.wrapStandardOut(5, 10, wrapColumn, true, String.valueOf(f));
        }
      }

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUES.get());

      boolean first = true;
      while (true)
      {
        final boolean isRequired;
        if (first)
        {
          first = false;
          isRequired = a.isRequired();
        }
        else
        {
          isRequired = false;
        }

        final Filter filterValue = promptForFilter(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, isRequired);
        if (filterValue == null)
        {
          return;
        }
        else
        {
          ArgumentHelper.addValueSuppressException(a,
               String.valueOf(filterValue));
        }
      }
    }
  }



  /**
   * Prompts for one or more integer values.
   *
   * @param  a  The integer argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForInteger(@NotNull final IntegerArgument a)
          throws LDAPException
  {
    final List<Integer> values = a.getValues();
    ArgumentHelper.reset(a);

    if (a.getMaxOccurrences() == 1)
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true, values.get(0));
      }

      final Integer intValue = promptForInteger(
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null,
           a.getLowerBound(), a.getUpperBound(), a.isRequired());
      if (intValue != null)
      {
        ArgumentHelper.addValueSuppressException(a,
             String.valueOf(intValue));
      }
    }
    else
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUES.get());
        for (final Integer i : values)
        {
          tool.wrapStandardOut(5, 10, wrapColumn, true, i);
        }
      }

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUES.get());

      boolean first = true;
      while (true)
      {
        final boolean isRequired;
        if (first)
        {
          first = false;
          isRequired = a.isRequired();
        }
        else
        {
          isRequired = false;
        }

        final Integer intValue = promptForInteger(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null,
             a.getLowerBound(), a.getUpperBound(), isRequired);
        if (intValue == null)
        {
          return;
        }
        else
        {
          ArgumentHelper.addValueSuppressException(a,
               String.valueOf(intValue));
        }
      }
    }
  }



  /**
   * Prompts for one or more scope values.
   *
   * @param  a  The scope argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForScope(@NotNull final ScopeArgument a)
          throws LDAPException
  {
    final SearchScope value = a.getValue();
    ArgumentHelper.reset(a);

    final String[] scopeValues =
    {
      "base",
      "one",
      "sub",
      "subordinates"
    };

    tool.out();
    if (value != null)
    {
      if (value.intValue() < scopeValues.length)
      {
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true,
             scopeValues[value.intValue()]);
      }
    }

    final int newIntValue = getNumberedMenuChoice(
         INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(),
         (! a.isRequired()),
         null,
         scopeValues);
    if (newIntValue >= 0)
    {
      ArgumentHelper.addValueSuppressException(a, scopeValues[newIntValue]);
    }
  }



  /**
   * Prompts for one or more string values.
   *
   * @param  a  The string argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForString(@NotNull final StringArgument a)
          throws LDAPException
  {
    // If the argument has a relatively small set of allowed values, then
    // display a menu to allow the user to select one of those values.
    if ((a.getAllowedValues() != null) && (! a.getAllowedValues().isEmpty()) &&
        (a.getAllowedValues().size() <= 20))
    {
      promptForStringWithMenu(a);
      return;
    }

    final List<String> values = a.getValues();
    ArgumentHelper.reset(a);

    if (a.getMaxOccurrences() == 1)
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true, values.get(0));
      }

      while (true)
      {
        final String newValue;
        if (a.isSensitive())
        {
          final byte[] newValueBytes = promptForPassword(
               INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(),
               INFO_INTERACTIVE_ARG_PROMPT_VALUE_CONFIRM.get(), a.isRequired());
          if (newValueBytes == null)
          {
            newValue = null;
          }
          else
          {
            newValue = StaticUtils.toUTF8String(newValueBytes);
          }
        }
        else
        {
          newValue = promptForString(
               INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null,
               a.isRequired());
        }

        try
        {
          if (newValue != null)
          {
            ArgumentHelper.addValue(a, newValue);
          }
          return;
        }
        catch (final ArgumentException ae)
        {
          Debug.debugException(ae);
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_ARG_PROMPT_INVALID_VALUE.get(ae.getMessage()));
        }
      }
    }
    else
    {
      if (! values.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUES.get());
        for (final String s : values)
        {
          tool.wrapStandardOut(5, 10, wrapColumn, true, s);
        }
      }

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUES.get());

      boolean first = true;
      while (true)
      {
        final String s = promptForString(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null,
             (first && a.isRequired()));
        if (s == null)
        {
          return;
        }

        try
        {
          ArgumentHelper.addValue(a, s);
          first = false;
        }
        catch (final ArgumentException ae)
        {
          Debug.debugException(ae);
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_ARG_PROMPT_INVALID_VALUE.get(ae.getMessage()));
        }
      }
    }
  }



  /**
   * Prompts for one or more string values using a menu to display the allowed
   * choices.
   *
   * @param  a  The string argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForStringWithMenu(@NotNull final StringArgument a)
          throws LDAPException
  {
    final List<String> values = a.getValues();
    ArgumentHelper.reset(a);

    final String[] allowedValueArray = new String[a.getAllowedValues().size()];
    a.getAllowedValues().toArray(allowedValueArray);

    if (! values.isEmpty())
    {
      tool.out();
      if (values.size() == 1)
      {
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true, values.get(0));
      }
      else
      {
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUES.get());
        for (final String s : values)
        {
          tool.wrapStandardOut(5, 10, wrapColumn, true, s);
        }
      }
    }

    final String message;
    if (a.getMaxOccurrences() > 1)
    {
      message = INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUES.get();
    }
    else
    {
      message = INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get();
    }

    final int firstChoice = getNumberedMenuChoice(message, (! a.isRequired()),
         null, allowedValueArray);
    if (firstChoice < 0)
    {
      return;
    }

    ArgumentHelper.addValueSuppressException(a, allowedValueArray[firstChoice]);

    if (a.getMaxOccurrences() > 1)
    {
      while (true)
      {
        final String stringValue = promptForString(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, false);
        if (stringValue == null)
        {
          return;
        }
        else if (stringValue.equalsIgnoreCase("q"))
        {
          throw new LDAPException(ResultCode.SUCCESS, "");
        }

        int selectedValue = -1;
        try
        {
          selectedValue = Integer.parseInt(stringValue);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        if ((selectedValue < 1) || (selectedValue > allowedValueArray.length))
        {
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_MENU_INVALID_CHOICE.get());
        }
        else
        {
          ArgumentHelper.addValueSuppressException(a,
               allowedValueArray[selectedValue - 1]);
        }
      }
    }
  }



  /**
   * Prompts for one or more timestamp values.
   *
   * @param  a  The timestamp argument for which to prompt.
   *
   * @throws  LDAPException  If a problem is encountered while interacting with
   *                         the user, or if the user wants to quit.
   */
  private void promptForTimestamp(@NotNull final TimestampArgument a)
          throws LDAPException
  {
    final List<String> stringValues = a.getValueStringRepresentations(true);
    ArgumentHelper.reset(a);

    if (a.getMaxOccurrences() == 1)
    {
      if (! stringValues.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
        tool.wrapStandardOut(5, 10, wrapColumn, true, stringValues.get(0));
      }

      final ObjectPair<Date,String> p = promptForTimestamp(
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, a.isRequired());
      if (p != null)
      {
        ArgumentHelper.addValueSuppressException(a, p.getSecond());
      }
    }
    else
    {
      if (! stringValues.isEmpty())
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, true,
             INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUES.get());
        for (final String s : stringValues)
        {
          tool.wrapStandardOut(5, 10, wrapColumn, true, String.valueOf(s));
        }
      }

      tool.out();
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUES.get());

      boolean first = true;
      while (true)
      {
        final boolean isRequired;
        if (first)
        {
          first = false;
          isRequired = a.isRequired();
        }
        else
        {
          isRequired = false;
        }

        final Filter filterValue = promptForFilter(
             INFO_INTERACTIVE_ARG_PROMPT_NEW_VALUE.get(), null, isRequired);
        if (filterValue == null)
        {
          return;
        }
        else
        {
          ArgumentHelper.addValueSuppressException(a,
               String.valueOf(filterValue));
        }
      }
    }
  }



  /**
   * Displays a menu of numbered options, and waits for the user to select one
   * of the options.
   *
   * @param  prompt               The string to display above the list of
   *                              numbered options.
   * @param  allowUndefined       Indicates whether to allow the value to remain
   *                              undefined.
   * @param  defaultOptionString  The number that corresponds to the default
   *                              option that will be selected if the user
   *                              presses ENTER without typing anything.  This
   *                              should be the display string value, so if it
   *                              is a number then it should be one-based rather
   *                              than zero-based.  It may be {@code null} if no
   *                              default string should be provided.
   * @param  options              The set of text to display next to the
   *                              numbered options.
   *
   * @return  The index of the option that was selected, or -1 if an undefined
   *          value is allowed and that option was selected.  Note that although
   *          the displayed menu will start numbering with one, the value
   *          returned will start numbering at zero so as to correspond with the
   *          elements in the provided options array.
   *
   * @throws  LDAPException  If an error occurs while determining which option
   *                         the user has chosen, or if the user has chosen to
   *                         quit rather than select a numbered option.
   */
  private int getNumberedMenuChoice(@NotNull final String prompt,
                                    final boolean allowUndefined,
                                    @Nullable final String defaultOptionString,
                                    @NotNull final String... options)
          throws LDAPException
  {
    final int maxNumberLength = String.valueOf(options.length).length();
    final int subsequentIndent = maxNumberLength + 3;

    tool.out();
    tool.wrapStandardOut(0, 0, wrapColumn, true, prompt);

    int optionNumber = 1;
    for (final String option : options)
    {
      tool.wrapStandardOut(0, subsequentIndent, wrapColumn, true,
           rightAlign(String.valueOf(optionNumber), maxNumberLength), " - ",
           option);
      optionNumber++;
    }

    tool.out();
    if (allowUndefined)
    {
      tool.wrapStandardOut((maxNumberLength - 1), subsequentIndent, wrapColumn,
           true, "u - ", INFO_INTERACTIVE_MENU_OPTION_UNDEFINED.get());
    }
    tool.wrapStandardOut((maxNumberLength - 1), subsequentIndent, wrapColumn,
         true, "q - ", INFO_INTERACTIVE_MENU_OPTION_QUIT.get());

    final String message;
    if (defaultOptionString == null)
    {
      message = INFO_INTERACTIVE_MENU_ENTER_CHOICE_WITHOUT_DEFAULT.get() + ' ';
    }
    else
    {
      message = INFO_INTERACTIVE_MENU_ENTER_CHOICE_WITH_DEFAULT.get(
           defaultOptionString) + ' ';
    }

    try
    {
      while (true)
      {
        tool.out();
        tool.wrapStandardOut(0, 0, wrapColumn, false, message);

        String line = systemInReader.readLine().trim();
        if (line.equalsIgnoreCase("q"))
        {
          throw new LDAPException(ResultCode.SUCCESS, "");
        }
        else if (allowUndefined && line.equalsIgnoreCase("u"))
        {
          return -1;
        }

        if (line.isEmpty() && (defaultOptionString != null))
        {
          line = defaultOptionString;
        }

        int selectedValue = -1;
        try
        {
          selectedValue = Integer.parseInt(line);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        if ((selectedValue < 1) || (selectedValue > options.length))
        {
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_MENU_INVALID_CHOICE.get());
        }
        else
        {
          return selectedValue - 1;
        }
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERACTIVE_MENU_CANNOT_READ_CHOICE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Prompts the user to enter a string value.
   *
   * @param  prompt        The prompt to display to the user.
   * @param  defaultValue  The value that should be selected if the user
   *                       presses ENTER without entering a value.
   * @param  requireValue  Indicates whether a value is required.
   *
   * @return  The string obtained from the user, or {@code null} if the user did
   *          not provide a value, there is no default value, and no value is
   *          required.
   *
   * @throws  LDAPException  If an error occurs while obtaining the value from
   *                         the user.
   */
  @Nullable()
  private String promptForString(@NotNull final String prompt,
                                 @Nullable final String defaultValue,
                                 final boolean requireValue)
          throws LDAPException
  {
    tool.out();

    final String promptStr;
    if (defaultValue == null)
    {
      promptStr = prompt + ": ";
    }
    else
    {
      promptStr = prompt + " [" + defaultValue + "]: ";
    }

    tool.wrapStandardOut(0, 0, wrapColumn, false, promptStr);

    try
    {
      String line = systemInReader.readLine().trim();
      if (line.isEmpty() && (defaultValue != null))
      {
        line = defaultValue;
      }

      if (! line.isEmpty())
      {
        return line;
      }
      else if (requireValue)
      {
        tool.wrapErr(0, wrapColumn,
             ERR_INTERACTIVE_PROMPT_VALUE_REQUIRED.get());
        return promptForString(prompt, defaultValue, requireValue);
      }
      else
      {
        return null;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERACTIVE_PROMPT_ERROR_READING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Prompts the user to enter a Boolean value.
   *
   * @param  prompt        The prompt to display to the user.
   * @param  defaultValue  The value that should be selected if the user
   *                       presses ENTER without entering a value.
   * @param  requireValue  Indicates whether a value is required.
   *
   * @return  The Boolean value obtained from the user, or {@code null} if the
   *          user did not provide a value, there is no default value, and no
   *          value is required.
   *
   * @throws  LDAPException  If an error occurs while obtaining the value from
   *                         the user.
   */
  @Nullable()
  private Boolean promptForBoolean(@NotNull final String prompt,
                                   @Nullable final Boolean defaultValue,
                                   final boolean requireValue)
          throws LDAPException
  {
    final String[] choices =
    {
      "true",
      "false"
    };

    tool.out();
    if (defaultValue != null)
    {
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
      tool.wrapStandardOut(5, 10, wrapColumn, true,
           String.valueOf(defaultValue));
    }

    final int newIntValue = getNumberedMenuChoice(prompt, (! requireValue),
         null, choices);
    switch (newIntValue)
    {
      case 0:
        return Boolean.TRUE;
      case 1:
        return Boolean.FALSE;
      default:
        return null;
    }
  }



  /**
   * Prompts the user to enter a yes or no value.
   *
   * @param  prompt        The prompt to display to the user.
   * @param  defaultValue  The value that should be selected if the user
   *                       presses ENTER without entering a value.
   * @param  requireValue  Indicates whether a value is required.
   *
   * @return  The Boolean value obtained from the user, or {@code null} if the
   *          user did not provide a value, there is no default value, and no
   *          value is required.
   *
   * @throws  LDAPException  If an error occurs while obtaining the value from
   *                         the user.
   */
  @Nullable()
  private Boolean promptForYesNo(@NotNull final String prompt,
                                 @Nullable final Boolean defaultValue,
                                 final boolean requireValue)
          throws LDAPException
  {
    final String[] choices =
    {
      INFO_INTERACTIVE_CHOICE_YES.get(),
      INFO_INTERACTIVE_CHOICE_NO.get()
    };

    tool.out();
    String defaultOptionString = null;
    if (defaultValue != null)
    {
      tool.wrapStandardOut(0, 0, wrapColumn, true,
           INFO_INTERACTIVE_ARG_DESC_CURRENT_VALUE.get());
      if (defaultValue)
      {
        tool.wrapStandardOut(5, 10, wrapColumn, true,
             INFO_INTERACTIVE_CHOICE_YES.get());
        defaultOptionString = "1";
      }
      else
      {
        tool.wrapStandardOut(5, 10, wrapColumn, true,
             INFO_INTERACTIVE_CHOICE_NO.get());
        defaultOptionString = "2";
      }
    }

    final int newIntValue = getNumberedMenuChoice(prompt, (! requireValue),
         defaultOptionString, choices);
    switch (newIntValue)
    {
      case 0:
        return Boolean.TRUE;
      case 1:
        return Boolean.FALSE;
      default:
        return null;
    }
  }



  /**
   * Prompts the user to enter a distinguished name value.
   *
   * @param  prompt         The prompt to display to the user.
   * @param  defaultValue   The value that should be selected if the user
   *                        presses ENTER without entering a value.
   * @param  nullDNAllowed  Indicates whether the user is allowed to select the
   *                        null DN by pressing ENTER without entering a value.
   *                        Note that it will not be possible to specify the
   *                        null DN if a default value is supplied, since the
   *                        default value will be chosen instead.
   *
   * @return  The DN value obtained from the user.  It may be the null DN if
   *          the user pressed ENTER without specifying a value.
   *
   * @throws  LDAPException  If an error occurs while obtaining the value from
   *                         the user.
   */
  @NotNull()
  private DN promptForDN(@NotNull final String prompt,
                         @Nullable final String defaultValue,
                         final boolean nullDNAllowed)
          throws LDAPException
  {
    tool.out();

    final String promptStr;
    if (defaultValue == null)
    {
      promptStr = prompt + ": ";
    }
    else
    {
      promptStr = prompt + " [" + defaultValue + "]: ";
    }

    tool.wrapStandardOut(0, 0, wrapColumn, false, promptStr);

    try
    {
      String line = systemInReader.readLine().trim();
      if (line.isEmpty())
      {
        if (defaultValue != null)
        {
          line = defaultValue;
        }

        if (line.isEmpty())
        {
          if (nullDNAllowed)
          {
            return DN.NULL_DN;
          }
          else
          {
            tool.wrapErr(0, wrapColumn,
                 ERR_INTERACTIVE_PROMPT_NULL_DN_NOT_ALLOWED.get());
            return promptForDN(prompt, defaultValue, nullDNAllowed);
          }
        }
      }

      try
      {
        return new DN(line);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        tool.wrapErr(0, wrapColumn, ERR_INTERACTIVE_PROMPT_INVALID_DN.get());
        return promptForDN(prompt, defaultValue, nullDNAllowed);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERACTIVE_PROMPT_ERROR_READING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Prompts the user to enter a filter.
   *
   * @param  prompt        The prompt to display to the user.
   * @param  defaultValue  The value that should be selected if the user
   *                       presses ENTER without entering a value.
   * @param  requireValue  Indicates whether a value is required.
   *
   * @return  The filter obtained from the user, or {@code null} if the user did
   *          not provide a value, there is no default value, and no value is
   *          required.
   *
   * @throws  LDAPException  If an error occurs while obtaining the value from
   *                         the user.
   */
  @Nullable()
  private Filter promptForFilter(@NotNull final String prompt,
                                 @Nullable final Filter defaultValue,
                                 final boolean requireValue)
          throws LDAPException
  {
    tool.out();

    final String promptStr;
    if (defaultValue == null)
    {
      promptStr = prompt + ": ";
    }
    else
    {
      promptStr = prompt + " [" + defaultValue + "]: ";
    }

    tool.wrapStandardOut(0, 0, wrapColumn, false, promptStr);

    try
    {
      String line = systemInReader.readLine().trim();
      if (line.isEmpty() && (defaultValue != null))
      {
        line = String.valueOf(defaultValue);
      }

      if (line.isEmpty())
      {
        if (requireValue)
        {
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_PROMPT_VALUE_REQUIRED.get());
          return promptForFilter(prompt, defaultValue, requireValue);
        }
        else
        {
          return null;
        }
      }

      try
      {
        return Filter.create(line);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        tool.wrapErr(0, wrapColumn,
             ERR_INTERACTIVE_PROMPT_INVALID_FILTER.get());
        return promptForFilter(prompt, defaultValue, requireValue);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERACTIVE_PROMPT_ERROR_READING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Prompts the user to enter an integer value.
   *
   * @param  prompt        The prompt to display to the user.
   * @param  defaultValue  The value that should be selected if the user
   *                       presses ENTER without entering a value.
   * @param  lowerBound    The lower bound for valid values.
   * @param  upperBound    The upper bound for valid values.
   * @param  requireValue  Indicates whether a value is required.
   *
   * @return  The value obtained from the user, or {@code null} if the user did
   *          not provide a value, there is no default value, and no value is
   *          required.
   *
   * @throws  LDAPException  If an error occurs while obtaining the value from
   *                         the user.
   */
  @Nullable()
  private Integer promptForInteger(@NotNull final String prompt,
                                   @Nullable final Integer defaultValue,
                                   @Nullable final Integer lowerBound,
                                   @Nullable final Integer upperBound,
                                   final boolean requireValue)
          throws LDAPException
  {
    tool.out();

    final int max;
    if (upperBound == null)
    {
      max = Integer.MAX_VALUE;
    }
    else
    {
      max = upperBound;
    }

    final int min;
    if (lowerBound == null)
    {
      min = Integer.MIN_VALUE;
    }
    else
    {
      min = lowerBound;
    }

    final String promptStr;
    if (defaultValue == null)
    {
      promptStr = prompt + ": ";
    }
    else
    {
      promptStr = prompt + " [" + defaultValue + "]: ";
    }

    tool.wrapStandardOut(0, 0, wrapColumn, false, promptStr);

    try
    {
      String line = systemInReader.readLine().trim();
      if (line.isEmpty() && (defaultValue != null))
      {
        line = String.valueOf(defaultValue);
      }

      if (line.isEmpty())
      {
        if (requireValue)
        {
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_PROMPT_VALUE_REQUIRED.get());
          return promptForInteger(prompt, defaultValue, lowerBound, upperBound,
               requireValue);
        }
        else
        {
          return null;
        }
      }

      final int intValue;
      try
      {
        intValue = Integer.parseInt(line);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        tool.wrapErr(0, wrapColumn,
             ERR_INTERACTIVE_PROMPT_INVALID_INTEGER_WITH_RANGE.get(min, max));
        return promptForInteger(prompt, defaultValue, lowerBound, upperBound,
             requireValue);
      }

      if ((intValue > max) || (intValue < min))
      {
        tool.wrapErr(0, wrapColumn,
             ERR_INTERACTIVE_PROMPT_INVALID_INTEGER_WITH_RANGE.get(min, max));
        return promptForInteger(prompt, defaultValue, lowerBound, upperBound,
             requireValue);
      }

      return intValue;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERACTIVE_PROMPT_ERROR_READING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Prompts the user to enter a path.
   *
   * @param  prompt           The prompt to display to the user.
   * @param  defaultValue     The value that should be selected if the user
   *                          presses ENTER without entering a value.
   * @param  requireValue     Indicates whether a value is required.
   * @param  fileMustExist    Indicates whether the value must represent a path
   *                          that exists.
   * @param  parentMustExist  Indicates whether the parent directory containing
   *                          the specified path must exist.
   * @param  mustBeFile       Indicates whether the path must represent a file.
   * @param  mustBeDirectory  Indicates whether the path must represent a
   *                          directory.
   *
   * @return  The file obtained from the user, or {@code null} if the user did
   *          not provide a value, there is no default value, and no value is
   *          required.
   *
   * @throws  LDAPException  If an error occurs while obtaining the value from
   *                         the user.
   */
  @Nullable()
  private File promptForPath(@NotNull final String prompt,
                             @Nullable final String defaultValue,
                             final boolean requireValue,
                             final boolean fileMustExist,
                             final boolean parentMustExist,
                             final boolean mustBeFile,
                             final boolean mustBeDirectory)
       throws LDAPException
  {
    tool.out();

    final String promptStr;
    if (defaultValue == null)
    {
      promptStr = prompt + ": ";
    }
    else
    {
      promptStr = prompt + " [" + defaultValue + "]: ";
    }

    tool.wrapStandardOut(0, 0, wrapColumn, false, promptStr);

    try
    {
      String line = systemInReader.readLine().trim();
      if (line.isEmpty() && (defaultValue != null))
      {
        line = String.valueOf(defaultValue);
      }

      if (line.isEmpty())
      {
        if (requireValue)
        {
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_PROMPT_VALUE_REQUIRED.get());
          return promptForPath(prompt, defaultValue, requireValue,
               fileMustExist, parentMustExist, mustBeFile, mustBeDirectory);
        }
        else
        {
          return null;
        }
      }

      final File f = new File(line).getAbsoluteFile();
      if (! f.exists())
      {
        if (fileMustExist)
        {
          if (mustBeDirectory)
          {
            tool.wrapErr(0, wrapColumn,
                 ERR_INTERACTIVE_PROMPT_DIR_DOES_NOT_EXIST.get(
                      f.getAbsolutePath()));
            return promptForPath(prompt, defaultValue, requireValue,
                 fileMustExist, parentMustExist, mustBeFile, mustBeDirectory);
          }
          else
          {
            tool.wrapErr(0, wrapColumn,
                 ERR_INTERACTIVE_PROMPT_FILE_DOES_NOT_EXIST.get(
                      f.getAbsolutePath()));
            return promptForPath(prompt, defaultValue, requireValue,
                 fileMustExist, parentMustExist, mustBeFile, mustBeDirectory);
          }
        }
        else if (parentMustExist)
        {
          final File parent = f.getParentFile();
          if ((parent == null) || (! parent.exists()))
          {
            tool.wrapErr(0, wrapColumn,
                 ERR_INTERACTIVE_PROMPT_PARENT_DOES_NOT_EXIST.get(
                      f.getAbsolutePath()));
            return promptForPath(prompt, defaultValue, requireValue,
                 fileMustExist, parentMustExist, mustBeFile, mustBeDirectory);
          }
        }

        return f;
      }

      if (f.isDirectory())
      {
        if (mustBeFile)
        {
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_PROMPT_PATH_MUST_BE_FILE.get(
                    f.getAbsolutePath()));
          return promptForPath(prompt, defaultValue, requireValue,
               fileMustExist, parentMustExist, mustBeFile, mustBeDirectory);
        }
      }
      else if (mustBeDirectory)
      {
        tool.wrapErr(0, wrapColumn,
             ERR_INTERACTIVE_PROMPT_PATH_MUST_BE_DIR.get(
                  f.getAbsolutePath()));
        return promptForPath(prompt, defaultValue, requireValue,
             fileMustExist, parentMustExist, mustBeFile, mustBeDirectory);
      }

      return f;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERACTIVE_PROMPT_ERROR_READING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Prompts the user to enter a password.
   *
   * @param  prompt         The prompt to display to the user.
   * @param  confirmPrompt  A prompt that should be displayed before prompting
   *                        for the password a second time (to confirm that the
   *                        user entered it correctly the first time).  If this
   *                        is {@code null}, then there will be no prompt for
   *                        confirmation.
   * @param  requireValue   Indicates whether a value is required.
   *
   * @return  The password obtained from the user, or {@code null} if the user
   *          did not provide a value and no value is required.
   *
   * @throws  LDAPException  If an error occurs while obtaining the value from
   *                         the user.
   */
  @Nullable()
  private byte[] promptForPassword(@NotNull final String prompt,
                                   @Nullable final String confirmPrompt,
                                   final boolean requireValue)
          throws LDAPException
  {
    tool.out();

    tool.wrapStandardOut(0, 0, wrapColumn, false, prompt, ": ");


    try
    {
      final byte[] pwBytes;
      try
      {
        if (IN_UNIT_TEST)
        {
          PasswordReader.setTestReader(systemInReader);
        }
        pwBytes = PasswordReader.readPassword();
      }
      finally
      {
        PasswordReader.setTestReader(null);
      }

      if ((pwBytes == null) || (pwBytes.length == 0))
      {
        if (requireValue)
        {
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_PROMPT_VALUE_REQUIRED.get());
          return promptForPassword(prompt, confirmPrompt, requireValue);
        }
        else
        {
          return null;
        }
      }
      else
      {
        if (confirmPrompt != null)
        {
          final byte[] confirmedPWBytes;
          try
          {
            if (IN_UNIT_TEST)
            {
              PasswordReader.setTestReader(systemInReader);
            }

            tool.wrapStandardOut(0, 0, wrapColumn, false, confirmPrompt, ": ");
            confirmedPWBytes = PasswordReader.readPassword();

            if (! Arrays.equals(pwBytes, confirmedPWBytes))
            {
              tool.wrapErr(0, wrapColumn,
                   ERR_INTERACTIVE_PROMPT_CONFIRM_MISMATCH.get());
              return promptForPassword(prompt, confirmPrompt, requireValue);
            }
          }
          finally
          {
            PasswordReader.setTestReader(null);
          }
        }

        return pwBytes;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERACTIVE_PROMPT_ERROR_READING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Prompts the user to enter a timestamp.
   *
   * @param  prompt        The prompt to display to the user.
   * @param  defaultValue  The value that should be selected if the user
   *                       presses ENTER without entering a value.
   * @param  requireValue  Indicates whether a value is required.
   *
   * @return  An object pair that contains both the parsed date and the string
   *          representation provided by the user, or {@code null} if the user
   *          did not provide a value, there is no default value, and no value
   *          is required.
   *
   * @throws  LDAPException  If an error occurs while obtaining the value from
   *                         the user.
   */
  @Nullable()
  private ObjectPair<Date,String> promptForTimestamp(
                                       @NotNull final String prompt,
                                       @Nullable final Date defaultValue,
                                       final boolean requireValue)
          throws LDAPException
  {
    tool.out();

    final String promptStr;
    if (defaultValue == null)
    {
      promptStr = prompt + ": ";
    }
    else
    {
      promptStr = prompt + " [" + defaultValue + "]: ";
    }

    tool.wrapStandardOut(0, 0, wrapColumn, false, promptStr);

    try
    {
      String line = systemInReader.readLine().trim();
      if (line.isEmpty() && (defaultValue != null))
      {
        line = String.valueOf(defaultValue);
      }

      if (line.isEmpty())
      {
        if (requireValue)
        {
          tool.wrapErr(0, wrapColumn,
               ERR_INTERACTIVE_PROMPT_VALUE_REQUIRED.get());
          return promptForTimestamp(prompt, defaultValue, requireValue);
        }
        else
        {
          return null;
        }
      }

      try
      {
        return new ObjectPair<>(TimestampArgument.parseTimestamp(line), line);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        tool.wrapErr(0, wrapColumn,
             ERR_INTERACTIVE_PROMPT_INVALID_TIMESTAMP.get());
        return promptForTimestamp(prompt, defaultValue, requireValue);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERACTIVE_PROMPT_ERROR_READING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new string with enough initial spaces to ensure that the last
   * character of the returned string is also the last character of the provided
   * string.
   *
   * @param  s  The string to be right-aligned.
   * @param  w  The number of characters to include in the string that is
   *            returned.
   *
   * @return  A right-aligned representation of the provided string in the given
   *          width.
   */
  @NotNull()
  private static String rightAlign(@NotNull final String s, final int w)
  {
    final int l = s.length();
    if (l >= w)
    {
      return s;
    }

    final StringBuilder buffer = new StringBuilder(w);
    for (int i=0; i < (w-l); i++)
    {
      buffer.append(' ');
    }

    buffer.append(s);
    return buffer.toString();
  }



  /**
   * Creates a new string with enough trailing spaces to ensure that the
   * returned string has the specified width.
   *
   * @param  s  The string to be left-aligned.
   * @param  w  The number of characters to include in the string that is
   *            returned.
   *
   * @return  A left-aligned representation of the provided string in the given
   *          width.
   */
  @NotNull()
  private static String leftAlign(@NotNull final String s, final int w)
  {
    final int l = s.length();
    if (l >= w)
    {
      return s;
    }

    final StringBuilder buffer = new StringBuilder(w);
    buffer.append(s);
    while (buffer.length() < w)
    {
      buffer.append(' ');
    }
    return buffer.toString();
  }



  /**
   * Examines the arguments provided to the tool to ensure that all required,
   * exclusive, and dependent argument set constraints have been satisfied.
   *
   * @throws  ArgumentException  If any required or exclusive argument
   *                             constraints are not satisfied.
   */
  private void validateRequiredExclusiveAndDependentArgumentSets()
          throws ArgumentException
  {
    validateRequiredExclusiveAndDependentArgumentSets(parser);

    final SubCommand selectedSubCommand = parser.getSelectedSubCommand();
    if (selectedSubCommand != null)
    {
      validateRequiredExclusiveAndDependentArgumentSets(
           selectedSubCommand.getArgumentParser());
    }
  }



  /**
   * Examines the arguments provided to the tool to ensure that all required,
   * exclusive, and dependent argument set constraints have been satisfied.
   *
   * @param  parser The argument parser to examine.
   *
   * @throws  ArgumentException  If any required or exclusive argument
   *                             constraints are not satisfied.
   */
  private static void validateRequiredExclusiveAndDependentArgumentSets(
                           @NotNull final ArgumentParser parser)
          throws ArgumentException
  {
    // Iterate through the required argument sets and make sure that at least
    // one argument from each set is present.
    for (final Set<Argument> requiredArgumentsSet :
         parser.getRequiredArgumentSets())
    {
      boolean found = false;
      for (final Argument a : requiredArgumentsSet)
      {
        if (a.getNumOccurrences() > 0)
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        final StringBuilder buffer = new StringBuilder();
        for (final Argument a : requiredArgumentsSet)
        {
          if (buffer.length() > 0)
          {
            buffer.append(", ");
          }

          buffer.append(a.getIdentifierString());
        }

        throw new ArgumentException(
             ERR_INTERACTIVE_REQUIRED_ARG_SET_CONFLICT.get(buffer.toString()));
      }
    }


    // Iterate through the exclusive argument sets and make sure that none of
    // them has multiple arguments that are present.
    for (final Set<Argument> exclusiveArgumentsSet :
         parser.getExclusiveArgumentSets())
    {
      boolean found = false;
      for (final Argument a : exclusiveArgumentsSet)
      {
        if (a.getNumOccurrences() > 0)
        {
          if (found)
          {
            final StringBuilder buffer = new StringBuilder();
            for (final Argument exclusiveArg : exclusiveArgumentsSet)
            {
              if (buffer.length() > 0)
              {
                buffer.append(", ");
              }

              buffer.append(exclusiveArg.getIdentifierString());
            }

            throw new ArgumentException(
                 ERR_INTERACTIVE_EXCLUSIVE_ARG_SET_CONFLICT.get(
                      buffer.toString()));
          }
          else
          {
            found = true;
          }
        }
      }
    }


    // Iterate through the dependent argument sets and make sure that all of
    // those constraints are satisfied.
    for (final ObjectPair<Argument,Set<Argument>> p :
         parser.getDependentArgumentSets())
    {
      if (p.getFirst().getNumOccurrences() > 0)
      {
        boolean found = false;
        for (final Argument a : p.getSecond())
        {
          if (a.isPresent())
          {
            found = true;
            break;
          }
        }

        if (! found)
        {
          final StringBuilder buffer = new StringBuilder();
          for (final Argument arg : p.getSecond())
          {
            if (buffer.length() > 0)
            {
              buffer.append(", ");
            }

            buffer.append(arg.getIdentifierString());
          }

          throw new ArgumentException(
               ERR_INTERACTIVE_DEPENDENT_ARG_SET_CONFLICT.get(
                    p.getFirst().getIdentifierString(),
                    buffer.toString()));
        }
      }
    }
  }



  /**
   * Specifies whether this processor is being run in a unit test environment.
   *
   * @param  inUnitTest  Indicates whether this processor is being run in a unit
   *                     test environment.
   */
  static void setInUnitTest(final boolean inUnitTest)
  {
    IN_UNIT_TEST = inUnitTest;
  }
}
