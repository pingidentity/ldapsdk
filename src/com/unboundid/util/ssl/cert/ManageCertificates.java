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



import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.Base64;
import com.unboundid.util.BouncyCastleFIPSHelper;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.BooleanValueArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IA5StringArgumentValueValidator;
import com.unboundid.util.args.IPAddressArgumentValueValidator;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.OIDArgumentValueValidator;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.args.TimestampArgument;
import com.unboundid.util.args.SubCommand;
import com.unboundid.util.ssl.JVMDefaultTrustManager;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides a tool that can be used to manage X.509 certificates for
 * use in TLS communication.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ManageCertificates
       extends CommandLineTool
{
  /**
   * The path to the keystore with the JVM's set of default trusted issuer
   * certificates.
   */
  @Nullable private static final File JVM_DEFAULT_CACERTS_FILE;
  static
  {
    File caCertsFile;
    try
    {
      caCertsFile = JVMDefaultTrustManager.getInstance().getCACertsFile();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      caCertsFile = null;
    }

    JVM_DEFAULT_CACERTS_FILE = caCertsFile;
  }



  /**
   * The name of the keystore type that should be used for the Bouncy Castle
   * FIPS 140-2-compliant keystore.
   */
  @NotNull private static final String BCFKS_KEYSTORE_TYPE =
       BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE;



  /**
   * The name of the BCFKS keystore type, formatted in all lowercase.
   */
  @NotNull private static final String BCFKS_KEYSTORE_TYPE_LC =
       BCFKS_KEYSTORE_TYPE.toLowerCase();



  /**
   * The name of a system property that can be used to specify the default
   * keystore type for new keystores.
   */
  @NotNull private static final String PROPERTY_DEFAULT_KEYSTORE_TYPE =
       ManageCertificates.class.getName() + ".defaultKeystoreType";



  /**
   * The default keystore type that will be used for new keystores when the
   * type is not specified.
   */
  @NotNull private static final String DEFAULT_KEYSTORE_TYPE;
  static
  {
    final String propertyValue =
         StaticUtils.getSystemProperty(PROPERTY_DEFAULT_KEYSTORE_TYPE);
    if (CryptoHelper.usingFIPSMode() ||
         ((propertyValue != null) && propertyValue.equalsIgnoreCase(
              BCFKS_KEYSTORE_TYPE)))
    {
      DEFAULT_KEYSTORE_TYPE = BCFKS_KEYSTORE_TYPE;
    }
    else if ((propertyValue != null) &&
         (propertyValue.equalsIgnoreCase("PKCS12") ||
              propertyValue.equalsIgnoreCase("PKCS#12") ||
              propertyValue.equalsIgnoreCase("PKCS #12") ||
              propertyValue.equalsIgnoreCase("PKCS 12")))
    {
      DEFAULT_KEYSTORE_TYPE = CryptoHelper.KEY_STORE_TYPE_PKCS_12;
    }
    else
    {
      DEFAULT_KEYSTORE_TYPE = CryptoHelper.KEY_STORE_TYPE_JKS;
    }
  }



  /**
   * The column at which to wrap long lines of output.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The set of values that will be allowed for the keystore type argument.
   */
  @NotNull private static final Set<String> ALLOWED_KEYSTORE_TYPE_VALUES =
       StaticUtils.setOf("jks", "pkcs12", "pkcs 12", "pkcs#12", "pkcs #12",
            BCFKS_KEYSTORE_TYPE_LC);



  // The global argument parser used by this tool.
  @Nullable private volatile ArgumentParser globalParser = null;

  // The argument parser for the selected subcommand.
  @Nullable private volatile ArgumentParser subCommandParser = null;

  // The input stream to use for standard input.
  @NotNull private final InputStream in;



  /**
   * Invokes this tool with the default standard output and standard error and
   * the provided set of arguments.
   *
   * @param  args  The command-line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.in, System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(Math.max(1, Math.min(resultCode.intValue(), 255)));
    }
  }



  /**
   * Invokes this tool with the provided output and error streams and set of
   * arguments.
   *
   * @param  in    The input stream to use for standard input.  It may be
   *               {@code null} if no input stream should be available.
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  The result code obtained from tool processing.
   */
  @NotNull()
  public static ResultCode main(@Nullable final InputStream in,
                                @Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final ManageCertificates manageCertificates =
         new ManageCertificates(in, out, err);
    return manageCertificates.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided output and error
   * streams.  Standard input will bot be available.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public ManageCertificates(@Nullable final OutputStream out,
                            @Nullable final OutputStream err)
  {
    this(null, out, err);
  }



  /**
   * Creates a new instance of this tool with the provided output and error
   * streams.
   *
   * @param  in   The input stream to use for standard input.  It may be
   *              {@code null} if no input stream should be available.
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public ManageCertificates(@Nullable final InputStream in,
                            @Nullable final OutputStream out,
                            @Nullable final OutputStream err)
  {
    super(out, err);

    if (in == null)
    {
      this.in = new ByteArrayInputStream(StaticUtils.NO_BYTES);
    }
    else
    {
      this.in = in;
    }
  }



  /**
   * Retrieves the name of this tool.  It should be the name of the command used
   * to invoke this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "manage-certificates";
  }



  /**
   * Retrieves a human-readable description for this tool.
   *
   * @return  A human-readable description for this tool.
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_MANAGE_CERTS_TOOL_DESC.get();
  }



  /**
   * Retrieves a version string for this tool, if available.
   *
   * @return  A version string for this tool, or {@code null} if none is
   *          available.
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * Indicates whether this tool should provide support for an interactive mode,
   * in which the tool offers a mode in which the arguments can be provided in
   * a text-driven menu rather than requiring them to be given on the command
   * line.  If interactive mode is supported, it may be invoked using the
   * "--interactive" argument.  Alternately, if interactive mode is supported
   * and {@link #defaultsToInteractiveMode()} returns {@code true}, then
   * interactive mode may be invoked by simply launching the tool without any
   * arguments.
   *
   * @return  {@code true} if this tool supports interactive mode, or
   *          {@code false} if not.
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool defaults to launching in interactive mode if
   * the tool is invoked without any command-line arguments.  This will only be
   * used if {@link #supportsInteractiveMode()} returns {@code true}.
   *
   * @return  {@code true} if this tool defaults to using interactive mode if
   *          launched without any command-line arguments, or {@code false} if
   *          not.
   */
  @Override()
  public boolean defaultsToInteractiveMode()
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
   * Indicates whether this tool should provide arguments for redirecting output
   * to a file.  If this method returns {@code true}, then the tool will offer
   * an "--outputFile" argument that will specify the path to a file to which
   * all standard output and standard error content will be written, and it will
   * also offer a "--teeToStandardOut" argument that can only be used if the
   * "--outputFile" argument is present and will cause all output to be written
   * to both the specified output file and to standard output.
   *
   * @return  {@code true} if this tool should provide arguments for redirecting
   *          output to a file, or {@code false} if not.
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    return false;
  }



  /**
   * Indicates whether to log messages about the launch and completion of this
   * tool into the invocation log of Ping Identity server products that may
   * include it.  This method is not needed for tools that are not expected to
   * be part of the Ping Identity server products suite.  Further, this value
   * may be overridden by settings in the server's
   * tool-invocation-logging.properties file.
   * <BR><BR>
   * This method should generally return {@code true} for tools that may alter
   * the server configuration, data, or other state information, and
   * {@code false} for tools that do not make any changes.
   *
   * @return  {@code true} if Ping Identity server products should include
   *          messages about the launch and completion of this tool in tool
   *          invocation log files by default, or {@code false} if not.
   */
  @Override()
  protected boolean logToolInvocationByDefault()
  {
    return true;
  }



  /**
   * Adds the command-line arguments supported for use with this tool to the
   * provided argument parser.  The tool may need to retain references to the
   * arguments (and/or the argument parser, if trailing arguments are allowed)
   * to it in order to obtain their values for use in later processing.
   *
   * @param  parser  The argument parser to which the arguments are to be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding any of the
   *                             tool-specific arguments to the provided
   *                             argument parser.
   */
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    globalParser = parser;


    // Define the "list-certificates" subcommand and all of its arguments.
    final ArgumentParser listCertsParser = new ArgumentParser(
         "list-certificates", INFO_MANAGE_CERTS_SC_LIST_CERTS_DESC.get());

    final FileArgument listCertsKeystore = new FileArgument(null, "keystore",
         (JVM_DEFAULT_CACERTS_FILE == null), 1, null,
         INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_KS_DESC.get(), true, true,  true,
         false);
    listCertsKeystore.addLongIdentifier("keystore-path", true);
    listCertsKeystore.addLongIdentifier("keystorePath", true);
    listCertsKeystore.addLongIdentifier("keystore-file", true);
    listCertsKeystore.addLongIdentifier("keystoreFile", true);
    listCertsParser.addArgument(listCertsKeystore);

    if (JVM_DEFAULT_CACERTS_FILE != null)
    {
      final BooleanArgument listCertsUseJVMDefault = new BooleanArgument(null,
           "use-jvm-default-trust-store", 1,
           INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_JVM_DEFAULT_DESC.get(
                JVM_DEFAULT_CACERTS_FILE.getAbsolutePath()));
      listCertsUseJVMDefault.addLongIdentifier("useJVMDefaultTrustStore", true);
      listCertsUseJVMDefault.addLongIdentifier("jvm-default", true);
      listCertsUseJVMDefault.addLongIdentifier("jvmDefault", true);
      listCertsParser.addArgument(listCertsUseJVMDefault);

      listCertsParser.addRequiredArgumentSet(listCertsUseJVMDefault,
           listCertsKeystore);
      listCertsParser.addExclusiveArgumentSet(listCertsUseJVMDefault,
           listCertsKeystore);
    }

    final StringArgument listCertsKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_KS_PW_DESC.get());
    listCertsKeystorePassword.addLongIdentifier("keystorePassword", true);
    listCertsKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    listCertsKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    listCertsKeystorePassword.addLongIdentifier("keystore-pin", true);
    listCertsKeystorePassword.addLongIdentifier("keystorePIN", true);
    listCertsKeystorePassword.addLongIdentifier("storepass", true);
    listCertsKeystorePassword.setSensitive(true);
    listCertsParser.addArgument(listCertsKeystorePassword);

    final FileArgument listCertsKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_KS_PW_FILE_DESC.get(), true, true,
         true, false);
    listCertsKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    listCertsKeystorePasswordFile.addLongIdentifier("keystore-passphrase-file",
         true);
    listCertsKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    listCertsKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    listCertsKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    listCertsParser.addArgument(listCertsKeystorePasswordFile);

    final BooleanArgument listCertsPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_PROMPT_FOR_KS_PW_DESC.get());
    listCertsPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    listCertsPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    listCertsPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    listCertsPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    listCertsPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    listCertsParser.addArgument(listCertsPromptForKeystorePassword);

    final StringArgument listCertsKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    listCertsKeystoreType.addLongIdentifier("keystoreType", true);
    listCertsKeystoreType.addLongIdentifier("storetype", true);
    listCertsParser.addArgument(listCertsKeystoreType);

    final StringArgument listCertsAlias = new StringArgument(null, "alias",
         false, 0, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_ALIAS_DESC.get());
    listCertsAlias.addLongIdentifier("nickname", true);
    listCertsParser.addArgument(listCertsAlias);

    final BooleanArgument listCertsDisplayPEM = new BooleanArgument(null,
         "display-pem-certificate", 1,
         INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_DISPLAY_PEM_DESC.get());
    listCertsDisplayPEM.addLongIdentifier("displayPEMCertificate", true);
    listCertsDisplayPEM.addLongIdentifier("display-pem", true);
    listCertsDisplayPEM.addLongIdentifier("displayPEM", true);
    listCertsDisplayPEM.addLongIdentifier("show-pem-certificate", true);
    listCertsDisplayPEM.addLongIdentifier("showPEMCertificate", true);
    listCertsDisplayPEM.addLongIdentifier("show-pem", true);
    listCertsDisplayPEM.addLongIdentifier("showPEM", true);
    listCertsDisplayPEM.addLongIdentifier("pem", true);
    listCertsDisplayPEM.addLongIdentifier("rfc", true);
    listCertsParser.addArgument(listCertsDisplayPEM);

    final BooleanArgument listCertsVerbose = new BooleanArgument(null,
         "verbose", 1, INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_VERBOSE_DESC.get());
    listCertsParser.addArgument(listCertsVerbose);

    final BooleanArgument listCertsDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_LIST_CERTS_ARG_DISPLAY_COMMAND_DESC.get());
    listCertsDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    listCertsDisplayCommand.addLongIdentifier("show-keytool-command", true);
    listCertsDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    listCertsParser.addArgument(listCertsDisplayCommand);

    listCertsParser.addExclusiveArgumentSet(listCertsKeystorePassword,
         listCertsKeystorePasswordFile, listCertsPromptForKeystorePassword);

    final LinkedHashMap<String[],String> listCertsExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(3));
    listCertsExamples.put(
         new String[]
         {
           "list-certificates",
           "--keystore", getPlatformSpecificPath("config", "keystore")
         },
         INFO_MANAGE_CERTS_SC_LIST_CERTS_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "keystore")));
    listCertsExamples.put(
         new String[]
         {
           "list-certificates",
           "--keystore", getPlatformSpecificPath("config", "keystore.p12"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--verbose",
           "--display-pem-certificate",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_LIST_CERTS_EXAMPLE_2.get(
              getPlatformSpecificPath("config", "keystore.p12"),
              getPlatformSpecificPath("config", "keystore.pin")));
    if (JVM_DEFAULT_CACERTS_FILE != null)
    {
      listCertsExamples.put(
           new String[]
           {
             "list-certificates",
             "--use-jvm-default-trust-store"
           },
           INFO_MANAGE_CERTS_SC_LIST_CERTS_EXAMPLE_3.get());
    }

    final SubCommand listCertsSubCommand = new SubCommand("list-certificates",
         INFO_MANAGE_CERTS_SC_LIST_CERTS_DESC.get(), listCertsParser,
         listCertsExamples);
    listCertsSubCommand.addName("listCertificates", true);
    listCertsSubCommand.addName("list-certs", true);
    listCertsSubCommand.addName("listCerts", true);
    listCertsSubCommand.addName("list", false);

    parser.addSubCommand(listCertsSubCommand);


    // Define the "export-certificate" subcommand and all of its arguments.
    final ArgumentParser exportCertParser = new ArgumentParser(
         "export-certificate", INFO_MANAGE_CERTS_SC_EXPORT_CERT_DESC.get());

    final FileArgument exportCertKeystore = new FileArgument(null, "keystore",
         (JVM_DEFAULT_CACERTS_FILE == null), 1, null,
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_KS_DESC.get(), true, true,  true,
         false);
    exportCertKeystore.addLongIdentifier("keystore-path", true);
    exportCertKeystore.addLongIdentifier("keystorePath", true);
    exportCertKeystore.addLongIdentifier("keystore-file", true);
    exportCertKeystore.addLongIdentifier("keystoreFile", true);
    exportCertParser.addArgument(exportCertKeystore);

    if (JVM_DEFAULT_CACERTS_FILE != null)
    {
      final BooleanArgument exportCertUseJVMDefault = new BooleanArgument(null,
           "use-jvm-default-trust-store", 1,
           INFO_MANAGE_CERTS_SC_EXPORT_CERTS_ARG_JVM_DEFAULT_DESC.get(
                JVM_DEFAULT_CACERTS_FILE.getAbsolutePath()));
      exportCertUseJVMDefault.addLongIdentifier("useJVMDefaultTrustStore",
           true);
      exportCertUseJVMDefault.addLongIdentifier("jvm-default", true);
      exportCertUseJVMDefault.addLongIdentifier("jvmDefault", true);
      exportCertParser.addArgument(exportCertUseJVMDefault);

      exportCertParser.addRequiredArgumentSet(exportCertUseJVMDefault,
           exportCertKeystore);
      exportCertParser.addExclusiveArgumentSet(exportCertUseJVMDefault,
           exportCertKeystore);
    }

    final StringArgument exportCertKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_KS_PW_DESC.get());
    exportCertKeystorePassword.addLongIdentifier("keystorePassword", true);
    exportCertKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    exportCertKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    exportCertKeystorePassword.addLongIdentifier("keystore-pin", true);
    exportCertKeystorePassword.addLongIdentifier("keystorePIN", true);
    exportCertKeystorePassword.addLongIdentifier("storepass", true);
    exportCertKeystorePassword.setSensitive(true);
    exportCertParser.addArgument(exportCertKeystorePassword);

    final FileArgument exportCertKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_KS_PW_FILE_DESC.get(), true, true,
         true, false);
    exportCertKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    exportCertKeystorePasswordFile.addLongIdentifier("keystore-passphrase-file",
         true);
    exportCertKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    exportCertKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    exportCertKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    exportCertParser.addArgument(exportCertKeystorePasswordFile);

    final BooleanArgument exportCertPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_PROMPT_FOR_KS_PW_DESC.get());
    exportCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    exportCertPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    exportCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    exportCertPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    exportCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    exportCertParser.addArgument(exportCertPromptForKeystorePassword);

    final StringArgument exportCertKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    exportCertKeystoreType.addLongIdentifier("keystoreType", true);
    exportCertKeystoreType.addLongIdentifier("storetype", true);
    exportCertParser.addArgument(exportCertKeystoreType);

    final StringArgument exportCertAlias = new StringArgument(null, "alias",
         true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_ALIAS_DESC.get());
    exportCertAlias.addLongIdentifier("nickname", true);
    exportCertParser.addArgument(exportCertAlias);

    final BooleanArgument exportCertChain = new BooleanArgument(null,
         "export-certificate-chain", 1,
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_CHAIN_DESC.get());
    exportCertChain.addLongIdentifier("exportCertificateChain", true);
    exportCertChain.addLongIdentifier("export-chain", true);
    exportCertChain.addLongIdentifier("exportChain", true);
    exportCertChain.addLongIdentifier("certificate-chain", true);
    exportCertChain.addLongIdentifier("certificateChain", true);
    exportCertChain.addLongIdentifier("chain", true);
    exportCertParser.addArgument(exportCertChain);

    final Set<String> exportCertOutputFormatAllowedValues = StaticUtils.setOf(
         "PEM", "text", "txt", "RFC", "DER", "binary", "bin");
    final StringArgument exportCertOutputFormat = new StringArgument(null,
         "output-format", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_FORMAT.get(),
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_FORMAT_DESC.get(),
         exportCertOutputFormatAllowedValues, "PEM");
    exportCertOutputFormat.addLongIdentifier("outputFormat", true);
    exportCertParser.addArgument(exportCertOutputFormat);

    final FileArgument exportCertOutputFile = new FileArgument(null,
         "output-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_FILE_DESC.get(), false, true,
         true, false);
    exportCertOutputFile.addLongIdentifier("outputFile", true);
    exportCertOutputFile.addLongIdentifier("export-file", true);
    exportCertOutputFile.addLongIdentifier("exportFile", true);
    exportCertOutputFile.addLongIdentifier("certificate-file", true);
    exportCertOutputFile.addLongIdentifier("certificateFile", true);
    exportCertOutputFile.addLongIdentifier("file", true);
    exportCertOutputFile.addLongIdentifier("filename", true);
    exportCertParser.addArgument(exportCertOutputFile);

    final BooleanArgument exportCertSeparateFile = new BooleanArgument(null,
         "separate-file-per-certificate", 1,
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_SEPARATE_FILE_DESC.get());
    exportCertSeparateFile.addLongIdentifier("separateFilePerCertificate",
         true);
    exportCertSeparateFile.addLongIdentifier("separate-files", true);
    exportCertSeparateFile.addLongIdentifier("separateFiles", true);
    exportCertParser.addArgument(exportCertSeparateFile);

    final BooleanArgument exportCertDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_ARG_DISPLAY_COMMAND_DESC.get());
    exportCertDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    exportCertDisplayCommand.addLongIdentifier("show-keytool-command", true);
    exportCertDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    exportCertParser.addArgument(exportCertDisplayCommand);

    exportCertParser.addExclusiveArgumentSet(exportCertKeystorePassword,
         exportCertKeystorePasswordFile, exportCertPromptForKeystorePassword);
    exportCertParser.addDependentArgumentSet(exportCertSeparateFile,
         exportCertChain);
    exportCertParser.addDependentArgumentSet(exportCertSeparateFile,
         exportCertOutputFile);

    final LinkedHashMap<String[],String> exportCertExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));
    exportCertExamples.put(
         new String[]
         {
           "export-certificate",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--alias", "server-cert"
         },
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_EXAMPLE_1.get());
    exportCertExamples.put(
         new String[]
         {
           "export-certificate",
           "--keystore", getPlatformSpecificPath("config", "keystore.p12"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--export-certificate-chain",
           "--output-format", "DER",
           "--output-file", "certificate-chain.der",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_EXAMPLE_2.get());

    final SubCommand exportCertSubCommand = new SubCommand("export-certificate",
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_DESC.get(), exportCertParser,
         exportCertExamples);
    exportCertSubCommand.addName("exportCertificate", true);
    exportCertSubCommand.addName("export-cert", true);
    exportCertSubCommand.addName("exportCert", true);
    exportCertSubCommand.addName("export", true);

    parser.addSubCommand(exportCertSubCommand);


    // Define the "export-private-key" subcommand and all of its arguments.
    final ArgumentParser exportKeyParser = new ArgumentParser(
         "export-private-key", INFO_MANAGE_CERTS_SC_EXPORT_KEY_DESC.get());

    final FileArgument exportKeyKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_KS_DESC.get(),
         true, true,  true, false);
    exportKeyKeystore.addLongIdentifier("keystore-path", true);
    exportKeyKeystore.addLongIdentifier("keystorePath", true);
    exportKeyKeystore.addLongIdentifier("keystore-file", true);
    exportKeyKeystore.addLongIdentifier("keystoreFile", true);
    exportKeyParser.addArgument(exportKeyKeystore);

    final StringArgument exportKeyKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_KS_PW_DESC.get());
    exportKeyKeystorePassword.addLongIdentifier("keystorePassword", true);
    exportKeyKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    exportKeyKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    exportKeyKeystorePassword.addLongIdentifier("keystore-pin", true);
    exportKeyKeystorePassword.addLongIdentifier("keystorePIN", true);
    exportKeyKeystorePassword.addLongIdentifier("storepass", true);
    exportKeyKeystorePassword.setSensitive(true);
    exportKeyParser.addArgument(exportKeyKeystorePassword);

    final FileArgument exportKeyKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_KS_PW_FILE_DESC.get(), true, true,
         true, false);
    exportKeyKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    exportKeyKeystorePasswordFile.addLongIdentifier("keystore-passphrase-file",
         true);
    exportKeyKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    exportKeyKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    exportKeyKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    exportKeyParser.addArgument(exportKeyKeystorePasswordFile);

    final BooleanArgument exportKeyPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_PROMPT_FOR_KS_PW_DESC.get());
    exportKeyPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    exportKeyPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    exportKeyPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    exportKeyPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    exportKeyPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    exportKeyParser.addArgument(exportKeyPromptForKeystorePassword);

    final StringArgument exportKeyPKPassword = new StringArgument(null,
         "private-key-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_PK_PW_DESC.get());
    exportKeyPKPassword.addLongIdentifier("privateKeyPassword", true);
    exportKeyPKPassword.addLongIdentifier("private-key-passphrase", true);
    exportKeyPKPassword.addLongIdentifier("privateKeyPassphrase", true);
    exportKeyPKPassword.addLongIdentifier("private-key-pin", true);
    exportKeyPKPassword.addLongIdentifier("privateKeyPIN", true);
    exportKeyPKPassword.addLongIdentifier("key-password", true);
    exportKeyPKPassword.addLongIdentifier("keyPassword", true);
    exportKeyPKPassword.addLongIdentifier("key-passphrase", true);
    exportKeyPKPassword.addLongIdentifier("keyPassphrase", true);
    exportKeyPKPassword.addLongIdentifier("key-pin", true);
    exportKeyPKPassword.addLongIdentifier("keyPIN", true);
    exportKeyPKPassword.addLongIdentifier("keypass", true);
    exportKeyPKPassword.setSensitive(true);
    exportKeyParser.addArgument(exportKeyPKPassword);

    final FileArgument exportKeyPKPasswordFile = new FileArgument(null,
         "private-key-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_PK_PW_FILE_DESC.get(), true, true,
         true, false);
    exportKeyPKPasswordFile.addLongIdentifier("privateKeyPasswordFile", true);
    exportKeyPKPasswordFile.addLongIdentifier("private-key-passphrase-file",
         true);
    exportKeyPKPasswordFile.addLongIdentifier("privateKeyPassphraseFile",
         true);
    exportKeyPKPasswordFile.addLongIdentifier("private-key-pin-file",
         true);
    exportKeyPKPasswordFile.addLongIdentifier("privateKeyPINFile", true);
    exportKeyPKPasswordFile.addLongIdentifier("key-password-file", true);
    exportKeyPKPasswordFile.addLongIdentifier("keyPasswordFile", true);
    exportKeyPKPasswordFile.addLongIdentifier("key-passphrase-file",
         true);
    exportKeyPKPasswordFile.addLongIdentifier("keyPassphraseFile",
         true);
    exportKeyPKPasswordFile.addLongIdentifier("key-pin-file",
         true);
    exportKeyPKPasswordFile.addLongIdentifier("keyPINFile", true);
    exportKeyParser.addArgument(exportKeyPKPasswordFile);

    final BooleanArgument exportKeyPromptForPKPassword =
         new BooleanArgument(null, "prompt-for-private-key-password",
        INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_PROMPT_FOR_PK_PW_DESC.get());
    exportKeyPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassword", true);
    exportKeyPromptForPKPassword.addLongIdentifier(
         "prompt-for-private-key-passphrase", true);
    exportKeyPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassphrase", true);
    exportKeyPromptForPKPassword.addLongIdentifier("prompt-for-private-key-pin",
         true);
    exportKeyPromptForPKPassword.addLongIdentifier("promptForPrivateKeyPIN",
         true);
    exportKeyPromptForPKPassword.addLongIdentifier("prompt-for-key-password",
         true);
    exportKeyPromptForPKPassword.addLongIdentifier("promptForKeyPassword",
         true);
    exportKeyPromptForPKPassword.addLongIdentifier(
         "prompt-for-key-passphrase", true);
    exportKeyPromptForPKPassword.addLongIdentifier(
         "promptForKeyPassphrase", true);
    exportKeyPromptForPKPassword.addLongIdentifier("prompt-for-key-pin", true);
    exportKeyPromptForPKPassword.addLongIdentifier("promptForKeyPIN", true);
    exportKeyParser.addArgument(exportKeyPromptForPKPassword);

    final StringArgument exportKeyKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    exportKeyKeystoreType.addLongIdentifier("keystoreType", true);
    exportKeyKeystoreType.addLongIdentifier("storetype", true);
    exportKeyParser.addArgument(exportKeyKeystoreType);

    final StringArgument exportKeyAlias = new StringArgument(null, "alias",
         true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_ALIAS_DESC.get());
    exportKeyAlias.addLongIdentifier("nickname", true);
    exportKeyParser.addArgument(exportKeyAlias);

    final Set<String> exportKeyOutputFormatAllowedValues = StaticUtils.setOf(
         "PEM", "text", "txt", "RFC", "DER", "binary", "bin");
    final StringArgument exportKeyOutputFormat = new StringArgument(null,
         "output-format", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_FORMAT.get(),
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_FORMAT_DESC.get(),
         exportKeyOutputFormatAllowedValues, "PEM");
    exportKeyOutputFormat.addLongIdentifier("outputFormat", true);
    exportKeyParser.addArgument(exportKeyOutputFormat);

    final FileArgument exportKeyOutputFile = new FileArgument(null,
         "output-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_ARG_FILE_DESC.get(), false, true,
         true, false);
    exportKeyOutputFile.addLongIdentifier("outputFile", true);
    exportKeyOutputFile.addLongIdentifier("export-file", true);
    exportKeyOutputFile.addLongIdentifier("exportFile", true);
    exportKeyOutputFile.addLongIdentifier("private-key-file", true);
    exportKeyOutputFile.addLongIdentifier("privateKeyFile", true);
    exportKeyOutputFile.addLongIdentifier("key-file", true);
    exportKeyOutputFile.addLongIdentifier("keyFile", true);
    exportKeyOutputFile.addLongIdentifier("file", true);
    exportKeyOutputFile.addLongIdentifier("filename", true);
    exportKeyParser.addArgument(exportKeyOutputFile);

    exportKeyParser.addRequiredArgumentSet(exportKeyKeystorePassword,
         exportKeyKeystorePasswordFile, exportKeyPromptForKeystorePassword);
    exportKeyParser.addExclusiveArgumentSet(exportKeyKeystorePassword,
         exportKeyKeystorePasswordFile, exportKeyPromptForKeystorePassword);
    exportKeyParser.addExclusiveArgumentSet(exportKeyPKPassword,
         exportKeyPKPasswordFile, exportKeyPromptForPKPassword);

    final LinkedHashMap<String[],String> exportKeyExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));
    exportKeyExamples.put(
         new String[]
         {
           "export-private-key",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert"
         },
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_EXAMPLE_1.get());
    exportKeyExamples.put(
         new String[]
         {
           "export-private-key",
           "--keystore", getPlatformSpecificPath("config", "keystore.p12"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--private-key-password-file",
                getPlatformSpecificPath("config", "server-cert-key.pin"),
           "--alias", "server-cert",
           "--output-format", "DER",
           "--output-file", "server-cert-key.der"
         },
         INFO_MANAGE_CERTS_SC_EXPORT_KEY_EXAMPLE_2.get());

    final SubCommand exportKeySubCommand = new SubCommand("export-private-key",
         INFO_MANAGE_CERTS_SC_EXPORT_CERT_DESC.get(), exportKeyParser,
         exportKeyExamples);
    exportKeySubCommand.addName("exportPrivateKey", true);
    exportKeySubCommand.addName("export-key", true);
    exportKeySubCommand.addName("exportKey", true);

    parser.addSubCommand(exportKeySubCommand);


    // Define the "import-certificate" subcommand and all of its arguments.
    final ArgumentParser importCertParser = new ArgumentParser(
         "import-certificate", INFO_MANAGE_CERTS_SC_IMPORT_CERT_DESC.get());

    final FileArgument importCertKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_KS_DESC.get(),
         false, true,  true, false);
    importCertKeystore.addLongIdentifier("keystore-path", true);
    importCertKeystore.addLongIdentifier("keystorePath", true);
    importCertKeystore.addLongIdentifier("keystore-file", true);
    importCertKeystore.addLongIdentifier("keystoreFile", true);
    importCertParser.addArgument(importCertKeystore);

    final StringArgument importCertKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_KS_PW_DESC.get());
    importCertKeystorePassword.addLongIdentifier("keystorePassword", true);
    importCertKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    importCertKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    importCertKeystorePassword.addLongIdentifier("keystore-pin", true);
    importCertKeystorePassword.addLongIdentifier("keystorePIN", true);
    importCertKeystorePassword.addLongIdentifier("storepass", true);
    importCertKeystorePassword.setSensitive(true);
    importCertParser.addArgument(importCertKeystorePassword);

    final FileArgument importCertKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_KS_PW_FILE_DESC.get(), true, true,
         true, false);
    importCertKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    importCertKeystorePasswordFile.addLongIdentifier("keystore-passphrase-file",
         true);
    importCertKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    importCertKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    importCertKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    importCertParser.addArgument(importCertKeystorePasswordFile);

    final BooleanArgument importCertPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_PROMPT_FOR_KS_PW_DESC.get());
    importCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    importCertPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    importCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    importCertPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    importCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    importCertParser.addArgument(importCertPromptForKeystorePassword);

    final StringArgument importCertKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    importCertKeystoreType.addLongIdentifier("keystoreType", true);
    importCertKeystoreType.addLongIdentifier("storetype", true);
    importCertParser.addArgument(importCertKeystoreType);

    final StringArgument importCertAlias = new StringArgument(null, "alias",
         true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_ALIAS_DESC.get());
    importCertAlias.addLongIdentifier("nickname", true);
    importCertParser.addArgument(importCertAlias);

    final FileArgument importCertCertificateFile = new FileArgument(null,
         "certificate-file", true, 0, null,
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_CERT_FILE_DESC.get(), true, true,
         true, false);
    importCertCertificateFile.addLongIdentifier("certificateFile", true);
    importCertCertificateFile.addLongIdentifier("certificate-chain-file", true);
    importCertCertificateFile.addLongIdentifier("certificateChainFile", true);
    importCertCertificateFile.addLongIdentifier("input-file", true);
    importCertCertificateFile.addLongIdentifier("inputFile", true);
    importCertCertificateFile.addLongIdentifier("import-file", true);
    importCertCertificateFile.addLongIdentifier("importFile", true);
    importCertCertificateFile.addLongIdentifier("file", true);
    importCertCertificateFile.addLongIdentifier("filename", true);
    importCertParser.addArgument(importCertCertificateFile);

    final FileArgument importCertPKFile = new FileArgument(null,
         "private-key-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_KEY_FILE_DESC.get(), true, true,
         true, false);
    importCertPKFile.addLongIdentifier("privateKeyFile", true);
    importCertPKFile.addLongIdentifier("key-file", true);
    importCertPKFile.addLongIdentifier("keyFile", true);
    importCertParser.addArgument(importCertPKFile);

    final StringArgument importCertPKPassword = new StringArgument(null,
         "private-key-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_PK_PW_DESC.get());
    importCertPKPassword.addLongIdentifier("privateKeyPassword", true);
    importCertPKPassword.addLongIdentifier("private-key-passphrase", true);
    importCertPKPassword.addLongIdentifier("privateKeyPassphrase", true);
    importCertPKPassword.addLongIdentifier("private-key-pin", true);
    importCertPKPassword.addLongIdentifier("privateKeyPIN", true);
    importCertPKPassword.addLongIdentifier("key-password", true);
    importCertPKPassword.addLongIdentifier("keyPassword", true);
    importCertPKPassword.addLongIdentifier("key-passphrase", true);
    importCertPKPassword.addLongIdentifier("keyPassphrase", true);
    importCertPKPassword.addLongIdentifier("key-pin", true);
    importCertPKPassword.addLongIdentifier("keyPIN", true);
    importCertPKPassword.addLongIdentifier("keypass", true);
    importCertPKPassword.setSensitive(true);
    importCertParser.addArgument(importCertPKPassword);

    final FileArgument importCertPKPasswordFile = new FileArgument(null,
         "private-key-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_PK_PW_FILE_DESC.get(), true, true,
         true, false);
    importCertPKPasswordFile.addLongIdentifier("privateKeyPasswordFile", true);
    importCertPKPasswordFile.addLongIdentifier("private-key-passphrase-file",
         true);
    importCertPKPasswordFile.addLongIdentifier("privateKeyPassphraseFile",
         true);
    importCertPKPasswordFile.addLongIdentifier("private-key-pin-file",
         true);
    importCertPKPasswordFile.addLongIdentifier("privateKeyPINFile", true);
    importCertPKPasswordFile.addLongIdentifier("key-password-file", true);
    importCertPKPasswordFile.addLongIdentifier("keyPasswordFile", true);
    importCertPKPasswordFile.addLongIdentifier("key-passphrase-file",
         true);
    importCertPKPasswordFile.addLongIdentifier("keyPassphraseFile",
         true);
    importCertPKPasswordFile.addLongIdentifier("key-pin-file",
         true);
    importCertPKPasswordFile.addLongIdentifier("keyPINFile", true);
    importCertParser.addArgument(importCertPKPasswordFile);

    final BooleanArgument importCertPromptForPKPassword =
         new BooleanArgument(null, "prompt-for-private-key-password",
        INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_PROMPT_FOR_PK_PW_DESC.get());
    importCertPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassword", true);
    importCertPromptForPKPassword.addLongIdentifier(
         "prompt-for-private-key-passphrase", true);
    importCertPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassphrase", true);
    importCertPromptForPKPassword.addLongIdentifier(
         "prompt-for-private-key-pin", true);
    importCertPromptForPKPassword.addLongIdentifier("promptForPrivateKeyPIN",
         true);
    importCertPromptForPKPassword.addLongIdentifier("prompt-for-key-password",
         true);
    importCertPromptForPKPassword.addLongIdentifier("promptForKeyPassword",
         true);
    importCertPromptForPKPassword.addLongIdentifier(
         "prompt-for-key-passphrase", true);
    importCertPromptForPKPassword.addLongIdentifier(
         "promptForKeyPassphrase", true);
    importCertPromptForPKPassword.addLongIdentifier("prompt-for-key-pin", true);
    importCertPromptForPKPassword.addLongIdentifier("promptForKeyPIN", true);
    importCertParser.addArgument(importCertPromptForPKPassword);

    final BooleanArgument importCertNoPrompt = new BooleanArgument(null,
         "no-prompt", 1,
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_NO_PROMPT_DESC.get());
    importCertNoPrompt.addLongIdentifier("noPrompt", true);
    importCertParser.addArgument(importCertNoPrompt);

    final BooleanArgument importCertDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_ARG_DISPLAY_COMMAND_DESC.get());
    importCertDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    importCertDisplayCommand.addLongIdentifier("show-keytool-command", true);
    importCertDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    importCertParser.addArgument(importCertDisplayCommand);

    importCertParser.addRequiredArgumentSet(importCertKeystorePassword,
         importCertKeystorePasswordFile, importCertPromptForKeystorePassword);
    importCertParser.addExclusiveArgumentSet(importCertKeystorePassword,
         importCertKeystorePasswordFile, importCertPromptForKeystorePassword);
    importCertParser.addExclusiveArgumentSet(importCertPKPassword,
         importCertPKPasswordFile, importCertPromptForPKPassword);

    final LinkedHashMap<String[],String> importCertExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));
    importCertExamples.put(
         new String[]
         {
           "import-certificate",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--certificate-file", "server-cert.crt"
         },
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_EXAMPLE_1.get("server-cert.crt"));
    importCertExamples.put(
         new String[]
         {
           "import-certificate",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--certificate-file", "server-cert.crt",
           "--certificate-file", "server-cert-issuer.crt",
           "--private-key-file", "server-cert.key",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_EXAMPLE_2.get());

    final SubCommand importCertSubCommand = new SubCommand("import-certificate",
         INFO_MANAGE_CERTS_SC_IMPORT_CERT_DESC.get(), importCertParser,
         importCertExamples);
    importCertSubCommand.addName("importCertificate", true);
    importCertSubCommand.addName("import-certificates", true);
    importCertSubCommand.addName("importCertificates", true);
    importCertSubCommand.addName("import-cert", true);
    importCertSubCommand.addName("importCert", true);
    importCertSubCommand.addName("import-certs", true);
    importCertSubCommand.addName("importCerts", true);
    importCertSubCommand.addName("import-certificate-chain", true);
    importCertSubCommand.addName("importCertificateChain", true);
    importCertSubCommand.addName("import-chain", true);
    importCertSubCommand.addName("importChain", true);
    importCertSubCommand.addName("import", false);

    parser.addSubCommand(importCertSubCommand);


    // Define the "delete-certificate" subcommand and all of its arguments.
    final ArgumentParser deleteCertParser = new ArgumentParser(
         "delete-certificate", INFO_MANAGE_CERTS_SC_DELETE_CERT_DESC.get());

    final FileArgument deleteCertKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_DELETE_CERT_ARG_KS_DESC.get(),
         true, true,  true, false);
    deleteCertKeystore.addLongIdentifier("keystore-path", true);
    deleteCertKeystore.addLongIdentifier("keystorePath", true);
    deleteCertKeystore.addLongIdentifier("keystore-file", true);
    deleteCertKeystore.addLongIdentifier("keystoreFile", true);
    deleteCertParser.addArgument(deleteCertKeystore);

    final StringArgument deleteCertKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_DELETE_CERT_ARG_KS_PW_DESC.get());
    deleteCertKeystorePassword.addLongIdentifier("keystorePassword", true);
    deleteCertKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    deleteCertKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    deleteCertKeystorePassword.addLongIdentifier("keystore-pin", true);
    deleteCertKeystorePassword.addLongIdentifier("keystorePIN", true);
    deleteCertKeystorePassword.addLongIdentifier("storepass", true);
    deleteCertKeystorePassword.setSensitive(true);
    deleteCertParser.addArgument(deleteCertKeystorePassword);

    final FileArgument deleteCertKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_DELETE_CERT_ARG_KS_PW_FILE_DESC.get(), true, true,
         true, false);
    deleteCertKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    deleteCertKeystorePasswordFile.addLongIdentifier("keystore-passphrase-file",
         true);
    deleteCertKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    deleteCertKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    deleteCertKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    deleteCertParser.addArgument(deleteCertKeystorePasswordFile);

    final BooleanArgument deleteCertPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_DELETE_CERT_ARG_PROMPT_FOR_KS_PW_DESC.get());
    deleteCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    deleteCertPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    deleteCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    deleteCertPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    deleteCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    deleteCertParser.addArgument(deleteCertPromptForKeystorePassword);

    final StringArgument deleteCertKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_DELETE_CERT_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    deleteCertKeystoreType.addLongIdentifier("keystoreType", true);
    deleteCertKeystoreType.addLongIdentifier("storetype", true);
    deleteCertParser.addArgument(deleteCertKeystoreType);

    final StringArgument deleteCertAlias = new StringArgument(null, "alias",
         true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_DELETE_CERT_ARG_ALIAS_DESC.get());
    deleteCertAlias.addLongIdentifier("nickname", true);
    deleteCertParser.addArgument(deleteCertAlias);

    final BooleanArgument deleteCertNoPrompt = new BooleanArgument(null,
         "no-prompt", 1,
         INFO_MANAGE_CERTS_SC_DELETE_CERT_ARG_NO_PROMPT_DESC.get());
    deleteCertNoPrompt.addLongIdentifier("noPrompt", true);
    deleteCertParser.addArgument(deleteCertNoPrompt);

    final BooleanArgument deleteCertDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_DELETE_CERT_ARG_DISPLAY_COMMAND_DESC.get());
    deleteCertDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    deleteCertDisplayCommand.addLongIdentifier("show-keytool-command", true);
    deleteCertDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    deleteCertParser.addArgument(deleteCertDisplayCommand);

    deleteCertParser.addExclusiveArgumentSet(deleteCertKeystorePassword,
         deleteCertKeystorePasswordFile, deleteCertPromptForKeystorePassword);
    deleteCertParser.addRequiredArgumentSet(deleteCertKeystorePassword,
         deleteCertKeystorePasswordFile, deleteCertPromptForKeystorePassword);

    final LinkedHashMap<String[],String> deleteCertExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    deleteCertExamples.put(
         new String[]
         {
           "delete-certificate",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--alias", "server-cert"
         },
         INFO_MANAGE_CERTS_SC_DELETE_CERT_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "keystore")));

    final SubCommand deleteCertSubCommand = new SubCommand("delete-certificate",
         INFO_MANAGE_CERTS_SC_DELETE_CERT_DESC.get(), deleteCertParser,
         deleteCertExamples);
    deleteCertSubCommand.addName("deleteCertificate", true);
    deleteCertSubCommand.addName("remove-certificate", true);
    deleteCertSubCommand.addName("removeCertificate", true);
    deleteCertSubCommand.addName("delete", true);
    deleteCertSubCommand.addName("remove", true);

    parser.addSubCommand(deleteCertSubCommand);


    // Define the "generate-self-signed-certificate" subcommand and all of its
    // arguments.
    final ArgumentParser genCertParser = new ArgumentParser(
         "generate-self-signed-certificate",
         INFO_MANAGE_CERTS_SC_GEN_CERT_DESC.get());

    final FileArgument genCertKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_KS_DESC.get(), false,
         true,  true, false);
    genCertKeystore.addLongIdentifier("keystore-path", true);
    genCertKeystore.addLongIdentifier("keystorePath", true);
    genCertKeystore.addLongIdentifier("keystore-file", true);
    genCertKeystore.addLongIdentifier("keystoreFile", true);
    genCertParser.addArgument(genCertKeystore);

    final StringArgument genCertKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_KS_PW_DESC.get());
    genCertKeystorePassword.addLongIdentifier("keystorePassword", true);
    genCertKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    genCertKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    genCertKeystorePassword.addLongIdentifier("keystore-pin", true);
    genCertKeystorePassword.addLongIdentifier("keystorePIN", true);
    genCertKeystorePassword.addLongIdentifier("storepass", true);
    genCertKeystorePassword.setSensitive(true);
    genCertParser.addArgument(genCertKeystorePassword);

    final FileArgument genCertKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_KS_PW_FILE_DESC.get(), true, true,
         true, false);
    genCertKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    genCertKeystorePasswordFile.addLongIdentifier("keystore-passphrase-file",
         true);
    genCertKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    genCertKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    genCertKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    genCertParser.addArgument(genCertKeystorePasswordFile);

    final BooleanArgument genCertPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_PROMPT_FOR_KS_PW_DESC.get());
    genCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    genCertPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    genCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    genCertPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    genCertPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    genCertParser.addArgument(genCertPromptForKeystorePassword);

    final StringArgument genCertPKPassword = new StringArgument(null,
         "private-key-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_PK_PW_DESC.get());
    genCertPKPassword.addLongIdentifier("privateKeyPassword", true);
    genCertPKPassword.addLongIdentifier("private-key-passphrase", true);
    genCertPKPassword.addLongIdentifier("privateKeyPassphrase", true);
    genCertPKPassword.addLongIdentifier("private-key-pin", true);
    genCertPKPassword.addLongIdentifier("privateKeyPIN", true);
    genCertPKPassword.addLongIdentifier("key-password", true);
    genCertPKPassword.addLongIdentifier("keyPassword", true);
    genCertPKPassword.addLongIdentifier("key-passphrase", true);
    genCertPKPassword.addLongIdentifier("keyPassphrase", true);
    genCertPKPassword.addLongIdentifier("key-pin", true);
    genCertPKPassword.addLongIdentifier("keyPIN", true);
    genCertPKPassword.addLongIdentifier("keypass", true);
    genCertPKPassword.setSensitive(true);
    genCertParser.addArgument(genCertPKPassword);

    final FileArgument genCertPKPasswordFile = new FileArgument(null,
         "private-key-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_PK_PW_FILE_DESC.get(), true, true,
         true, false);
    genCertPKPasswordFile.addLongIdentifier("privateKeyPasswordFile", true);
    genCertPKPasswordFile.addLongIdentifier("private-key-passphrase-file",
         true);
    genCertPKPasswordFile.addLongIdentifier("privateKeyPassphraseFile",
         true);
    genCertPKPasswordFile.addLongIdentifier("private-key-pin-file",
         true);
    genCertPKPasswordFile.addLongIdentifier("privateKeyPINFile", true);
    genCertPKPasswordFile.addLongIdentifier("key-password-file", true);
    genCertPKPasswordFile.addLongIdentifier("keyPasswordFile", true);
    genCertPKPasswordFile.addLongIdentifier("key-passphrase-file",
         true);
    genCertPKPasswordFile.addLongIdentifier("keyPassphraseFile",
         true);
    genCertPKPasswordFile.addLongIdentifier("key-pin-file",
         true);
    genCertPKPasswordFile.addLongIdentifier("keyPINFile", true);
    genCertParser.addArgument(genCertPKPasswordFile);

    final BooleanArgument genCertPromptForPKPassword =
         new BooleanArgument(null, "prompt-for-private-key-password",
        INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_PROMPT_FOR_PK_PW_DESC.get());
    genCertPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassword", true);
    genCertPromptForPKPassword.addLongIdentifier(
         "prompt-for-private-key-passphrase", true);
    genCertPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassphrase", true);
    genCertPromptForPKPassword.addLongIdentifier("prompt-for-private-key-pin",
         true);
    genCertPromptForPKPassword.addLongIdentifier("promptForPrivateKeyPIN",
         true);
    genCertPromptForPKPassword.addLongIdentifier("prompt-for-key-password",
         true);
    genCertPromptForPKPassword.addLongIdentifier("promptForKeyPassword",
         true);
    genCertPromptForPKPassword.addLongIdentifier(
         "prompt-for-key-passphrase", true);
    genCertPromptForPKPassword.addLongIdentifier(
         "promptForKeyPassphrase", true);
    genCertPromptForPKPassword.addLongIdentifier("prompt-for-key-pin", true);
    genCertPromptForPKPassword.addLongIdentifier("promptForKeyPIN", true);
    genCertParser.addArgument(genCertPromptForPKPassword);

    final StringArgument genCertKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    genCertKeystoreType.addLongIdentifier("keystoreType", true);
    genCertKeystoreType.addLongIdentifier("storetype", true);
    genCertParser.addArgument(genCertKeystoreType);

    final StringArgument genCertAlias = new StringArgument(null, "alias",
         true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_ALIAS_DESC.get());
    genCertAlias.addLongIdentifier("nickname", true);
    genCertParser.addArgument(genCertAlias);

    final BooleanArgument genCertReplace = new BooleanArgument(null,
         "replace-existing-certificate", 1,
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_REPLACE_DESC.get());
    genCertReplace.addLongIdentifier("replaceExistingCertificate", true);
    genCertReplace.addLongIdentifier("replace-certificate", true);
    genCertReplace.addLongIdentifier("replaceCertificate", true);
    genCertReplace.addLongIdentifier("replace-existing", true);
    genCertReplace.addLongIdentifier("replaceExisting", true);
    genCertReplace.addLongIdentifier("replace", true);
    genCertReplace.addLongIdentifier("use-existing-key-pair", true);
    genCertReplace.addLongIdentifier("use-existing-keypair", true);
    genCertReplace.addLongIdentifier("useExistingKeypair", true);
    genCertParser.addArgument(genCertReplace);

    final DNArgument genCertSubjectDN = new DNArgument(null, "subject-dn",
         false, 1, null,
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_SUBJECT_DN_DESC.get());
    genCertSubjectDN.addLongIdentifier("subjectDN", true);
    genCertSubjectDN.addLongIdentifier("subject", true);
    genCertSubjectDN.addLongIdentifier("dname", true);
    genCertParser.addArgument(genCertSubjectDN);

    final IntegerArgument genCertDaysValid = new IntegerArgument(null,
         "days-valid", false, 1, null,
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_DAYS_VALID_DESC.get(), 1,
         Integer.MAX_VALUE);
    genCertDaysValid.addLongIdentifier("daysValid", true);
    genCertDaysValid.addLongIdentifier("validity", true);
    genCertParser.addArgument(genCertDaysValid);

    final TimestampArgument genCertNotBefore = new TimestampArgument(null,
         "validity-start-time", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_TIMESTAMP.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_VALIDITY_START_TIME_DESC.get(
              "20180102123456"));
    genCertNotBefore.addLongIdentifier("validityStartTime", true);
    genCertNotBefore.addLongIdentifier("not-before", true);
    genCertNotBefore.addLongIdentifier("notBefore", true);
    genCertParser.addArgument(genCertNotBefore);

    final StringArgument genCertKeyAlgorithm = new StringArgument(null,
         "key-algorithm", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_KEY_ALGORITHM_DESC.get());
    genCertKeyAlgorithm.addLongIdentifier("keyAlgorithm", true);
    genCertKeyAlgorithm.addLongIdentifier("key-alg", true);
    genCertKeyAlgorithm.addLongIdentifier("keyAlg", true);
    genCertParser.addArgument(genCertKeyAlgorithm);

    final IntegerArgument genCertKeySizeBits = new IntegerArgument(null,
         "key-size-bits", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_BITS.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_KEY_SIZE_BITS_DESC.get(), 1,
         Integer.MAX_VALUE);
    genCertKeySizeBits.addLongIdentifier("keySizeBits", true);
    genCertKeySizeBits.addLongIdentifier("key-length-bits", true);
    genCertKeySizeBits.addLongIdentifier("keyLengthBits", true);
    genCertKeySizeBits.addLongIdentifier("key-size", true);
    genCertKeySizeBits.addLongIdentifier("keySize", true);
    genCertKeySizeBits.addLongIdentifier("key-length", true);
    genCertKeySizeBits.addLongIdentifier("keyLength", true);
    genCertParser.addArgument(genCertKeySizeBits);

    final StringArgument genCertSignatureAlgorithm = new StringArgument(null,
         "signature-algorithm", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_SIG_ALG_DESC.get());
    genCertSignatureAlgorithm.addLongIdentifier("signatureAlgorithm", true);
    genCertSignatureAlgorithm.addLongIdentifier("signature-alg", true);
    genCertSignatureAlgorithm.addLongIdentifier("signatureAlg", true);
    genCertSignatureAlgorithm.addLongIdentifier("sig-alg", true);
    genCertSignatureAlgorithm.addLongIdentifier("sigAlg", true);
    genCertParser.addArgument(genCertSignatureAlgorithm);

    final BooleanArgument genCertInheritExtensions = new BooleanArgument(null,
         "inherit-extensions", 1,
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_INHERIT_EXT_DESC.get());
    genCertInheritExtensions.addLongIdentifier("inheritExtensions", true);
    genCertParser.addArgument(genCertInheritExtensions);

    final StringArgument genCertSubjectAltDNS = new StringArgument(null,
         "subject-alternative-name-dns", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_SAN_DNS_DESC.get());
    genCertSubjectAltDNS.addLongIdentifier("subjectAlternativeNameDNS", true);
    genCertSubjectAltDNS.addLongIdentifier("subject-alt-name-dns", true);
    genCertSubjectAltDNS.addLongIdentifier("subjectAltNameDNS", true);
    genCertSubjectAltDNS.addLongIdentifier("subject-alternative-dns", true);
    genCertSubjectAltDNS.addLongIdentifier("subjectAlternativeDNS", true);
    genCertSubjectAltDNS.addLongIdentifier("subject-alt-dns", true);
    genCertSubjectAltDNS.addLongIdentifier("subjectAltDNS", true);
    genCertSubjectAltDNS.addLongIdentifier("san-dns", true);
    genCertSubjectAltDNS.addLongIdentifier("sanDNS", true);
    genCertSubjectAltDNS.addValueValidator(
         new IA5StringArgumentValueValidator(false));
    genCertParser.addArgument(genCertSubjectAltDNS);

    final StringArgument genCertSubjectAltIP = new StringArgument(null,
         "subject-alternative-name-ip-address", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_SAN_IP_DESC.get());
    genCertSubjectAltIP.addLongIdentifier("subjectAlternativeNameIPAddress",
         true);
    genCertSubjectAltIP.addLongIdentifier("subject-alternative-name-ip", true);
    genCertSubjectAltIP.addLongIdentifier("subjectAlternativeNameIP", true);
    genCertSubjectAltIP.addLongIdentifier("subject-alt-name-ip-address", true);
    genCertSubjectAltIP.addLongIdentifier("subjectAltNameIPAddress", true);
    genCertSubjectAltIP.addLongIdentifier("subject-alt-name-ip", true);
    genCertSubjectAltIP.addLongIdentifier("subjectAltNameIP", true);
    genCertSubjectAltIP.addLongIdentifier("subject-alternative-ip-address",
         true);
    genCertSubjectAltIP.addLongIdentifier("subjectAlternativeIPAddress", true);
    genCertSubjectAltIP.addLongIdentifier("subject-alternative-ip", true);
    genCertSubjectAltIP.addLongIdentifier("subjectAlternativeIP", true);
    genCertSubjectAltIP.addLongIdentifier("subject-alt-ip-address", true);
    genCertSubjectAltIP.addLongIdentifier("subjectAltIPAddress", true);
    genCertSubjectAltIP.addLongIdentifier("subject-alt-ip", true);
    genCertSubjectAltIP.addLongIdentifier("subjectAltIP", true);
    genCertSubjectAltIP.addLongIdentifier("san-ip-address", true);
    genCertSubjectAltIP.addLongIdentifier("sanIPAddress", true);
    genCertSubjectAltIP.addLongIdentifier("san-ip", true);
    genCertSubjectAltIP.addLongIdentifier("sanIP", true);
    genCertSubjectAltIP.addValueValidator(
         new IPAddressArgumentValueValidator(true, true));
    genCertParser.addArgument(genCertSubjectAltIP);

    final StringArgument genCertSubjectAltEmail = new StringArgument(null,
         "subject-alternative-name-email-address", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_SAN_EMAIL_DESC.get());
    genCertSubjectAltEmail.addLongIdentifier(
         "subjectAlternativeNameEmailAddress", true);
    genCertSubjectAltEmail.addLongIdentifier("subject-alternative-name-email",
         true);
    genCertSubjectAltEmail.addLongIdentifier("subjectAlternativeNameEmail",
         true);
    genCertSubjectAltEmail.addLongIdentifier("subject-alt-name-email-address",
         true);
    genCertSubjectAltEmail.addLongIdentifier("subjectAltNameEmailAddress",
         true);
    genCertSubjectAltEmail.addLongIdentifier("subject-alt-name-email", true);
    genCertSubjectAltEmail.addLongIdentifier("subjectAltNameEmail", true);
    genCertSubjectAltEmail.addLongIdentifier(
         "subject-alternative-email-address", true);
    genCertSubjectAltEmail.addLongIdentifier("subjectAlternativeEmailAddress",
         true);
    genCertSubjectAltEmail.addLongIdentifier("subject-alternative-email", true);
    genCertSubjectAltEmail.addLongIdentifier("subjectAlternativeEmail", true);
    genCertSubjectAltEmail.addLongIdentifier("subject-alt-email-address", true);
    genCertSubjectAltEmail.addLongIdentifier("subjectAltEmailAddress", true);
    genCertSubjectAltEmail.addLongIdentifier("subject-alt-email", true);
    genCertSubjectAltEmail.addLongIdentifier("subjectAltEmail", true);
    genCertSubjectAltEmail.addLongIdentifier("san-email-address", true);
    genCertSubjectAltEmail.addLongIdentifier("sanEmailAddress", true);
    genCertSubjectAltEmail.addLongIdentifier("san-email", true);
    genCertSubjectAltEmail.addLongIdentifier("sanEmail", true);
    genCertSubjectAltEmail.addValueValidator(
         new IA5StringArgumentValueValidator(false));
    genCertParser.addArgument(genCertSubjectAltEmail);

    final StringArgument genCertSubjectAltURI = new StringArgument(null,
         "subject-alternative-name-uri", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_URI.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_SAN_URI_DESC.get());
    genCertSubjectAltURI.addLongIdentifier("subjectAlternativeNameURI", true);
    genCertSubjectAltURI.addLongIdentifier("subject-alt-name-uri", true);
    genCertSubjectAltURI.addLongIdentifier("subjectAltNameURI", true);
    genCertSubjectAltURI.addLongIdentifier("subject-alternative-uri", true);
    genCertSubjectAltURI.addLongIdentifier("subjectAlternativeURI", true);
    genCertSubjectAltURI.addLongIdentifier("subject-alt-uri", true);
    genCertSubjectAltURI.addLongIdentifier("subjectAltURI", true);
    genCertSubjectAltURI.addLongIdentifier("san-uri", true);
    genCertSubjectAltURI.addLongIdentifier("sanURI", true);
    genCertParser.addArgument(genCertSubjectAltURI);

    final StringArgument genCertSubjectAltOID = new StringArgument(null,
         "subject-alternative-name-oid", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_OID.get(),
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_SAN_OID_DESC.get());
    genCertSubjectAltOID.addLongIdentifier("subjectAlternativeNameOID", true);
    genCertSubjectAltOID.addLongIdentifier("subject-alt-name-oid", true);
    genCertSubjectAltOID.addLongIdentifier("subjectAltNameOID", true);
    genCertSubjectAltOID.addLongIdentifier("subject-alternative-oid", true);
    genCertSubjectAltOID.addLongIdentifier("subjectAlternativeOID", true);
    genCertSubjectAltOID.addLongIdentifier("subject-alt-oid", true);
    genCertSubjectAltOID.addLongIdentifier("subjectAltOID", true);
    genCertSubjectAltOID.addLongIdentifier("san-oid", true);
    genCertSubjectAltOID.addLongIdentifier("sanOID", true);
    genCertSubjectAltOID.addValueValidator(new OIDArgumentValueValidator(true));
    genCertParser.addArgument(genCertSubjectAltOID);

    final BooleanValueArgument genCertBasicConstraintsIsCA =
         new BooleanValueArgument(null, "basic-constraints-is-ca", false, null,
              INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_BC_IS_CA_DESC.get());
    genCertBasicConstraintsIsCA.addLongIdentifier("basicConstraintsIsCA", true);
    genCertBasicConstraintsIsCA.addLongIdentifier("bc-is-ca", true);
    genCertBasicConstraintsIsCA.addLongIdentifier("bcIsCA", true);
    genCertParser.addArgument(genCertBasicConstraintsIsCA);

    final IntegerArgument genCertBasicConstraintsPathLength =
         new IntegerArgument(null, "basic-constraints-maximum-path-length",
              false, 1, null,
              INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_BC_PATH_LENGTH_DESC.get(), 0,
              Integer.MAX_VALUE);
    genCertBasicConstraintsPathLength.addLongIdentifier(
         "basicConstraintsMaximumPathLength", true);
    genCertBasicConstraintsPathLength.addLongIdentifier(
         "basic-constraints-max-path-length", true);
    genCertBasicConstraintsPathLength.addLongIdentifier(
         "basicConstraintsMaxPathLength", true);
    genCertBasicConstraintsPathLength.addLongIdentifier(
         "basic-constraints-path-length", true);
    genCertBasicConstraintsPathLength.addLongIdentifier(
         "basicConstraintsPathLength", true);
    genCertBasicConstraintsPathLength.addLongIdentifier(
         "bc-maximum-path-length", true);
    genCertBasicConstraintsPathLength.addLongIdentifier("bcMaximumPathLength",
         true);
    genCertBasicConstraintsPathLength.addLongIdentifier("bc-max-path-length",
         true);
    genCertBasicConstraintsPathLength.addLongIdentifier("bcMaxPathLength",
         true);
    genCertBasicConstraintsPathLength.addLongIdentifier("bc-path-length", true);
    genCertBasicConstraintsPathLength.addLongIdentifier("bcPathLength", true);
    genCertParser.addArgument(genCertBasicConstraintsPathLength);

    final StringArgument genCertKeyUsage = new StringArgument(null, "key-usage",
         false, 0, null, INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_KU_DESC.get());
    genCertKeyUsage.addLongIdentifier("keyUsage", true);
    genCertParser.addArgument(genCertKeyUsage);

    final StringArgument genCertExtendedKeyUsage = new StringArgument(null,
         "extended-key-usage", false, 0, null,
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_EKU_DESC.get());
    genCertExtendedKeyUsage.addLongIdentifier("extendedKeyUsage", true);
    genCertParser.addArgument(genCertExtendedKeyUsage);

    final StringArgument genCertExtension = new StringArgument(null,
         "extension", false, 0, null,
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_EXT_DESC.get());
    genCertExtension.addLongIdentifier("ext", true);
    genCertParser.addArgument(genCertExtension);

    final BooleanArgument genCertDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_DISPLAY_COMMAND_DESC.get());
    genCertDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    genCertDisplayCommand.addLongIdentifier("show-keytool-command", true);
    genCertDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    genCertParser.addArgument(genCertDisplayCommand);

    genCertParser.addRequiredArgumentSet(genCertKeystorePassword,
         genCertKeystorePasswordFile, genCertPromptForKeystorePassword);
    genCertParser.addExclusiveArgumentSet(genCertKeystorePassword,
         genCertKeystorePasswordFile, genCertPromptForKeystorePassword);
    genCertParser.addExclusiveArgumentSet(genCertPKPassword,
         genCertPKPasswordFile, genCertPromptForPKPassword);
    genCertParser.addExclusiveArgumentSet(genCertReplace, genCertKeyAlgorithm);
    genCertParser.addExclusiveArgumentSet(genCertReplace, genCertKeySizeBits);
    genCertParser.addExclusiveArgumentSet(genCertReplace,
         genCertSignatureAlgorithm);
    genCertParser.addDependentArgumentSet(genCertBasicConstraintsPathLength,
         genCertBasicConstraintsIsCA);

    final LinkedHashMap<String[],String> genCertExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(4));
    genCertExamples.put(
         new String[]
         {
           "generate-self-signed-certificate",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--subject-dn", "CN=ldap.example.com,O=Example Corp,C=US"
         },
         INFO_MANAGE_CERTS_SC_GEN_CERT_EXAMPLE_1.get());
    genCertExamples.put(
         new String[]
         {
           "generate-self-signed-certificate",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--replace-existing-certificate",
           "--inherit-extensions"
         },
         INFO_MANAGE_CERTS_SC_GEN_CERT_EXAMPLE_2.get());
    genCertExamples.put(
         new String[]
         {
           "generate-self-signed-certificate",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--subject-dn", "CN=ldap.example.com,O=Example Corp,C=US",
           "--days-valid", "3650",
           "--validity-start-time", "20170101000000",
           "--key-algorithm", "RSA",
           "--key-size-bits", "4096",
           "--signature-algorithm", "SHA256withRSA",
           "--subject-alternative-name-dns", "ldap1.example.com",
           "--subject-alternative-name-dns", "ldap2.example.com",
           "--subject-alternative-name-ip-address", "1.2.3.4",
           "--subject-alternative-name-ip-address", "1.2.3.5",
           "--extended-key-usage", "server-auth",
           "--extended-key-usage", "client-auth",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_GEN_CERT_EXAMPLE_3.get());
    genCertExamples.put(
         new String[]
         {
           "generate-self-signed-certificate",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "ca-cert",
           "--subject-dn",
                "CN=Example Certification Authority,O=Example Corp,C=US",
           "--days-valid", "7300",
           "--validity-start-time", "20170101000000",
           "--key-algorithm", "EC",
           "--key-size-bits", "256",
           "--signature-algorithm", "SHA256withECDSA",
           "--basic-constraints-is-ca", "true",
           "--key-usage", "key-cert-sign",
           "--key-usage", "crl-sign",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_GEN_CERT_EXAMPLE_4.get());

    final SubCommand genCertSubCommand = new SubCommand(
         "generate-self-signed-certificate",
         INFO_MANAGE_CERTS_SC_GEN_CERT_DESC.get(), genCertParser,
         genCertExamples);
    genCertSubCommand.addName("generateSelfSignedCertificate", true);
    genCertSubCommand.addName("generate-certificate", true);
    genCertSubCommand.addName("generateCertificate", true);
    genCertSubCommand.addName("self-signed-certificate", true);
    genCertSubCommand.addName("selfSignedCertificate", true);
    genCertSubCommand.addName("selfcert", true);

    parser.addSubCommand(genCertSubCommand);


    // Define the "generate-certificate-signing-request" subcommand and all of
    // its arguments.
    final ArgumentParser genCSRParser = new ArgumentParser(
         "generate-certificate-signing-request",
         INFO_MANAGE_CERTS_SC_GEN_CSR_DESC.get());

    final Set<String> genCSROutputFormatAllowedValues = StaticUtils.setOf(
         "PEM", "text", "txt", "RFC", "DER", "binary", "bin");
    final StringArgument genCSROutputFormat = new StringArgument(null,
         "output-format", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_FORMAT.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_FORMAT_DESC.get(),
         genCSROutputFormatAllowedValues, "PEM");
    genCSROutputFormat.addLongIdentifier("outputFormat", true);
    genCSRParser.addArgument(genCSROutputFormat);

    final FileArgument genCSROutputFile = new FileArgument(null, "output-file",
         false, 1, null,
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_OUTPUT_FILE_DESC.get(), false, true,
         true, false);
    genCSROutputFile.addLongIdentifier("outputFile", true);
    genCSROutputFile.addLongIdentifier("filename", true);
    genCSROutputFile.addLongIdentifier("file", true);
    genCSRParser.addArgument(genCSROutputFile);

    final FileArgument genCSRKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_KS_DESC.get(), false,
         true,  true, false);
    genCSRKeystore.addLongIdentifier("keystore-path", true);
    genCSRKeystore.addLongIdentifier("keystorePath", true);
    genCSRKeystore.addLongIdentifier("keystore-file", true);
    genCSRKeystore.addLongIdentifier("keystoreFile", true);
    genCSRParser.addArgument(genCSRKeystore);

    final StringArgument genCSRKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_KS_PW_DESC.get());
    genCSRKeystorePassword.addLongIdentifier("keystorePassword", true);
    genCSRKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    genCSRKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    genCSRKeystorePassword.addLongIdentifier("keystore-pin", true);
    genCSRKeystorePassword.addLongIdentifier("keystorePIN", true);
    genCSRKeystorePassword.addLongIdentifier("storepass", true);
    genCSRKeystorePassword.setSensitive(true);
    genCSRParser.addArgument(genCSRKeystorePassword);

    final FileArgument genCSRKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_KS_PW_FILE_DESC.get(), true, true,
         true, false);
    genCSRKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    genCSRKeystorePasswordFile.addLongIdentifier("keystore-passphrase-file",
         true);
    genCSRKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    genCSRKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    genCSRKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    genCSRParser.addArgument(genCSRKeystorePasswordFile);

    final BooleanArgument genCSRPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_PROMPT_FOR_KS_PW_DESC.get());
    genCSRPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    genCSRPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    genCSRPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    genCSRPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    genCSRPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    genCSRParser.addArgument(genCSRPromptForKeystorePassword);

    final StringArgument genCSRPKPassword = new StringArgument(null,
         "private-key-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_PK_PW_DESC.get());
    genCSRPKPassword.addLongIdentifier("privateKeyPassword", true);
    genCSRPKPassword.addLongIdentifier("private-key-passphrase", true);
    genCSRPKPassword.addLongIdentifier("privateKeyPassphrase", true);
    genCSRPKPassword.addLongIdentifier("private-key-pin", true);
    genCSRPKPassword.addLongIdentifier("privateKeyPIN", true);
    genCSRPKPassword.addLongIdentifier("key-password", true);
    genCSRPKPassword.addLongIdentifier("keyPassword", true);
    genCSRPKPassword.addLongIdentifier("key-passphrase", true);
    genCSRPKPassword.addLongIdentifier("keyPassphrase", true);
    genCSRPKPassword.addLongIdentifier("key-pin", true);
    genCSRPKPassword.addLongIdentifier("keyPIN", true);
    genCSRPKPassword.addLongIdentifier("keypass", true);
    genCSRPKPassword.setSensitive(true);
    genCSRParser.addArgument(genCSRPKPassword);

    final FileArgument genCSRPKPasswordFile = new FileArgument(null,
         "private-key-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_PK_PW_FILE_DESC.get(), true, true,
         true, false);
    genCSRPKPasswordFile.addLongIdentifier("privateKeyPasswordFile", true);
    genCSRPKPasswordFile.addLongIdentifier("private-key-passphrase-file",
         true);
    genCSRPKPasswordFile.addLongIdentifier("privateKeyPassphraseFile",
         true);
    genCSRPKPasswordFile.addLongIdentifier("private-key-pin-file",
         true);
    genCSRPKPasswordFile.addLongIdentifier("privateKeyPINFile", true);
    genCSRPKPasswordFile.addLongIdentifier("key-password-file", true);
    genCSRPKPasswordFile.addLongIdentifier("keyPasswordFile", true);
    genCSRPKPasswordFile.addLongIdentifier("key-passphrase-file",
         true);
    genCSRPKPasswordFile.addLongIdentifier("keyPassphraseFile",
         true);
    genCSRPKPasswordFile.addLongIdentifier("key-pin-file",
         true);
    genCSRPKPasswordFile.addLongIdentifier("keyPINFile", true);
    genCSRParser.addArgument(genCSRPKPasswordFile);

    final BooleanArgument genCSRPromptForPKPassword =
         new BooleanArgument(null, "prompt-for-private-key-password",
        INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_PROMPT_FOR_PK_PW_DESC.get());
    genCSRPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassword", true);
    genCSRPromptForPKPassword.addLongIdentifier(
         "prompt-for-private-key-passphrase", true);
    genCSRPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassphrase", true);
    genCSRPromptForPKPassword.addLongIdentifier("prompt-for-private-key-pin",
         true);
    genCSRPromptForPKPassword.addLongIdentifier("promptForPrivateKeyPIN",
         true);
    genCSRPromptForPKPassword.addLongIdentifier("prompt-for-key-password",
         true);
    genCSRPromptForPKPassword.addLongIdentifier("promptForKeyPassword",
         true);
    genCSRPromptForPKPassword.addLongIdentifier(
         "prompt-for-key-passphrase", true);
    genCSRPromptForPKPassword.addLongIdentifier(
         "promptForKeyPassphrase", true);
    genCSRPromptForPKPassword.addLongIdentifier("prompt-for-key-pin", true);
    genCSRPromptForPKPassword.addLongIdentifier("promptForKeyPIN", true);
    genCSRParser.addArgument(genCSRPromptForPKPassword);

    final StringArgument genCSRKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    genCSRKeystoreType.addLongIdentifier("keystoreType", true);
    genCSRKeystoreType.addLongIdentifier("storetype", true);
    genCSRParser.addArgument(genCSRKeystoreType);

    final StringArgument genCSRAlias = new StringArgument(null, "alias",
         true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_ALIAS_DESC.get());
    genCSRAlias.addLongIdentifier("nickname", true);
    genCSRParser.addArgument(genCSRAlias);

    final BooleanArgument genCSRReplace = new BooleanArgument(null,
         "use-existing-key-pair", 1,
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_REPLACE_DESC.get());
    genCSRReplace.addLongIdentifier("use-existing-keypair", true);
    genCSRReplace.addLongIdentifier("useExistingKeyPair", true);
    genCSRReplace.addLongIdentifier("replace-existing-certificate", true);
    genCSRReplace.addLongIdentifier("replaceExistingCertificate", true);
    genCSRReplace.addLongIdentifier("replace-certificate", true);
    genCSRReplace.addLongIdentifier("replaceCertificate", true);
    genCSRReplace.addLongIdentifier("replace-existing", true);
    genCSRReplace.addLongIdentifier("replaceExisting", true);
    genCSRReplace.addLongIdentifier("replace", true);
    genCSRParser.addArgument(genCSRReplace);

    final DNArgument genCSRSubjectDN = new DNArgument(null, "subject-dn",
         false, 1, null,
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_SUBJECT_DN_DESC.get());
    genCSRSubjectDN.addLongIdentifier("subjectDN", true);
    genCSRSubjectDN.addLongIdentifier("subject", true);
    genCSRSubjectDN.addLongIdentifier("dname", true);
    genCSRParser.addArgument(genCSRSubjectDN);

    final StringArgument genCSRKeyAlgorithm = new StringArgument(null,
         "key-algorithm", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_KEY_ALGORITHM_DESC.get());
    genCSRKeyAlgorithm.addLongIdentifier("keyAlgorithm", true);
    genCSRKeyAlgorithm.addLongIdentifier("key-alg", true);
    genCSRKeyAlgorithm.addLongIdentifier("keyAlg", true);
    genCSRParser.addArgument(genCSRKeyAlgorithm);

    final IntegerArgument genCSRKeySizeBits = new IntegerArgument(null,
         "key-size-bits", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_BITS.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_KEY_SIZE_BITS_DESC.get(), 1,
         Integer.MAX_VALUE);
    genCSRKeySizeBits.addLongIdentifier("keySizeBits", true);
    genCSRKeySizeBits.addLongIdentifier("key-length-bits", true);
    genCSRKeySizeBits.addLongIdentifier("keyLengthBits", true);
    genCSRKeySizeBits.addLongIdentifier("key-size", true);
    genCSRKeySizeBits.addLongIdentifier("keySize", true);
    genCSRKeySizeBits.addLongIdentifier("key-length", true);
    genCSRKeySizeBits.addLongIdentifier("keyLength", true);
    genCSRParser.addArgument(genCSRKeySizeBits);

    final StringArgument genCSRSignatureAlgorithm = new StringArgument(null,
         "signature-algorithm", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_SIG_ALG_DESC.get());
    genCSRSignatureAlgorithm.addLongIdentifier("signatureAlgorithm", true);
    genCSRSignatureAlgorithm.addLongIdentifier("signature-alg", true);
    genCSRSignatureAlgorithm.addLongIdentifier("signatureAlg", true);
    genCSRSignatureAlgorithm.addLongIdentifier("sig-alg", true);
    genCSRSignatureAlgorithm.addLongIdentifier("sigAlg", true);
    genCSRParser.addArgument(genCSRSignatureAlgorithm);

    final BooleanArgument genCSRInheritExtensions = new BooleanArgument(null,
         "inherit-extensions", 1,
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_INHERIT_EXT_DESC.get());
    genCSRInheritExtensions.addLongIdentifier("inheritExtensions", true);
    genCSRParser.addArgument(genCSRInheritExtensions);

    final StringArgument genCSRSubjectAltDNS = new StringArgument(null,
         "subject-alternative-name-dns", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_SAN_DNS_DESC.get());
    genCSRSubjectAltDNS.addLongIdentifier("subjectAlternativeNameDNS", true);
    genCSRSubjectAltDNS.addLongIdentifier("subject-alt-name-dns", true);
    genCSRSubjectAltDNS.addLongIdentifier("subjectAltNameDNS", true);
    genCSRSubjectAltDNS.addLongIdentifier("subject-alternative-dns", true);
    genCSRSubjectAltDNS.addLongIdentifier("subjectAlternativeDNS", true);
    genCSRSubjectAltDNS.addLongIdentifier("subject-alt-dns", true);
    genCSRSubjectAltDNS.addLongIdentifier("subjectAltDNS", true);
    genCSRSubjectAltDNS.addLongIdentifier("san-dns", true);
    genCSRSubjectAltDNS.addLongIdentifier("sanDNS", true);
    genCSRSubjectAltDNS.addValueValidator(
         new IA5StringArgumentValueValidator(false));
    genCSRParser.addArgument(genCSRSubjectAltDNS);

    final StringArgument genCSRSubjectAltIP = new StringArgument(null,
         "subject-alternative-name-ip-address", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_SAN_IP_DESC.get());
    genCSRSubjectAltIP.addLongIdentifier("subjectAlternativeNameIPAddress",
         true);
    genCSRSubjectAltIP.addLongIdentifier("subject-alternative-name-ip", true);
    genCSRSubjectAltIP.addLongIdentifier("subjectAlternativeNameIP", true);
    genCSRSubjectAltIP.addLongIdentifier("subject-alt-name-ip-address", true);
    genCSRSubjectAltIP.addLongIdentifier("subjectAltNameIPAddress", true);
    genCSRSubjectAltIP.addLongIdentifier("subject-alt-name-ip", true);
    genCSRSubjectAltIP.addLongIdentifier("subjectAltNameIP", true);
    genCSRSubjectAltIP.addLongIdentifier("subject-alternative-ip-address",
         true);
    genCSRSubjectAltIP.addLongIdentifier("subjectAlternativeIPAddress", true);
    genCSRSubjectAltIP.addLongIdentifier("subject-alternative-ip", true);
    genCSRSubjectAltIP.addLongIdentifier("subjectAlternativeIP", true);
    genCSRSubjectAltIP.addLongIdentifier("subject-alt-ip-address", true);
    genCSRSubjectAltIP.addLongIdentifier("subjectAltIPAddress", true);
    genCSRSubjectAltIP.addLongIdentifier("subject-alt-ip", true);
    genCSRSubjectAltIP.addLongIdentifier("subjectAltIP", true);
    genCSRSubjectAltIP.addLongIdentifier("san-ip-address", true);
    genCSRSubjectAltIP.addLongIdentifier("sanIPAddress", true);
    genCSRSubjectAltIP.addLongIdentifier("san-ip", true);
    genCSRSubjectAltIP.addLongIdentifier("sanIP", true);
    genCSRSubjectAltIP.addValueValidator(
         new IPAddressArgumentValueValidator(true, true));
    genCSRParser.addArgument(genCSRSubjectAltIP);

    final StringArgument genCSRSubjectAltEmail = new StringArgument(null,
         "subject-alternative-name-email-address", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_SAN_EMAIL_DESC.get());
    genCSRSubjectAltEmail.addLongIdentifier(
         "subjectAlternativeNameEmailAddress", true);
    genCSRSubjectAltEmail.addLongIdentifier("subject-alternative-name-email",
         true);
    genCSRSubjectAltEmail.addLongIdentifier("subjectAlternativeNameEmail",
         true);
    genCSRSubjectAltEmail.addLongIdentifier("subject-alt-name-email-address",
         true);
    genCSRSubjectAltEmail.addLongIdentifier("subjectAltNameEmailAddress",
         true);
    genCSRSubjectAltEmail.addLongIdentifier("subject-alt-name-email", true);
    genCSRSubjectAltEmail.addLongIdentifier("subjectAltNameEmail", true);
    genCSRSubjectAltEmail.addLongIdentifier(
         "subject-alternative-email-address", true);
    genCSRSubjectAltEmail.addLongIdentifier("subjectAlternativeEmailAddress",
         true);
    genCSRSubjectAltEmail.addLongIdentifier("subject-alternative-email", true);
    genCSRSubjectAltEmail.addLongIdentifier("subjectAlternativeEmail", true);
    genCSRSubjectAltEmail.addLongIdentifier("subject-alt-email-address", true);
    genCSRSubjectAltEmail.addLongIdentifier("subjectAltEmailAddress", true);
    genCSRSubjectAltEmail.addLongIdentifier("subject-alt-email", true);
    genCSRSubjectAltEmail.addLongIdentifier("subjectAltEmail", true);
    genCSRSubjectAltEmail.addLongIdentifier("san-email-address", true);
    genCSRSubjectAltEmail.addLongIdentifier("sanEmailAddress", true);
    genCSRSubjectAltEmail.addLongIdentifier("san-email", true);
    genCSRSubjectAltEmail.addLongIdentifier("sanEmail", true);
    genCSRSubjectAltEmail.addValueValidator(
         new IA5StringArgumentValueValidator(false));
    genCSRParser.addArgument(genCSRSubjectAltEmail);

    final StringArgument genCSRSubjectAltURI = new StringArgument(null,
         "subject-alternative-name-uri", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_URI.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_SAN_URI_DESC.get());
    genCSRSubjectAltURI.addLongIdentifier("subjectAlternativeNameURI", true);
    genCSRSubjectAltURI.addLongIdentifier("subject-alt-name-uri", true);
    genCSRSubjectAltURI.addLongIdentifier("subjectAltNameURI", true);
    genCSRSubjectAltURI.addLongIdentifier("subject-alternative-uri", true);
    genCSRSubjectAltURI.addLongIdentifier("subjectAlternativeURI", true);
    genCSRSubjectAltURI.addLongIdentifier("subject-alt-uri", true);
    genCSRSubjectAltURI.addLongIdentifier("subjectAltURI", true);
    genCSRSubjectAltURI.addLongIdentifier("san-uri", true);
    genCSRSubjectAltURI.addLongIdentifier("sanURI", true);
    genCSRParser.addArgument(genCSRSubjectAltURI);

    final StringArgument genCSRSubjectAltOID = new StringArgument(null,
         "subject-alternative-name-oid", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_OID.get(),
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_SAN_OID_DESC.get());
    genCSRSubjectAltOID.addLongIdentifier("subjectAlternativeNameOID", true);
    genCSRSubjectAltOID.addLongIdentifier("subject-alt-name-oid", true);
    genCSRSubjectAltOID.addLongIdentifier("subjectAltNameOID", true);
    genCSRSubjectAltOID.addLongIdentifier("subject-alternative-oid", true);
    genCSRSubjectAltOID.addLongIdentifier("subjectAlternativeOID", true);
    genCSRSubjectAltOID.addLongIdentifier("subject-alt-oid", true);
    genCSRSubjectAltOID.addLongIdentifier("subjectAltOID", true);
    genCSRSubjectAltOID.addLongIdentifier("san-oid", true);
    genCSRSubjectAltOID.addLongIdentifier("sanOID", true);
    genCSRSubjectAltOID.addValueValidator(new OIDArgumentValueValidator(true));
    genCSRParser.addArgument(genCSRSubjectAltOID);

    final BooleanValueArgument genCSRBasicConstraintsIsCA =
         new BooleanValueArgument(null, "basic-constraints-is-ca", false, null,
              INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_BC_IS_CA_DESC.get());
    genCSRBasicConstraintsIsCA.addLongIdentifier("basicConstraintsIsCA", true);
    genCSRBasicConstraintsIsCA.addLongIdentifier("bc-is-ca", true);
    genCSRBasicConstraintsIsCA.addLongIdentifier("bcIsCA", true);
    genCSRParser.addArgument(genCSRBasicConstraintsIsCA);

    final IntegerArgument genCSRBasicConstraintsPathLength =
         new IntegerArgument(null, "basic-constraints-maximum-path-length",
              false, 1, null,
              INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_BC_PATH_LENGTH_DESC.get(), 0,
              Integer.MAX_VALUE);
    genCSRBasicConstraintsPathLength.addLongIdentifier(
         "basicConstraintsMaximumPathLength", true);
    genCSRBasicConstraintsPathLength.addLongIdentifier(
         "basic-constraints-max-path-length", true);
    genCSRBasicConstraintsPathLength.addLongIdentifier(
         "basicConstraintsMaxPathLength", true);
    genCSRBasicConstraintsPathLength.addLongIdentifier(
         "basic-constraints-path-length", true);
    genCSRBasicConstraintsPathLength.addLongIdentifier(
         "basicConstraintsPathLength", true);
    genCSRBasicConstraintsPathLength.addLongIdentifier(
         "bc-maximum-path-length", true);
    genCSRBasicConstraintsPathLength.addLongIdentifier("bcMaximumPathLength",
         true);
    genCSRBasicConstraintsPathLength.addLongIdentifier("bc-max-path-length",
         true);
    genCSRBasicConstraintsPathLength.addLongIdentifier("bcMaxPathLength",
         true);
    genCSRBasicConstraintsPathLength.addLongIdentifier("bc-path-length", true);
    genCSRBasicConstraintsPathLength.addLongIdentifier("bcPathLength", true);
    genCSRParser.addArgument(genCSRBasicConstraintsPathLength);

    final StringArgument genCSRKeyUsage = new StringArgument(null, "key-usage",
         false, 0, null, INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_KU_DESC.get());
    genCSRKeyUsage.addLongIdentifier("keyUsage", true);
    genCSRParser.addArgument(genCSRKeyUsage);

    final StringArgument genCSRExtendedKeyUsage = new StringArgument(null,
         "extended-key-usage", false, 0, null,
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_EKU_DESC.get());
    genCSRExtendedKeyUsage.addLongIdentifier("extendedKeyUsage", true);
    genCSRParser.addArgument(genCSRExtendedKeyUsage);

    final StringArgument genCSRExtension = new StringArgument(null,
         "extension", false, 0, null,
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_EXT_DESC.get());
    genCSRExtension.addLongIdentifier("ext", true);
    genCSRParser.addArgument(genCSRExtension);

    final BooleanArgument genCSRDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_GEN_CSR_ARG_DISPLAY_COMMAND_DESC.get());
    genCSRDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    genCSRDisplayCommand.addLongIdentifier("show-keytool-command", true);
    genCSRDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    genCSRParser.addArgument(genCSRDisplayCommand);

    genCSRParser.addRequiredArgumentSet(genCSRKeystorePassword,
         genCSRKeystorePasswordFile, genCSRPromptForKeystorePassword);
    genCSRParser.addExclusiveArgumentSet(genCSRKeystorePassword,
         genCSRKeystorePasswordFile, genCSRPromptForKeystorePassword);
    genCSRParser.addExclusiveArgumentSet(genCSRPKPassword,
         genCSRPKPasswordFile, genCSRPromptForPKPassword);
    genCSRParser.addExclusiveArgumentSet(genCSRReplace, genCSRKeyAlgorithm);
    genCSRParser.addExclusiveArgumentSet(genCSRReplace, genCSRKeySizeBits);
    genCSRParser.addExclusiveArgumentSet(genCSRReplace,
         genCSRSignatureAlgorithm);
    genCSRParser.addDependentArgumentSet(genCSRBasicConstraintsPathLength,
         genCSRBasicConstraintsIsCA);

    final LinkedHashMap<String[],String> genCSRExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(3));
    genCSRExamples.put(
         new String[]
         {
           "generate-certificate-signing-request",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--subject-dn", "CN=ldap.example.com,O=Example Corp,C=US"
         },
         INFO_MANAGE_CERTS_SC_GEN_CSR_EXAMPLE_1.get());
    genCSRExamples.put(
         new String[]
         {
           "generate-certificate-signing-request",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--use-existing-key-pair",
           "--inherit-extensions",
           "--output-file", "server-cert.csr"
         },
         INFO_MANAGE_CERTS_SC_GEN_CSR_EXAMPLE_2.get());
    genCSRExamples.put(
         new String[]
         {
           "generate-certificate-signing-request",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--subject-dn", "CN=ldap.example.com,O=Example Corp,C=US",
           "--key-algorithm", "EC",
           "--key-size-bits", "256",
           "--signature-algorithm", "SHA256withECDSA",
           "--subject-alternative-name-dns", "ldap1.example.com",
           "--subject-alternative-name-dns", "ldap2.example.com",
           "--subject-alternative-name-ip-address", "1.2.3.4",
           "--subject-alternative-name-ip-address", "1.2.3.5",
           "--extended-key-usage", "server-auth",
           "--extended-key-usage", "client-auth",
           "--output-file", "server-cert.csr",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_GEN_CSR_EXAMPLE_3.get());

    final SubCommand genCSRSubCommand = new SubCommand(
         "generate-certificate-signing-request",
         INFO_MANAGE_CERTS_SC_GEN_CSR_DESC.get(), genCSRParser,
         genCSRExamples);
    genCSRSubCommand.addName("generateCertificateSigningRequest", true);
    genCSRSubCommand.addName("generate-certificate-request", true);
    genCSRSubCommand.addName("generateCertificateRequest", true);
    genCSRSubCommand.addName("generate-csr", true);
    genCSRSubCommand.addName("generateCSR", true);
    genCSRSubCommand.addName("certificate-signing-request", true);
    genCSRSubCommand.addName("certificateSigningRequest", true);
    genCSRSubCommand.addName("csr", true);
    genCSRSubCommand.addName("certreq", true);

    parser.addSubCommand(genCSRSubCommand);


    // Define the "sign-certificate-signing-request" subcommand and all of its
    // arguments.
    final ArgumentParser signCSRParser = new ArgumentParser(
         "sign-certificate-signing-request",
         INFO_MANAGE_CERTS_SC_SIGN_CSR_DESC.get());

    final FileArgument signCSRInputFile = new FileArgument(null,
         "request-input-file", true, 1, null,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_INPUT_FILE_DESC.get(), true, true,
         true, false);
    signCSRInputFile.addLongIdentifier("requestInputFile", true);
    signCSRInputFile.addLongIdentifier("certificate-signing-request", true);
    signCSRInputFile.addLongIdentifier("certificateSigningRequest", true);
    signCSRInputFile.addLongIdentifier("input-file", false);
    signCSRInputFile.addLongIdentifier("inputFile", true);
    signCSRInputFile.addLongIdentifier("csr", true);
    signCSRParser.addArgument(signCSRInputFile);

    final FileArgument signCSROutputFile = new FileArgument(null,
         "certificate-output-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_OUTPUT_FILE_DESC.get(), false, true,
         true, false);
    signCSROutputFile.addLongIdentifier("certificateOutputFile", true);
    signCSROutputFile.addLongIdentifier("output-file", false);
    signCSROutputFile.addLongIdentifier("outputFile", true);
    signCSROutputFile.addLongIdentifier("certificate-file", true);
    signCSROutputFile.addLongIdentifier("certificateFile", true);
    signCSRParser.addArgument(signCSROutputFile);

    final Set<String> signCSROutputFormatAllowedValues = StaticUtils.setOf(
         "PEM", "text", "txt", "RFC", "DER", "binary", "bin");
    final StringArgument signCSROutputFormat = new StringArgument(null,
         "output-format", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_FORMAT.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_FORMAT_DESC.get(),
         signCSROutputFormatAllowedValues, "PEM");
    signCSROutputFormat.addLongIdentifier("outputFormat", true);
    signCSRParser.addArgument(signCSROutputFormat);

    final FileArgument signCSRKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_KS_DESC.get(), true,
         true,  true, false);
    signCSRKeystore.addLongIdentifier("keystore-path", true);
    signCSRKeystore.addLongIdentifier("keystorePath", true);
    signCSRKeystore.addLongIdentifier("keystore-file", true);
    signCSRKeystore.addLongIdentifier("keystoreFile", true);
    signCSRParser.addArgument(signCSRKeystore);

    final StringArgument signCSRKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_KS_PW_DESC.get());
    signCSRKeystorePassword.addLongIdentifier("keystorePassword", true);
    signCSRKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    signCSRKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    signCSRKeystorePassword.addLongIdentifier("keystore-pin", true);
    signCSRKeystorePassword.addLongIdentifier("keystorePIN", true);
    signCSRKeystorePassword.addLongIdentifier("storepass", true);
    signCSRKeystorePassword.setSensitive(true);
    signCSRParser.addArgument(signCSRKeystorePassword);

    final FileArgument signCSRKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_KS_PW_FILE_DESC.get(), true, true,
         true, false);
    signCSRKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    signCSRKeystorePasswordFile.addLongIdentifier("keystore-passphrase-file",
         true);
    signCSRKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    signCSRKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    signCSRKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    signCSRParser.addArgument(signCSRKeystorePasswordFile);

    final BooleanArgument signCSRPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_PROMPT_FOR_KS_PW_DESC.get());
    signCSRPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    signCSRPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    signCSRPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    signCSRPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    signCSRPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    signCSRParser.addArgument(signCSRPromptForKeystorePassword);

    final StringArgument signCSRPKPassword = new StringArgument(null,
         "private-key-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_PK_PW_DESC.get());
    signCSRPKPassword.addLongIdentifier("privateKeyPassword", true);
    signCSRPKPassword.addLongIdentifier("private-key-passphrase", true);
    signCSRPKPassword.addLongIdentifier("privateKeyPassphrase", true);
    signCSRPKPassword.addLongIdentifier("private-key-pin", true);
    signCSRPKPassword.addLongIdentifier("privateKeyPIN", true);
    signCSRPKPassword.addLongIdentifier("key-password", true);
    signCSRPKPassword.addLongIdentifier("keyPassword", true);
    signCSRPKPassword.addLongIdentifier("key-passphrase", true);
    signCSRPKPassword.addLongIdentifier("keyPassphrase", true);
    signCSRPKPassword.addLongIdentifier("key-pin", true);
    signCSRPKPassword.addLongIdentifier("keyPIN", true);
    signCSRPKPassword.addLongIdentifier("keypass", true);
    signCSRPKPassword.setSensitive(true);
    signCSRParser.addArgument(signCSRPKPassword);

    final FileArgument signCSRPKPasswordFile = new FileArgument(null,
         "private-key-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_PK_PW_FILE_DESC.get(), true, true,
         true, false);
    signCSRPKPasswordFile.addLongIdentifier("privateKeyPasswordFile", true);
    signCSRPKPasswordFile.addLongIdentifier("private-key-passphrase-file",
         true);
    signCSRPKPasswordFile.addLongIdentifier("privateKeyPassphraseFile",
         true);
    signCSRPKPasswordFile.addLongIdentifier("private-key-pin-file",
         true);
    signCSRPKPasswordFile.addLongIdentifier("privateKeyPINFile", true);
    signCSRPKPasswordFile.addLongIdentifier("key-password-file", true);
    signCSRPKPasswordFile.addLongIdentifier("keyPasswordFile", true);
    signCSRPKPasswordFile.addLongIdentifier("key-passphrase-file",
         true);
    signCSRPKPasswordFile.addLongIdentifier("keyPassphraseFile",
         true);
    signCSRPKPasswordFile.addLongIdentifier("key-pin-file",
         true);
    signCSRPKPasswordFile.addLongIdentifier("keyPINFile", true);
    signCSRParser.addArgument(signCSRPKPasswordFile);

    final BooleanArgument signCSRPromptForPKPassword =
         new BooleanArgument(null, "prompt-for-private-key-password",
        INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_PROMPT_FOR_PK_PW_DESC.get());
    signCSRPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassword", true);
    signCSRPromptForPKPassword.addLongIdentifier(
         "prompt-for-private-key-passphrase", true);
    signCSRPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassphrase", true);
    signCSRPromptForPKPassword.addLongIdentifier("prompt-for-private-key-pin",
         true);
    signCSRPromptForPKPassword.addLongIdentifier("promptForPrivateKeyPIN",
         true);
    signCSRPromptForPKPassword.addLongIdentifier("prompt-for-key-password",
         true);
    signCSRPromptForPKPassword.addLongIdentifier("promptForKeyPassword",
         true);
    signCSRPromptForPKPassword.addLongIdentifier(
         "prompt-for-key-passphrase", true);
    signCSRPromptForPKPassword.addLongIdentifier(
         "promptForKeyPassphrase", true);
    signCSRPromptForPKPassword.addLongIdentifier("prompt-for-key-pin", true);
    signCSRPromptForPKPassword.addLongIdentifier("promptForKeyPIN", true);
    signCSRParser.addArgument(signCSRPromptForPKPassword);

    final StringArgument signCSRKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    signCSRKeystoreType.addLongIdentifier("keystoreType", true);
    signCSRKeystoreType.addLongIdentifier("storetype", true);
    signCSRParser.addArgument(signCSRKeystoreType);

    final StringArgument signCSRAlias = new StringArgument(null,
         "signing-certificate-alias",
         true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_ALIAS_DESC.get());
    signCSRAlias.addLongIdentifier("signingCertificateAlias", true);
    signCSRAlias.addLongIdentifier("signing-certificate-nickname", true);
    signCSRAlias.addLongIdentifier("signingCertificateNickname", true);
    signCSRAlias.addLongIdentifier("alias", true);
    signCSRAlias.addLongIdentifier("nickname", true);
    signCSRParser.addArgument(signCSRAlias);

    final DNArgument signCSRSubjectDN = new DNArgument(null, "subject-dn",
         false, 1, null,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_SUBJECT_DN_DESC.get());
    signCSRSubjectDN.addLongIdentifier("subjectDN", true);
    signCSRSubjectDN.addLongIdentifier("subject", true);
    signCSRSubjectDN.addLongIdentifier("dname", true);
    signCSRParser.addArgument(signCSRSubjectDN);

    final IntegerArgument signCSRDaysValid = new IntegerArgument(null,
         "days-valid", false, 1, null,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_DAYS_VALID_DESC.get(), 1,
         Integer.MAX_VALUE);
    signCSRDaysValid.addLongIdentifier("daysValid", true);
    signCSRDaysValid.addLongIdentifier("validity", true);
    signCSRParser.addArgument(signCSRDaysValid);

    final TimestampArgument signCSRNotBefore = new TimestampArgument(null,
         "validity-start-time", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_TIMESTAMP.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_VALIDITY_START_TIME_DESC.get(
              "20180102123456"));
    signCSRNotBefore.addLongIdentifier("validityStartTime", true);
    signCSRNotBefore.addLongIdentifier("not-before", true);
    signCSRNotBefore.addLongIdentifier("notBefore", true);
    signCSRParser.addArgument(signCSRNotBefore);

    final StringArgument signCSRSignatureAlgorithm = new StringArgument(null,
         "signature-algorithm", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_SIG_ALG_DESC.get());
    signCSRSignatureAlgorithm.addLongIdentifier("signatureAlgorithm", true);
    signCSRSignatureAlgorithm.addLongIdentifier("signature-alg", true);
    signCSRSignatureAlgorithm.addLongIdentifier("signatureAlg", true);
    signCSRSignatureAlgorithm.addLongIdentifier("sig-alg", true);
    signCSRSignatureAlgorithm.addLongIdentifier("sigAlg", true);
    signCSRParser.addArgument(signCSRSignatureAlgorithm);

    final BooleanArgument signCSRIncludeExtensions = new BooleanArgument(null,
         "include-requested-extensions", 1,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_INCLUDE_EXT_DESC.get());
    signCSRIncludeExtensions.addLongIdentifier("includeRequestedExtensions",
         true);
    signCSRParser.addArgument(signCSRIncludeExtensions);

    final StringArgument signCSRSubjectAltDNS = new StringArgument(null,
         "subject-alternative-name-dns", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_SAN_DNS_DESC.get());
    signCSRSubjectAltDNS.addLongIdentifier("subjectAlternativeNameDNS", true);
    signCSRSubjectAltDNS.addLongIdentifier("subject-alt-name-dns", true);
    signCSRSubjectAltDNS.addLongIdentifier("subjectAltNameDNS", true);
    signCSRSubjectAltDNS.addLongIdentifier("subject-alternative-dns", true);
    signCSRSubjectAltDNS.addLongIdentifier("subjectAlternativeDNS", true);
    signCSRSubjectAltDNS.addLongIdentifier("subject-alt-dns", true);
    signCSRSubjectAltDNS.addLongIdentifier("subjectAltDNS", true);
    signCSRSubjectAltDNS.addLongIdentifier("san-dns", true);
    signCSRSubjectAltDNS.addLongIdentifier("sanDNS", true);
    signCSRSubjectAltDNS.addValueValidator(
         new IA5StringArgumentValueValidator(false));
    signCSRParser.addArgument(signCSRSubjectAltDNS);

    final StringArgument signCSRSubjectAltIP = new StringArgument(null,
         "subject-alternative-name-ip-address", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_SAN_IP_DESC.get());
    signCSRSubjectAltIP.addLongIdentifier("subjectAlternativeNameIPAddress",
         true);
    signCSRSubjectAltIP.addLongIdentifier("subject-alternative-name-ip", true);
    signCSRSubjectAltIP.addLongIdentifier("subjectAlternativeNameIP", true);
    signCSRSubjectAltIP.addLongIdentifier("subject-alt-name-ip-address", true);
    signCSRSubjectAltIP.addLongIdentifier("subjectAltNameIPAddress", true);
    signCSRSubjectAltIP.addLongIdentifier("subject-alt-name-ip", true);
    signCSRSubjectAltIP.addLongIdentifier("subjectAltNameIP", true);
    signCSRSubjectAltIP.addLongIdentifier("subject-alternative-ip-address",
         true);
    signCSRSubjectAltIP.addLongIdentifier("subjectAlternativeIPAddress", true);
    signCSRSubjectAltIP.addLongIdentifier("subject-alternative-ip", true);
    signCSRSubjectAltIP.addLongIdentifier("subjectAlternativeIP", true);
    signCSRSubjectAltIP.addLongIdentifier("subject-alt-ip-address", true);
    signCSRSubjectAltIP.addLongIdentifier("subjectAltIPAddress", true);
    signCSRSubjectAltIP.addLongIdentifier("subject-alt-ip", true);
    signCSRSubjectAltIP.addLongIdentifier("subjectAltIP", true);
    signCSRSubjectAltIP.addLongIdentifier("san-ip-address", true);
    signCSRSubjectAltIP.addLongIdentifier("sanIPAddress", true);
    signCSRSubjectAltIP.addLongIdentifier("san-ip", true);
    signCSRSubjectAltIP.addLongIdentifier("sanIP", true);
    signCSRSubjectAltIP.addValueValidator(
         new IPAddressArgumentValueValidator(true, true));
    signCSRParser.addArgument(signCSRSubjectAltIP);

    final StringArgument signCSRSubjectAltEmail = new StringArgument(null,
         "subject-alternative-name-email-address", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_SAN_EMAIL_DESC.get());
    signCSRSubjectAltEmail.addLongIdentifier(
         "subjectAlternativeNameEmailAddress", true);
    signCSRSubjectAltEmail.addLongIdentifier("subject-alternative-name-email",
         true);
    signCSRSubjectAltEmail.addLongIdentifier("subjectAlternativeNameEmail",
         true);
    signCSRSubjectAltEmail.addLongIdentifier("subject-alt-name-email-address",
         true);
    signCSRSubjectAltEmail.addLongIdentifier("subjectAltNameEmailAddress",
         true);
    signCSRSubjectAltEmail.addLongIdentifier("subject-alt-name-email", true);
    signCSRSubjectAltEmail.addLongIdentifier("subjectAltNameEmail", true);
    signCSRSubjectAltEmail.addLongIdentifier(
         "subject-alternative-email-address", true);
    signCSRSubjectAltEmail.addLongIdentifier("subjectAlternativeEmailAddress",
         true);
    signCSRSubjectAltEmail.addLongIdentifier("subject-alternative-email", true);
    signCSRSubjectAltEmail.addLongIdentifier("subjectAlternativeEmail", true);
    signCSRSubjectAltEmail.addLongIdentifier("subject-alt-email-address", true);
    signCSRSubjectAltEmail.addLongIdentifier("subjectAltEmailAddress", true);
    signCSRSubjectAltEmail.addLongIdentifier("subject-alt-email", true);
    signCSRSubjectAltEmail.addLongIdentifier("subjectAltEmail", true);
    signCSRSubjectAltEmail.addLongIdentifier("san-email-address", true);
    signCSRSubjectAltEmail.addLongIdentifier("sanEmailAddress", true);
    signCSRSubjectAltEmail.addLongIdentifier("san-email", true);
    signCSRSubjectAltEmail.addLongIdentifier("sanEmail", true);
    signCSRSubjectAltEmail.addValueValidator(
         new IA5StringArgumentValueValidator(false));
    signCSRParser.addArgument(signCSRSubjectAltEmail);

    final StringArgument signCSRSubjectAltURI = new StringArgument(null,
         "subject-alternative-name-uri", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_URI.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_SAN_URI_DESC.get());
    signCSRSubjectAltURI.addLongIdentifier("subjectAlternativeNameURI", true);
    signCSRSubjectAltURI.addLongIdentifier("subject-alt-name-uri", true);
    signCSRSubjectAltURI.addLongIdentifier("subjectAltNameURI", true);
    signCSRSubjectAltURI.addLongIdentifier("subject-alternative-uri", true);
    signCSRSubjectAltURI.addLongIdentifier("subjectAlternativeURI", true);
    signCSRSubjectAltURI.addLongIdentifier("subject-alt-uri", true);
    signCSRSubjectAltURI.addLongIdentifier("subjectAltURI", true);
    signCSRSubjectAltURI.addLongIdentifier("san-uri", true);
    signCSRSubjectAltURI.addLongIdentifier("sanURI", true);
    signCSRParser.addArgument(signCSRSubjectAltURI);

    final StringArgument signCSRSubjectAltOID = new StringArgument(null,
         "subject-alternative-name-oid", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_OID.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_SAN_OID_DESC.get());
    signCSRSubjectAltOID.addLongIdentifier("subjectAlternativeNameOID", true);
    signCSRSubjectAltOID.addLongIdentifier("subject-alt-name-oid", true);
    signCSRSubjectAltOID.addLongIdentifier("subjectAltNameOID", true);
    signCSRSubjectAltOID.addLongIdentifier("subject-alternative-oid", true);
    signCSRSubjectAltOID.addLongIdentifier("subjectAlternativeOID", true);
    signCSRSubjectAltOID.addLongIdentifier("subject-alt-oid", true);
    signCSRSubjectAltOID.addLongIdentifier("subjectAltOID", true);
    signCSRSubjectAltOID.addLongIdentifier("san-oid", true);
    signCSRSubjectAltOID.addLongIdentifier("sanOID", true);
    signCSRSubjectAltOID.addValueValidator(new OIDArgumentValueValidator(true));
    signCSRParser.addArgument(signCSRSubjectAltOID);

    final StringArgument signCSRIssuerAltDNS = new StringArgument(null,
         "issuer-alternative-name-dns", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_IAN_DNS_DESC.get());
    signCSRIssuerAltDNS.addLongIdentifier("issuerAlternativeNameDNS", true);
    signCSRIssuerAltDNS.addLongIdentifier("issuer-alt-name-dns", true);
    signCSRIssuerAltDNS.addLongIdentifier("issuerAltNameDNS", true);
    signCSRIssuerAltDNS.addLongIdentifier("issuer-alternative-dns", true);
    signCSRIssuerAltDNS.addLongIdentifier("issuerAlternativeDNS", true);
    signCSRIssuerAltDNS.addLongIdentifier("issuer-alt-dns", true);
    signCSRIssuerAltDNS.addLongIdentifier("issuerAltDNS", true);
    signCSRIssuerAltDNS.addLongIdentifier("ian-dns", true);
    signCSRIssuerAltDNS.addLongIdentifier("ianDNS", true);
    signCSRIssuerAltDNS.addValueValidator(
         new IA5StringArgumentValueValidator(false));
    signCSRParser.addArgument(signCSRIssuerAltDNS);

    final StringArgument signCSRIssuerAltIP = new StringArgument(null,
         "issuer-alternative-name-ip-address", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_IAN_IP_DESC.get());
    signCSRIssuerAltIP.addLongIdentifier("issuerAlternativeNameIPAddress",
         true);
    signCSRIssuerAltIP.addLongIdentifier("issuer-alternative-name-ip", true);
    signCSRIssuerAltIP.addLongIdentifier("issuerAlternativeNameIP", true);
    signCSRIssuerAltIP.addLongIdentifier("issuer-alt-name-ip-address", true);
    signCSRIssuerAltIP.addLongIdentifier("issuerAltNameIPAddress", true);
    signCSRIssuerAltIP.addLongIdentifier("issuer-alt-name-ip", true);
    signCSRIssuerAltIP.addLongIdentifier("issuerAltNameIP", true);
    signCSRIssuerAltIP.addLongIdentifier("issuer-alternative-ip-address",
         true);
    signCSRIssuerAltIP.addLongIdentifier("issuerAlternativeIPAddress", true);
    signCSRIssuerAltIP.addLongIdentifier("issuer-alternative-ip", true);
    signCSRIssuerAltIP.addLongIdentifier("issuerAlternativeIP", true);
    signCSRIssuerAltIP.addLongIdentifier("issuer-alt-ip-address", true);
    signCSRIssuerAltIP.addLongIdentifier("issuerAltIPAddress", true);
    signCSRIssuerAltIP.addLongIdentifier("issuer-alt-ip", true);
    signCSRIssuerAltIP.addLongIdentifier("issuerAltIP", true);
    signCSRIssuerAltIP.addLongIdentifier("ian-ip-address", true);
    signCSRIssuerAltIP.addLongIdentifier("ianIPAddress", true);
    signCSRIssuerAltIP.addLongIdentifier("ian-ip", true);
    signCSRIssuerAltIP.addLongIdentifier("ianIP", true);
    signCSRIssuerAltIP.addValueValidator(
         new IPAddressArgumentValueValidator(true, true));
    signCSRParser.addArgument(signCSRIssuerAltIP);

    final StringArgument signCSRIssuerAltEmail = new StringArgument(null,
         "issuer-alternative-name-email-address", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_NAME.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_IAN_EMAIL_DESC.get());
    signCSRIssuerAltEmail.addLongIdentifier(
         "issuerAlternativeNameEmailAddress", true);
    signCSRIssuerAltEmail.addLongIdentifier("issuer-alternative-name-email",
         true);
    signCSRIssuerAltEmail.addLongIdentifier("issuerAlternativeNameEmail",
         true);
    signCSRIssuerAltEmail.addLongIdentifier("issuer-alt-name-email-address",
         true);
    signCSRIssuerAltEmail.addLongIdentifier("issuerAltNameEmailAddress",
         true);
    signCSRIssuerAltEmail.addLongIdentifier("issuer-alt-name-email", true);
    signCSRIssuerAltEmail.addLongIdentifier("issuerAltNameEmail", true);
    signCSRIssuerAltEmail.addLongIdentifier(
         "issuer-alternative-email-address", true);
    signCSRIssuerAltEmail.addLongIdentifier("issuerAlternativeEmailAddress",
         true);
    signCSRIssuerAltEmail.addLongIdentifier("issuer-alternative-email", true);
    signCSRIssuerAltEmail.addLongIdentifier("issuerAlternativeEmail", true);
    signCSRIssuerAltEmail.addLongIdentifier("issuer-alt-email-address", true);
    signCSRIssuerAltEmail.addLongIdentifier("issuerAltEmailAddress", true);
    signCSRIssuerAltEmail.addLongIdentifier("issuer-alt-email", true);
    signCSRIssuerAltEmail.addLongIdentifier("issuerAltEmail", true);
    signCSRIssuerAltEmail.addLongIdentifier("ian-email-address", true);
    signCSRIssuerAltEmail.addLongIdentifier("ianEmailAddress", true);
    signCSRIssuerAltEmail.addLongIdentifier("ian-email", true);
    signCSRIssuerAltEmail.addLongIdentifier("ianEmail", true);
    signCSRIssuerAltEmail.addValueValidator(
         new IA5StringArgumentValueValidator(false));
    signCSRParser.addArgument(signCSRIssuerAltEmail);

    final StringArgument signCSRIssuerAltURI = new StringArgument(null,
         "issuer-alternative-name-uri", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_URI.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_IAN_URI_DESC.get());
    signCSRIssuerAltURI.addLongIdentifier("issuerAlternativeNameURI", true);
    signCSRIssuerAltURI.addLongIdentifier("issuer-alt-name-uri", true);
    signCSRIssuerAltURI.addLongIdentifier("issuerAltNameURI", true);
    signCSRIssuerAltURI.addLongIdentifier("issuer-alternative-uri", true);
    signCSRIssuerAltURI.addLongIdentifier("issuerAlternativeURI", true);
    signCSRIssuerAltURI.addLongIdentifier("issuer-alt-uri", true);
    signCSRIssuerAltURI.addLongIdentifier("issuerAltURI", true);
    signCSRIssuerAltURI.addLongIdentifier("ian-uri", true);
    signCSRIssuerAltURI.addLongIdentifier("ianURI", true);
    signCSRParser.addArgument(signCSRIssuerAltURI);

    final StringArgument signCSRIssuerAltOID = new StringArgument(null,
         "issuer-alternative-name-oid", false, 0,
         INFO_MANAGE_CERTS_PLACEHOLDER_OID.get(),
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_IAN_OID_DESC.get());
    signCSRIssuerAltOID.addLongIdentifier("issuerAlternativeNameOID", true);
    signCSRIssuerAltOID.addLongIdentifier("issuer-alt-name-oid", true);
    signCSRIssuerAltOID.addLongIdentifier("issuerAltNameOID", true);
    signCSRIssuerAltOID.addLongIdentifier("issuer-alternative-oid", true);
    signCSRIssuerAltOID.addLongIdentifier("issuerAlternativeOID", true);
    signCSRIssuerAltOID.addLongIdentifier("issuer-alt-oid", true);
    signCSRIssuerAltOID.addLongIdentifier("issuerAltOID", true);
    signCSRIssuerAltOID.addLongIdentifier("ian-oid", true);
    signCSRIssuerAltOID.addLongIdentifier("ianOID", true);
    signCSRIssuerAltOID.addValueValidator(new OIDArgumentValueValidator(true));
    signCSRParser.addArgument(signCSRIssuerAltOID);

    final BooleanValueArgument signCSRBasicConstraintsIsCA =
         new BooleanValueArgument(null, "basic-constraints-is-ca", false, null,
              INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_BC_IS_CA_DESC.get());
    signCSRBasicConstraintsIsCA.addLongIdentifier("basicConstraintsIsCA", true);
    signCSRBasicConstraintsIsCA.addLongIdentifier("bc-is-ca", true);
    signCSRBasicConstraintsIsCA.addLongIdentifier("bcIsCA", true);
    signCSRParser.addArgument(signCSRBasicConstraintsIsCA);

    final IntegerArgument signCSRBasicConstraintsPathLength =
         new IntegerArgument(null, "basic-constraints-maximum-path-length",
              false, 1, null,
              INFO_MANAGE_CERTS_SC_GEN_CERT_ARG_BC_PATH_LENGTH_DESC.get(), 0,
              Integer.MAX_VALUE);
    signCSRBasicConstraintsPathLength.addLongIdentifier(
         "basicConstraintsMaximumPathLength", true);
    signCSRBasicConstraintsPathLength.addLongIdentifier(
         "basic-constraints-max-path-length", true);
    signCSRBasicConstraintsPathLength.addLongIdentifier(
         "basicConstraintsMaxPathLength", true);
    signCSRBasicConstraintsPathLength.addLongIdentifier(
         "basic-constraints-path-length", true);
    signCSRBasicConstraintsPathLength.addLongIdentifier(
         "basicConstraintsPathLength", true);
    signCSRBasicConstraintsPathLength.addLongIdentifier(
         "bc-maximum-path-length", true);
    signCSRBasicConstraintsPathLength.addLongIdentifier("bcMaximumPathLength",
         true);
    signCSRBasicConstraintsPathLength.addLongIdentifier("bc-max-path-length",
         true);
    signCSRBasicConstraintsPathLength.addLongIdentifier("bcMaxPathLength",
         true);
    signCSRBasicConstraintsPathLength.addLongIdentifier("bc-path-length", true);
    signCSRBasicConstraintsPathLength.addLongIdentifier("bcPathLength", true);
    signCSRParser.addArgument(signCSRBasicConstraintsPathLength);

    final StringArgument signCSRKeyUsage = new StringArgument(null, "key-usage",
         false, 0, null, INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_KU_DESC.get());
    signCSRKeyUsage.addLongIdentifier("keyUsage", true);
    signCSRParser.addArgument(signCSRKeyUsage);

    final StringArgument signCSRExtendedKeyUsage = new StringArgument(null,
         "extended-key-usage", false, 0, null,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_EKU_DESC.get());
    signCSRExtendedKeyUsage.addLongIdentifier("extendedKeyUsage", true);
    signCSRParser.addArgument(signCSRExtendedKeyUsage);

    final StringArgument signCSRExtension = new StringArgument(null,
         "extension", false, 0, null,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_EXT_DESC.get());
    signCSRExtension.addLongIdentifier("ext", true);
    signCSRParser.addArgument(signCSRExtension);

    final BooleanArgument signCSRNoPrompt = new BooleanArgument(null,
         "no-prompt", 1,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_NO_PROMPT_DESC.get());
    signCSRNoPrompt.addLongIdentifier("noPrompt", true);
    signCSRParser.addArgument(signCSRNoPrompt);

    final BooleanArgument signCSRDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_SIGN_CSR_ARG_DISPLAY_COMMAND_DESC.get());
    signCSRDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    signCSRDisplayCommand.addLongIdentifier("show-keytool-command", true);
    signCSRDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    signCSRParser.addArgument(signCSRDisplayCommand);

    signCSRParser.addRequiredArgumentSet(signCSRKeystorePassword,
         signCSRKeystorePasswordFile, signCSRPromptForKeystorePassword);
    signCSRParser.addExclusiveArgumentSet(signCSRKeystorePassword,
         signCSRKeystorePasswordFile, signCSRPromptForKeystorePassword);
    signCSRParser.addExclusiveArgumentSet(signCSRPKPassword,
         signCSRPKPasswordFile, signCSRPromptForPKPassword);
    signCSRParser.addDependentArgumentSet(signCSRBasicConstraintsPathLength,
         signCSRBasicConstraintsIsCA);

    final LinkedHashMap<String[],String> signCSRExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));
    signCSRExamples.put(
         new String[]
         {
           "sign-certificate-signing-request",
           "--request-input-file", "server-cert.csr",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--signing-certificate-alias", "ca-cert",
           "--include-requested-extensions"
         },
         INFO_MANAGE_CERTS_SC_SIGN_CSR_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "keystore")));
    signCSRExamples.put(
         new String[]
         {
           "sign-certificate-signing-request",
           "--request-input-file", "server-cert.csr",
           "--certificate-output-file", "server-cert.der",
           "--output-format", "DER",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--signing-certificate-alias", "ca-cert",
           "--days-valid", "730",
           "--validity-start-time", "20170101000000",
           "--include-requested-extensions",
           "--issuer-alternative-name-email-address", "ca@example.com",
         },
         INFO_MANAGE_CERTS_SC_SIGN_CSR_EXAMPLE_2.get(
              getPlatformSpecificPath("config", "keystore")));

    final SubCommand signCSRSubCommand = new SubCommand(
         "sign-certificate-signing-request",
         INFO_MANAGE_CERTS_SC_SIGN_CSR_DESC.get(), signCSRParser,
         signCSRExamples);
    signCSRSubCommand.addName("signCertificateSigningRequest", true);
    signCSRSubCommand.addName("sign-certificate-request", true);
    signCSRSubCommand.addName("signCertificateRequest", true);
    signCSRSubCommand.addName("sign-certificate", true);
    signCSRSubCommand.addName("signCertificate", true);
    signCSRSubCommand.addName("sign-csr", true);
    signCSRSubCommand.addName("signCSR", true);
    signCSRSubCommand.addName("sign", true);
    signCSRSubCommand.addName("gencert", true);

    parser.addSubCommand(signCSRSubCommand);


    // Define the "change-certificate-alias" subcommand and all of its
    // arguments.
    final ArgumentParser changeAliasParser = new ArgumentParser(
         "change-certificate-alias",
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_DESC.get());

    final FileArgument changeAliasKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_KS_DESC.get(),
         true, true,  true, false);
    changeAliasKeystore.addLongIdentifier("keystore-path", true);
    changeAliasKeystore.addLongIdentifier("keystorePath", true);
    changeAliasKeystore.addLongIdentifier("keystore-file", true);
    changeAliasKeystore.addLongIdentifier("keystoreFile", true);
    changeAliasParser.addArgument(changeAliasKeystore);

    final StringArgument changeAliasKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_KS_PW_DESC.get());
    changeAliasKeystorePassword.addLongIdentifier("keystorePassword", true);
    changeAliasKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    changeAliasKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    changeAliasKeystorePassword.addLongIdentifier("keystore-pin", true);
    changeAliasKeystorePassword.addLongIdentifier("keystorePIN", true);
    changeAliasKeystorePassword.addLongIdentifier("storepass", true);
    changeAliasKeystorePassword.setSensitive(true);
    changeAliasParser.addArgument(changeAliasKeystorePassword);

    final FileArgument changeAliasKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_KS_PW_FILE_DESC.get(), true,
         true, true, false);
    changeAliasKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    changeAliasKeystorePasswordFile.addLongIdentifier(
         "keystore-passphrase-file", true);
    changeAliasKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    changeAliasKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    changeAliasKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    changeAliasParser.addArgument(changeAliasKeystorePasswordFile);

    final BooleanArgument changeAliasPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_PROMPT_FOR_KS_PW_DESC.get());
    changeAliasPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    changeAliasPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    changeAliasPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    changeAliasPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    changeAliasPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    changeAliasParser.addArgument(changeAliasPromptForKeystorePassword);

    final StringArgument changeAliasPKPassword = new StringArgument(null,
         "private-key-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_PK_PW_DESC.get());
    changeAliasPKPassword.addLongIdentifier("privateKeyPassword", true);
    changeAliasPKPassword.addLongIdentifier("private-key-passphrase", true);
    changeAliasPKPassword.addLongIdentifier("privateKeyPassphrase", true);
    changeAliasPKPassword.addLongIdentifier("private-key-pin", true);
    changeAliasPKPassword.addLongIdentifier("privateKeyPIN", true);
    changeAliasPKPassword.addLongIdentifier("key-password", true);
    changeAliasPKPassword.addLongIdentifier("keyPassword", true);
    changeAliasPKPassword.addLongIdentifier("key-passphrase", true);
    changeAliasPKPassword.addLongIdentifier("keyPassphrase", true);
    changeAliasPKPassword.addLongIdentifier("key-pin", true);
    changeAliasPKPassword.addLongIdentifier("keyPIN", true);
    changeAliasPKPassword.addLongIdentifier("keypass", true);
    changeAliasPKPassword.setSensitive(true);
    changeAliasParser.addArgument(changeAliasPKPassword);

    final FileArgument changeAliasPKPasswordFile = new FileArgument(null,
         "private-key-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_PK_PW_FILE_DESC.get(), true,
         true, true, false);
    changeAliasPKPasswordFile.addLongIdentifier("privateKeyPasswordFile", true);
    changeAliasPKPasswordFile.addLongIdentifier("private-key-passphrase-file",
         true);
    changeAliasPKPasswordFile.addLongIdentifier("privateKeyPassphraseFile",
         true);
    changeAliasPKPasswordFile.addLongIdentifier("private-key-pin-file",
         true);
    changeAliasPKPasswordFile.addLongIdentifier("privateKeyPINFile", true);
    changeAliasPKPasswordFile.addLongIdentifier("key-password-file", true);
    changeAliasPKPasswordFile.addLongIdentifier("keyPasswordFile", true);
    changeAliasPKPasswordFile.addLongIdentifier("key-passphrase-file",
         true);
    changeAliasPKPasswordFile.addLongIdentifier("keyPassphraseFile",
         true);
    changeAliasPKPasswordFile.addLongIdentifier("key-pin-file",
         true);
    changeAliasPKPasswordFile.addLongIdentifier("keyPINFile", true);
    changeAliasParser.addArgument(changeAliasPKPasswordFile);

    final BooleanArgument changeAliasPromptForPKPassword =
         new BooleanArgument(null, "prompt-for-private-key-password",
        INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_PROMPT_FOR_PK_PW_DESC.get());
    changeAliasPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassword", true);
    changeAliasPromptForPKPassword.addLongIdentifier(
         "prompt-for-private-key-passphrase", true);
    changeAliasPromptForPKPassword.addLongIdentifier(
         "promptForPrivateKeyPassphrase", true);
    changeAliasPromptForPKPassword.addLongIdentifier(
         "prompt-for-private-key-pin", true);
    changeAliasPromptForPKPassword.addLongIdentifier("promptForPrivateKeyPIN",
         true);
    changeAliasPromptForPKPassword.addLongIdentifier("prompt-for-key-password",
         true);
    changeAliasPromptForPKPassword.addLongIdentifier("promptForKeyPassword",
         true);
    changeAliasPromptForPKPassword.addLongIdentifier(
         "prompt-for-key-passphrase", true);
    changeAliasPromptForPKPassword.addLongIdentifier(
         "promptForKeyPassphrase", true);
    changeAliasPromptForPKPassword.addLongIdentifier("prompt-for-key-pin",
         true);
    changeAliasPromptForPKPassword.addLongIdentifier("promptForKeyPIN", true);
    changeAliasParser.addArgument(changeAliasPromptForPKPassword);

    final StringArgument changeAliasKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    changeAliasKeystoreType.addLongIdentifier("keystoreType", true);
    changeAliasKeystoreType.addLongIdentifier("storetype", true);
    changeAliasParser.addArgument(changeAliasKeystoreType);

    final StringArgument changeAliasCurrentAlias = new StringArgument(null,
         "current-alias", true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_CURRENT_ALIAS_DESC.get());
    changeAliasCurrentAlias.addLongIdentifier("currentAlias", true);
    changeAliasCurrentAlias.addLongIdentifier("old-alias", true);
    changeAliasCurrentAlias.addLongIdentifier("oldAlias", true);
    changeAliasCurrentAlias.addLongIdentifier("source-alias", true);
    changeAliasCurrentAlias.addLongIdentifier("sourceAlias", true);
    changeAliasCurrentAlias.addLongIdentifier("alias", true);
    changeAliasCurrentAlias.addLongIdentifier("current-nickname", true);
    changeAliasCurrentAlias.addLongIdentifier("currentNickname", true);
    changeAliasCurrentAlias.addLongIdentifier("old-nickname", true);
    changeAliasCurrentAlias.addLongIdentifier("oldNickname", true);
    changeAliasCurrentAlias.addLongIdentifier("source-nickname", true);
    changeAliasCurrentAlias.addLongIdentifier("sourceNickname", true);
    changeAliasCurrentAlias.addLongIdentifier("nickname", true);
    changeAliasCurrentAlias.addLongIdentifier("from", false);
    changeAliasParser.addArgument(changeAliasCurrentAlias);

    final StringArgument changeAliasNewAlias = new StringArgument(null,
         "new-alias", true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_NEW_ALIAS_DESC.get());
    changeAliasNewAlias.addLongIdentifier("newAlias", true);
    changeAliasNewAlias.addLongIdentifier("destination-alias", true);
    changeAliasNewAlias.addLongIdentifier("destinationAlias", true);
    changeAliasNewAlias.addLongIdentifier("new-nickname", true);
    changeAliasNewAlias.addLongIdentifier("newNickname", true);
    changeAliasNewAlias.addLongIdentifier("destination-nickname", true);
    changeAliasNewAlias.addLongIdentifier("destinationNickname", true);
    changeAliasNewAlias.addLongIdentifier("to", false);
    changeAliasParser.addArgument(changeAliasNewAlias);

    final BooleanArgument changeAliasDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_ARG_DISPLAY_COMMAND_DESC.get());
    changeAliasDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    changeAliasDisplayCommand.addLongIdentifier("show-keytool-command", true);
    changeAliasDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    changeAliasParser.addArgument(changeAliasDisplayCommand);

    changeAliasParser.addRequiredArgumentSet(changeAliasKeystorePassword,
         changeAliasKeystorePasswordFile, changeAliasPromptForKeystorePassword);
    changeAliasParser.addExclusiveArgumentSet(changeAliasKeystorePassword,
         changeAliasKeystorePasswordFile, changeAliasPromptForKeystorePassword);
    changeAliasParser.addExclusiveArgumentSet(changeAliasPKPassword,
         changeAliasPKPasswordFile, changeAliasPromptForPKPassword);

    final LinkedHashMap<String[],String> changeAliasExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    changeAliasExamples.put(
         new String[]
         {
           "change-certificate-alias",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--current-alias", "server-cert",
           "--new-alias", "server-certificate",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_EXAMPLE_1.get());

    final SubCommand changeAliasSubCommand = new SubCommand(
         "change-certificate-alias",
         INFO_MANAGE_CERTS_SC_CHANGE_ALIAS_DESC.get(), changeAliasParser,
         changeAliasExamples);
    changeAliasSubCommand.addName("changeCertificateAlias", true);
    changeAliasSubCommand.addName("change-alias", true);
    changeAliasSubCommand.addName("changeAlias", true);
    changeAliasSubCommand.addName("rename-certificate", true);
    changeAliasSubCommand.addName("renameCertificate", true);
    changeAliasSubCommand.addName("rename", true);

    parser.addSubCommand(changeAliasSubCommand);


    // Define the "change-keystore-password" subcommand and all of its
    // arguments.
    final ArgumentParser changeKSPWParser = new ArgumentParser(
         "change-keystore-password",
         INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_DESC.get());

    final FileArgument changeKSPWKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_ARG_KS_DESC.get(),
         true, true,  true, false);
    changeKSPWKeystore.addLongIdentifier("keystore-path", true);
    changeKSPWKeystore.addLongIdentifier("keystorePath", true);
    changeKSPWKeystore.addLongIdentifier("keystore-file", true);
    changeKSPWKeystore.addLongIdentifier("keystoreFile", true);
    changeKSPWParser.addArgument(changeKSPWKeystore);

    final StringArgument changeKSPWCurrentPassword = new StringArgument(null,
         "current-keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_ARG_CURRENT_PW_DESC.get());
    changeKSPWCurrentPassword.addLongIdentifier("currentKeystorePassword",
         true);
    changeKSPWCurrentPassword.addLongIdentifier("current-keystore-passphrase",
         true);
    changeKSPWCurrentPassword.addLongIdentifier("currentKeystorePassphrase",
         true);
    changeKSPWCurrentPassword.addLongIdentifier("current-keystore-pin", true);
    changeKSPWCurrentPassword.addLongIdentifier("currentKeystorePIN", true);
    changeKSPWCurrentPassword.addLongIdentifier("storepass", true);
    changeKSPWCurrentPassword.setSensitive(true);
    changeKSPWParser.addArgument(changeKSPWCurrentPassword);

    final FileArgument changeKSPWCurrentPasswordFile = new FileArgument(null,
         "current-keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_ARG_CURRENT_PW_FILE_DESC.get(), true,
         true, true, false);
    changeKSPWCurrentPasswordFile.addLongIdentifier(
         "currentKeystorePasswordFile", true);
    changeKSPWCurrentPasswordFile.addLongIdentifier(
         "current-keystore-passphrase-file", true);
    changeKSPWCurrentPasswordFile.addLongIdentifier(
         "currentKeystorePassphraseFile", true);
    changeKSPWCurrentPasswordFile.addLongIdentifier("current-keystore-pin-file",
         true);
    changeKSPWCurrentPasswordFile.addLongIdentifier("currentKeystorePINFile",
         true);
    changeKSPWParser.addArgument(changeKSPWCurrentPasswordFile);

    final BooleanArgument changeKSPWPromptForCurrentPassword =
         new BooleanArgument(null, "prompt-for-current-keystore-password",
        INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_ARG_PROMPT_FOR_CURRENT_PW_DESC.get());
    changeKSPWPromptForCurrentPassword.addLongIdentifier(
         "promptForCurrentKeystorePassword", true);
    changeKSPWPromptForCurrentPassword.addLongIdentifier(
         "prompt-for-current-keystore-passphrase", true);
    changeKSPWPromptForCurrentPassword.addLongIdentifier(
         "promptForCurrentKeystorePassphrase", true);
    changeKSPWPromptForCurrentPassword.addLongIdentifier(
         "prompt-for-current-keystore-pin", true);
    changeKSPWPromptForCurrentPassword.addLongIdentifier(
         "promptForCurrentKeystorePIN", true);
    changeKSPWParser.addArgument(changeKSPWPromptForCurrentPassword);

    final StringArgument changeKSPWNewPassword = new StringArgument(null,
         "new-keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_ARG_NEW_PW_DESC.get());
    changeKSPWNewPassword.addLongIdentifier("newKeystorePassword",
         true);
    changeKSPWNewPassword.addLongIdentifier("new-keystore-passphrase",
         true);
    changeKSPWNewPassword.addLongIdentifier("newKeystorePassphrase",
         true);
    changeKSPWNewPassword.addLongIdentifier("new-keystore-pin", true);
    changeKSPWNewPassword.addLongIdentifier("newKeystorePIN", true);
    changeKSPWNewPassword.addLongIdentifier("new", true);
    changeKSPWNewPassword.setSensitive(true);
    changeKSPWParser.addArgument(changeKSPWNewPassword);

    final FileArgument changeKSPWNewPasswordFile = new FileArgument(null,
         "new-keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_ARG_NEW_PW_FILE_DESC.get(), true,
         true, true, false);
    changeKSPWNewPasswordFile.addLongIdentifier("newKeystorePasswordFile",
         true);
    changeKSPWNewPasswordFile.addLongIdentifier("new-keystore-passphrase-file",
         true);
    changeKSPWNewPasswordFile.addLongIdentifier("newKeystorePassphraseFile",
         true);
    changeKSPWNewPasswordFile.addLongIdentifier("new-keystore-pin-file", true);
    changeKSPWNewPasswordFile.addLongIdentifier("newKeystorePINFile", true);
    changeKSPWParser.addArgument(changeKSPWNewPasswordFile);

    final BooleanArgument changeKSPWPromptForNewPassword =
         new BooleanArgument(null, "prompt-for-new-keystore-password",
        INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_ARG_PROMPT_FOR_NEW_PW_DESC.get());
    changeKSPWPromptForNewPassword.addLongIdentifier(
         "promptForNewKeystorePassword", true);
    changeKSPWPromptForNewPassword.addLongIdentifier(
         "prompt-for-new-keystore-passphrase", true);
    changeKSPWPromptForNewPassword.addLongIdentifier(
         "promptForNewKeystorePassphrase", true);
    changeKSPWPromptForNewPassword.addLongIdentifier(
         "prompt-for-new-keystore-pin", true);
    changeKSPWPromptForNewPassword.addLongIdentifier(
         "promptForNewKeystorePIN", true);
    changeKSPWParser.addArgument(changeKSPWPromptForNewPassword);

    final BooleanArgument changeKSPWDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_ARG_DISPLAY_COMMAND_DESC.get());
    changeKSPWDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    changeKSPWDisplayCommand.addLongIdentifier("show-keytool-command", true);
    changeKSPWDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    changeKSPWParser.addArgument(changeKSPWDisplayCommand);

    changeKSPWParser.addRequiredArgumentSet(changeKSPWCurrentPassword,
         changeKSPWCurrentPasswordFile, changeKSPWPromptForCurrentPassword);
    changeKSPWParser.addExclusiveArgumentSet(changeKSPWCurrentPassword,
         changeKSPWCurrentPasswordFile, changeKSPWPromptForCurrentPassword);
    changeKSPWParser.addRequiredArgumentSet(changeKSPWNewPassword,
         changeKSPWNewPasswordFile, changeKSPWPromptForNewPassword);
    changeKSPWParser.addExclusiveArgumentSet(changeKSPWNewPassword,
         changeKSPWNewPasswordFile, changeKSPWPromptForNewPassword);

    final LinkedHashMap<String[],String> changeKSPWExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    changeKSPWExamples.put(
         new String[]
         {
           "change-keystore-password",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--current-keystore-password-file",
                getPlatformSpecificPath("config", "current.pin"),
           "--new-keystore-password-file",
                getPlatformSpecificPath("config", "new.pin"),
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "keystore"),
              getPlatformSpecificPath("config", "current.pin"),
              getPlatformSpecificPath("config", "new.pin")));

    final SubCommand changeKSPWSubCommand = new SubCommand(
         "change-keystore-password",
         INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_DESC.get(), changeKSPWParser,
         changeKSPWExamples);
    changeKSPWSubCommand.addName("changeKeystorePassword", true);
    changeKSPWSubCommand.addName("change-keystore-passphrase", true);
    changeKSPWSubCommand.addName("changeKeystorePassphrase", true);
    changeKSPWSubCommand.addName("change-keystore-pin", true);
    changeKSPWSubCommand.addName("changeKeystorePIN", true);
    changeKSPWSubCommand.addName("storepasswd", true);

    parser.addSubCommand(changeKSPWSubCommand);


    // Define the "change-private-key-password" subcommand and all of its
    // arguments.
    final ArgumentParser changePKPWParser = new ArgumentParser(
         "change-private-key-password",
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_DESC.get());

    final FileArgument changePKPWKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_KS_DESC.get(),
         true, true,  true, false);
    changePKPWKeystore.addLongIdentifier("keystore-path", true);
    changePKPWKeystore.addLongIdentifier("keystorePath", true);
    changePKPWKeystore.addLongIdentifier("keystore-file", true);
    changePKPWKeystore.addLongIdentifier("keystoreFile", true);
    changePKPWParser.addArgument(changePKPWKeystore);

    final StringArgument changePKPWKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_KS_PW_DESC.get());
    changePKPWKeystorePassword.addLongIdentifier("keystorePassword", true);
    changePKPWKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    changePKPWKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    changePKPWKeystorePassword.addLongIdentifier("keystore-pin", true);
    changePKPWKeystorePassword.addLongIdentifier("keystorePIN", true);
    changePKPWKeystorePassword.addLongIdentifier("storepass", true);
    changePKPWKeystorePassword.setSensitive(true);
    changePKPWParser.addArgument(changePKPWKeystorePassword);

    final FileArgument changePKPWKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_KS_PW_FILE_DESC.get(), true,
         true, true, false);
    changePKPWKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    changePKPWKeystorePasswordFile.addLongIdentifier(
         "keystore-passphrase-file", true);
    changePKPWKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    changePKPWKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    changePKPWKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    changePKPWParser.addArgument(changePKPWKeystorePasswordFile);

    final BooleanArgument changePKPWPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_PROMPT_FOR_KS_PW_DESC.get());
    changePKPWPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    changePKPWPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    changePKPWPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    changePKPWPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    changePKPWPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    changePKPWParser.addArgument(changePKPWPromptForKeystorePassword);

    final StringArgument changePKPWKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    changePKPWKeystoreType.addLongIdentifier("keystoreType", true);
    changePKPWKeystoreType.addLongIdentifier("storetype", true);
    changePKPWParser.addArgument(changePKPWKeystoreType);

    final StringArgument changePKPWAlias = new StringArgument(null, "alias",
         true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_ALIAS_DESC.get());
    changePKPWAlias.addLongIdentifier("nickname", true);
    changePKPWParser.addArgument(changePKPWAlias);

    final StringArgument changePKPWCurrentPassword = new StringArgument(null,
         "current-private-key-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_CURRENT_PW_DESC.get());
    changePKPWCurrentPassword.addLongIdentifier("currentPrivateKeyPassword",
         true);
    changePKPWCurrentPassword.addLongIdentifier(
         "current-private-key-passphrase", true);
    changePKPWCurrentPassword.addLongIdentifier("currentPrivateKeyPassphrase",
         true);
    changePKPWCurrentPassword.addLongIdentifier("current-private-key-pin",
         true);
    changePKPWCurrentPassword.addLongIdentifier("currentPrivateKeyPIN", true);
    changePKPWCurrentPassword.addLongIdentifier("keypass", true);
    changePKPWCurrentPassword.setSensitive(true);
    changePKPWParser.addArgument(changePKPWCurrentPassword);

    final FileArgument changePKPWCurrentPasswordFile = new FileArgument(null,
         "current-private-key-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_CURRENT_PW_FILE_DESC.get(), true,
         true, true, false);
    changePKPWCurrentPasswordFile.addLongIdentifier(
         "currentPrivateKeyPasswordFile", true);
    changePKPWCurrentPasswordFile.addLongIdentifier(
         "current-private-key-passphrase-file", true);
    changePKPWCurrentPasswordFile.addLongIdentifier(
         "currentPrivateKeyPassphraseFile", true);
    changePKPWCurrentPasswordFile.addLongIdentifier(
         "current-private-key-pin-file", true);
    changePKPWCurrentPasswordFile.addLongIdentifier("currentPrivateKeyPINFile",
         true);
    changePKPWParser.addArgument(changePKPWCurrentPasswordFile);

    final BooleanArgument changePKPWPromptForCurrentPassword =
         new BooleanArgument(null, "prompt-for-current-private-key-password",
        INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_PROMPT_FOR_CURRENT_PW_DESC.get());
    changePKPWPromptForCurrentPassword.addLongIdentifier(
         "promptForCurrentPrivateKeyPassword", true);
    changePKPWPromptForCurrentPassword.addLongIdentifier(
         "prompt-for-current-private-key-passphrase", true);
    changePKPWPromptForCurrentPassword.addLongIdentifier(
         "promptForCurrentPrivateKeyPassphrase", true);
    changePKPWPromptForCurrentPassword.addLongIdentifier(
         "prompt-for-current-private-key-pin", true);
    changePKPWPromptForCurrentPassword.addLongIdentifier(
         "promptForCurrentPrivateKeyPIN", true);
    changePKPWParser.addArgument(changePKPWPromptForCurrentPassword);

    final StringArgument changePKPWNewPassword = new StringArgument(null,
         "new-private-key-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_NEW_PW_DESC.get());
    changePKPWNewPassword.addLongIdentifier("newPrivateKeyPassword",
         true);
    changePKPWNewPassword.addLongIdentifier("new-private-key-passphrase", true);
    changePKPWNewPassword.addLongIdentifier("newPrivateKeyPassphrase", true);
    changePKPWNewPassword.addLongIdentifier("new-private-key-pin", true);
    changePKPWNewPassword.addLongIdentifier("newPrivateKeyPIN", true);
    changePKPWNewPassword.addLongIdentifier("new", true);
    changePKPWNewPassword.setSensitive(true);
    changePKPWParser.addArgument(changePKPWNewPassword);

    final FileArgument changePKPWNewPasswordFile = new FileArgument(null,
         "new-private-key-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_NEW_PW_FILE_DESC.get(), true,
         true, true, false);
    changePKPWNewPasswordFile.addLongIdentifier("newPrivateKeyPasswordFile",
         true);
    changePKPWNewPasswordFile.addLongIdentifier(
         "new-private-key-passphrase-file", true);
    changePKPWNewPasswordFile.addLongIdentifier("newPrivateKeyPassphraseFile",
         true);
    changePKPWNewPasswordFile.addLongIdentifier("new-private-key-pin-file",
         true);
    changePKPWNewPasswordFile.addLongIdentifier("newPrivateKeyPINFile", true);
    changePKPWParser.addArgument(changePKPWNewPasswordFile);

    final BooleanArgument changePKPWPromptForNewPassword =
         new BooleanArgument(null, "prompt-for-new-private-key-password",
        INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_PROMPT_FOR_NEW_PW_DESC.get());
    changePKPWPromptForNewPassword.addLongIdentifier(
         "promptForNewPrivateKeyPassword", true);
    changePKPWPromptForNewPassword.addLongIdentifier(
         "prompt-for-new-private-key-passphrase", true);
    changePKPWPromptForNewPassword.addLongIdentifier(
         "promptForNewPrivateKeyPassphrase", true);
    changePKPWPromptForNewPassword.addLongIdentifier(
         "prompt-for-new-private-key-pin", true);
    changePKPWPromptForNewPassword.addLongIdentifier(
         "promptForNewPrivateKeyPIN", true);
    changePKPWParser.addArgument(changePKPWPromptForNewPassword);

    final BooleanArgument changePKPWDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_ARG_DISPLAY_COMMAND_DESC.get());
    changePKPWDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    changePKPWDisplayCommand.addLongIdentifier("show-keytool-command", true);
    changePKPWDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    changePKPWParser.addArgument(changePKPWDisplayCommand);

    changePKPWParser.addRequiredArgumentSet(changePKPWKeystorePassword,
         changePKPWKeystorePasswordFile, changePKPWPromptForKeystorePassword);
    changePKPWParser.addExclusiveArgumentSet(changePKPWKeystorePassword,
         changePKPWKeystorePasswordFile, changePKPWPromptForKeystorePassword);
    changePKPWParser.addRequiredArgumentSet(changePKPWCurrentPassword,
         changePKPWCurrentPasswordFile, changePKPWPromptForCurrentPassword);
    changePKPWParser.addExclusiveArgumentSet(changePKPWCurrentPassword,
         changePKPWCurrentPasswordFile, changePKPWPromptForCurrentPassword);
    changePKPWParser.addRequiredArgumentSet(changePKPWNewPassword,
         changePKPWNewPasswordFile, changePKPWPromptForNewPassword);
    changePKPWParser.addExclusiveArgumentSet(changePKPWNewPassword,
         changePKPWNewPasswordFile, changePKPWPromptForNewPassword);

    final LinkedHashMap<String[],String> changePKPWExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    changePKPWExamples.put(
         new String[]
         {
           "change-private-key-password",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert",
           "--current-private-key-password-file",
                getPlatformSpecificPath("config", "current.pin"),
           "--new-private-key-password-file",
                getPlatformSpecificPath("config", "new.pin"),
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "keystore"),
              getPlatformSpecificPath("config", "current.pin"),
              getPlatformSpecificPath("config", "new.pin")));

    final SubCommand changePKPWSubCommand = new SubCommand(
         "change-private-key-password",
         INFO_MANAGE_CERTS_SC_CHANGE_PK_PW_DESC.get(), changePKPWParser,
         changePKPWExamples);
    changePKPWSubCommand.addName("changePrivateKeyPassword", true);
    changePKPWSubCommand.addName("change-private-key-passphrase", true);
    changePKPWSubCommand.addName("changePrivateKeyPassphrase", true);
    changePKPWSubCommand.addName("change-private-key-pin", true);
    changePKPWSubCommand.addName("changePrivateKeyPIN", true);
    changePKPWSubCommand.addName("change-key-password", true);
    changePKPWSubCommand.addName("changeKeyPassword", true);
    changePKPWSubCommand.addName("change-key-passphrase", true);
    changePKPWSubCommand.addName("changeKeyPassphrase", true);
    changePKPWSubCommand.addName("change-key-pin", true);
    changePKPWSubCommand.addName("changeKeyPIN", true);
    changePKPWSubCommand.addName("keypasswd", true);

    parser.addSubCommand(changePKPWSubCommand);


    // Define the "retrieve-server-certificate" subcommand and all of its
    // arguments.
    final ArgumentParser retrieveCertParser = new ArgumentParser(
         "retrieve-server-certificate",
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_DESC.get());

    final StringArgument retrieveCertHostname = new StringArgument('h',
         "hostname", true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_HOST.get(),
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_ARG_HOSTNAME_DESC.get());
    retrieveCertHostname.addLongIdentifier("server-address", true);
    retrieveCertHostname.addLongIdentifier("serverAddress", true);
    retrieveCertHostname.addLongIdentifier("address", true);
    retrieveCertParser.addArgument(retrieveCertHostname);

    final IntegerArgument retrieveCertPort = new IntegerArgument('p',
         "port", true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_PORT.get(),
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_ARG_PORT_DESC.get(), 1, 65_535);
    retrieveCertPort.addLongIdentifier("server-port", true);
    retrieveCertPort.addLongIdentifier("serverPort", true);
    retrieveCertParser.addArgument(retrieveCertPort);

    final BooleanArgument retrieveCertUseStartTLS = new BooleanArgument('q',
         "use-ldap-start-tls", 1,
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_ARG_USE_START_TLS_DESC.get());
    retrieveCertUseStartTLS.addLongIdentifier("use-ldap-starttls", true);
    retrieveCertUseStartTLS.addLongIdentifier("useLDAPStartTLS", true);
    retrieveCertUseStartTLS.addLongIdentifier("use-start-tls", true);
    retrieveCertUseStartTLS.addLongIdentifier("use-starttls", true);
    retrieveCertUseStartTLS.addLongIdentifier("useStartTLS", true);
    retrieveCertParser.addArgument(retrieveCertUseStartTLS);

    final FileArgument retrieveCertOutputFile = new FileArgument(null,
         "output-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_ARG_FILE_DESC.get(), false, true,
         true, false);
    retrieveCertOutputFile.addLongIdentifier("outputFile", true);
    retrieveCertOutputFile.addLongIdentifier("export-file", true);
    retrieveCertOutputFile.addLongIdentifier("exportFile", true);
    retrieveCertOutputFile.addLongIdentifier("certificate-file", true);
    retrieveCertOutputFile.addLongIdentifier("certificateFile", true);
    retrieveCertOutputFile.addLongIdentifier("file", true);
    retrieveCertOutputFile.addLongIdentifier("filename", true);
    retrieveCertParser.addArgument(retrieveCertOutputFile);

    final Set<String> retrieveCertOutputFormatAllowedValues = StaticUtils.setOf(
         "PEM", "text", "txt", "RFC", "DER", "binary", "bin");
    final StringArgument retrieveCertOutputFormat = new StringArgument(null,
         "output-format", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_FORMAT.get(),
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_ARG_FORMAT_DESC.get(),
         retrieveCertOutputFormatAllowedValues, "PEM");
    retrieveCertOutputFormat.addLongIdentifier("outputFormat", true);
    retrieveCertParser.addArgument(retrieveCertOutputFormat);

    final BooleanArgument retrieveCertOnlyPeer = new BooleanArgument(null,
         "only-peer-certificate", 1,
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_ARG_ONLY_PEER_DESC.get());
    retrieveCertOnlyPeer.addLongIdentifier("onlyPeerCertificate", true);
    retrieveCertOnlyPeer.addLongIdentifier("only-peer", true);
    retrieveCertOnlyPeer.addLongIdentifier("onlyPeer", true);
    retrieveCertOnlyPeer.addLongIdentifier("peer-certificate-only", true);
    retrieveCertOnlyPeer.addLongIdentifier("peerCertificateOnly", true);
    retrieveCertOnlyPeer.addLongIdentifier("peer-only", true);
    retrieveCertOnlyPeer.addLongIdentifier("peerOnly", true);
    retrieveCertParser.addArgument(retrieveCertOnlyPeer);

    final BooleanArgument retrieveCertEnableSSLDebugging = new BooleanArgument(
         null, "enableSSLDebugging", 1,
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_ARG_ENABLE_SSL_DEBUGGING_DESC.
              get());
    retrieveCertEnableSSLDebugging.addLongIdentifier("enableTLSDebugging",
         true);
    retrieveCertEnableSSLDebugging.addLongIdentifier("enableStartTLSDebugging",
         true);
    retrieveCertEnableSSLDebugging.addLongIdentifier("enable-ssl-debugging",
         true);
    retrieveCertEnableSSLDebugging.addLongIdentifier("enable-tls-debugging",
         true);
    retrieveCertEnableSSLDebugging.addLongIdentifier(
         "enable-starttls-debugging", true);
    retrieveCertEnableSSLDebugging.addLongIdentifier(
         "enable-start-tls-debugging", true);
    retrieveCertParser.addArgument(retrieveCertEnableSSLDebugging);
    addEnableSSLDebuggingArgument(retrieveCertEnableSSLDebugging);

    final BooleanArgument retrieveCertVerbose = new BooleanArgument(null,
         "verbose", 1,
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_ARG_VERBOSE_DESC.get());
    retrieveCertParser.addArgument(retrieveCertVerbose);

    retrieveCertParser.addDependentArgumentSet(retrieveCertOutputFormat,
         retrieveCertOutputFile);

    final LinkedHashMap<String[],String> retrieveCertExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));
    retrieveCertExamples.put(
         new String[]
         {
           "retrieve-server-certificate",
           "--hostname", "ds.example.com",
           "--port", "636"
         },
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "truststore")));
    retrieveCertExamples.put(
         new String[]
         {
           "retrieve-server-certificate",
           "--hostname", "ds.example.com",
           "--port", "389",
           "--use-ldap-start-tls",
           "--only-peer-certificate",
           "--output-file", "ds-cert.pem",
           "--output-format", "PEM",
           "--verbose"
         },
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_EXAMPLE_2.get(
              getPlatformSpecificPath("config", "truststore")));

    final SubCommand retrieveCertSubCommand = new SubCommand(
         "retrieve-server-certificate",
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_DESC.get(), retrieveCertParser,
         retrieveCertExamples);
    retrieveCertSubCommand.addName("retrieveServerCertificate", true);
    retrieveCertSubCommand.addName("retrieve-certificate", true);
    retrieveCertSubCommand.addName("retrieveCertificate", true);
    retrieveCertSubCommand.addName("get-server-certificate", true);
    retrieveCertSubCommand.addName("getServerCertificate", true);
    retrieveCertSubCommand.addName("get-certificate", true);
    retrieveCertSubCommand.addName("getCertificate", true);
    retrieveCertSubCommand.addName("display-server-certificate", true);
    retrieveCertSubCommand.addName("displayServerCertificate", true);

    parser.addSubCommand(retrieveCertSubCommand);


    // Define the "trust-server-certificate" subcommand and all of its
    // arguments.
    final ArgumentParser trustServerParser = new ArgumentParser(
         "trust-server-certificate",
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_DESC.get());

    final StringArgument trustServerHostname = new StringArgument('h',
         "hostname", true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_HOST.get(),
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_HOSTNAME_DESC.get());
    trustServerHostname.addLongIdentifier("server-address", true);
    trustServerHostname.addLongIdentifier("serverAddress", true);
    trustServerHostname.addLongIdentifier("address", true);
    trustServerParser.addArgument(trustServerHostname);

    final IntegerArgument trustServerPort = new IntegerArgument('p',
         "port", true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_PORT.get(),
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_PORT_DESC.get(), 1, 65_535);
    trustServerPort.addLongIdentifier("server-port", true);
    trustServerPort.addLongIdentifier("serverPort", true);
    trustServerParser.addArgument(trustServerPort);

    final BooleanArgument trustServerUseStartTLS = new BooleanArgument('q',
         "use-ldap-start-tls", 1,
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_USE_START_TLS_DESC.get());
    trustServerUseStartTLS.addLongIdentifier("use-ldap-starttls", true);
    trustServerUseStartTLS.addLongIdentifier("useLDAPStartTLS", true);
    trustServerUseStartTLS.addLongIdentifier("use-start-tls", true);
    trustServerUseStartTLS.addLongIdentifier("use-starttls", true);
    trustServerUseStartTLS.addLongIdentifier("useStartTLS", true);
    trustServerParser.addArgument(trustServerUseStartTLS);

    final FileArgument trustServerKeystore = new FileArgument(null, "keystore",
         true, 1, null, INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_KS_DESC.get(),
         false, true,  true, false);
    trustServerKeystore.addLongIdentifier("keystore-path", true);
    trustServerKeystore.addLongIdentifier("keystorePath", true);
    trustServerKeystore.addLongIdentifier("keystore-file", true);
    trustServerKeystore.addLongIdentifier("keystoreFile", true);
    trustServerParser.addArgument(trustServerKeystore);

    final StringArgument trustServerKeystorePassword = new StringArgument(null,
         "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_KS_PW_DESC.get());
    trustServerKeystorePassword.addLongIdentifier("keystorePassword", true);
    trustServerKeystorePassword.addLongIdentifier("keystore-passphrase", true);
    trustServerKeystorePassword.addLongIdentifier("keystorePassphrase", true);
    trustServerKeystorePassword.addLongIdentifier("keystore-pin", true);
    trustServerKeystorePassword.addLongIdentifier("keystorePIN", true);
    trustServerKeystorePassword.addLongIdentifier("storepass", true);
    trustServerKeystorePassword.setSensitive(true);
    trustServerParser.addArgument(trustServerKeystorePassword);

    final FileArgument trustServerKeystorePasswordFile = new FileArgument(null,
         "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_KS_PW_FILE_DESC.get(), true,
         true, true, false);
    trustServerKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    trustServerKeystorePasswordFile.addLongIdentifier(
         "keystore-passphrase-file", true);
    trustServerKeystorePasswordFile.addLongIdentifier("keystorePassphraseFile",
         true);
    trustServerKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    trustServerKeystorePasswordFile.addLongIdentifier("keystorePINFile", true);
    trustServerParser.addArgument(trustServerKeystorePasswordFile);

    final BooleanArgument trustServerPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_PROMPT_FOR_KS_PW_DESC.get());
    trustServerPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    trustServerPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    trustServerPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    trustServerPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    trustServerPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    trustServerParser.addArgument(trustServerPromptForKeystorePassword);

    final StringArgument trustServerKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    trustServerKeystoreType.addLongIdentifier("keystoreType", true);
    trustServerKeystoreType.addLongIdentifier("storetype", true);
    trustServerParser.addArgument(trustServerKeystoreType);

    final StringArgument trustServerAlias = new StringArgument(null,
         "alias", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_ALIAS_DESC.get());
    trustServerAlias.addLongIdentifier("nickname", true);
    trustServerParser.addArgument(trustServerAlias);

    final BooleanArgument trustServerIssuersOnly = new BooleanArgument(null,
         "issuers-only", 1,
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_ISSUERS_ONLY_DESC.get());
    trustServerIssuersOnly.addLongIdentifier("issuersOnly", true);
    trustServerIssuersOnly.addLongIdentifier("issuer-certificates-only", true);
    trustServerIssuersOnly.addLongIdentifier("issuerCertificatesOnly", true);
    trustServerIssuersOnly.addLongIdentifier("only-issuers", true);
    trustServerIssuersOnly.addLongIdentifier("onlyIssuers", true);
    trustServerIssuersOnly.addLongIdentifier("only-issuer-certificates", true);
    trustServerIssuersOnly.addLongIdentifier("onlyIssuerCertificates", true);
    trustServerParser.addArgument(trustServerIssuersOnly);

    final BooleanArgument trustServerEnableSSLDebugging = new BooleanArgument(
         null, "enableSSLDebugging", 1,
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_ENABLE_SSL_DEBUGGING_DESC.get());
    trustServerEnableSSLDebugging.addLongIdentifier("enableTLSDebugging", true);
    trustServerEnableSSLDebugging.addLongIdentifier("enableStartTLSDebugging",
         true);
    trustServerEnableSSLDebugging.addLongIdentifier("enable-ssl-debugging",
         true);
    trustServerEnableSSLDebugging.addLongIdentifier("enable-tls-debugging",
         true);
    trustServerEnableSSLDebugging.addLongIdentifier("enable-starttls-debugging",
         true);
    trustServerEnableSSLDebugging.addLongIdentifier(
         "enable-start-tls-debugging", true);
    trustServerParser.addArgument(trustServerEnableSSLDebugging);
    addEnableSSLDebuggingArgument(trustServerEnableSSLDebugging);

    final BooleanArgument trustServerVerbose = new BooleanArgument(null,
         "verbose", 1,
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_VERBOSE_DESC.get());
    trustServerParser.addArgument(trustServerVerbose);

    final BooleanArgument trustServerNoPrompt = new BooleanArgument(null,
         "no-prompt", 1,
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_ARG_NO_PROMPT_DESC.get());
    trustServerNoPrompt.addLongIdentifier("noPrompt", true);
    trustServerParser.addArgument(trustServerNoPrompt);

    trustServerParser.addRequiredArgumentSet(trustServerKeystorePassword,
         trustServerKeystorePasswordFile, trustServerPromptForKeystorePassword);
    trustServerParser.addExclusiveArgumentSet(trustServerKeystorePassword,
         trustServerKeystorePasswordFile, trustServerPromptForKeystorePassword);

    final LinkedHashMap<String[],String> trustServerExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));
    trustServerExamples.put(
         new String[]
         {
           "trust-server-certificate",
           "--hostname", "ds.example.com",
           "--port", "636",
           "--keystore", getPlatformSpecificPath("config", "truststore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "truststore.pin"),
           "--verbose"
         },
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "truststore")));
    trustServerExamples.put(
         new String[]
         {
           "trust-server-certificate",
           "--hostname", "ds.example.com",
           "--port", "389",
           "--use-ldap-start-tls",
           "--keystore", getPlatformSpecificPath("config", "truststore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "truststore.pin"),
           "--issuers-only",
           "--alias", "ds-start-tls-cert",
           "--no-prompt"
         },
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_EXAMPLE_2.get(
              getPlatformSpecificPath("config", "truststore")));

    final SubCommand trustServerSubCommand = new SubCommand(
         "trust-server-certificate",
         INFO_MANAGE_CERTS_SC_TRUST_SERVER_DESC.get(), trustServerParser,
         trustServerExamples);
    trustServerSubCommand.addName("trustServerCertificate", true);
    trustServerSubCommand.addName("trust-server", true);
    trustServerSubCommand.addName("trustServer", true);

    parser.addSubCommand(trustServerSubCommand);


    // Define the "check-certificate-usability" subcommand and all of its
    // arguments.
    final ArgumentParser checkUsabilityParser = new ArgumentParser(
         "check-certificate-usability",
         INFO_MANAGE_CERTS_SC_CHECK_USABILITY_DESC.get());

    final FileArgument checkUsabilityKeystore = new FileArgument(null,
         "keystore", true, 1, null,
         INFO_MANAGE_CERTS_SC_CHECK_USABILITY_ARG_KS_DESC.get(),
         true, true,  true, false);
    checkUsabilityKeystore.addLongIdentifier("keystore-path", true);
    checkUsabilityKeystore.addLongIdentifier("keystorePath", true);
    checkUsabilityKeystore.addLongIdentifier("keystore-file", true);
    checkUsabilityKeystore.addLongIdentifier("keystoreFile", true);
    checkUsabilityParser.addArgument(checkUsabilityKeystore);

    final StringArgument checkUsabilityKeystorePassword = new StringArgument(
         null, "keystore-password", false, 1,
         INFO_MANAGE_CERTS_PLACEHOLDER_PASSWORD.get(),
         INFO_MANAGE_CERTS_SC_CHECK_USABILITY_ARG_KS_PW_DESC.get());
    checkUsabilityKeystorePassword.addLongIdentifier("keystorePassword", true);
    checkUsabilityKeystorePassword.addLongIdentifier("keystore-passphrase",
         true);
    checkUsabilityKeystorePassword.addLongIdentifier("keystorePassphrase",
         true);
    checkUsabilityKeystorePassword.addLongIdentifier("keystore-pin", true);
    checkUsabilityKeystorePassword.addLongIdentifier("keystorePIN", true);
    checkUsabilityKeystorePassword.addLongIdentifier("storepass", true);
    checkUsabilityKeystorePassword.setSensitive(true);
    checkUsabilityParser.addArgument(checkUsabilityKeystorePassword);

    final FileArgument checkUsabilityKeystorePasswordFile = new FileArgument(
         null, "keystore-password-file", false, 1, null,
         INFO_MANAGE_CERTS_SC_CHECK_USABILITY_ARG_KS_PW_FILE_DESC.get(), true,
         true, true, false);
    checkUsabilityKeystorePasswordFile.addLongIdentifier("keystorePasswordFile",
         true);
    checkUsabilityKeystorePasswordFile.addLongIdentifier(
         "keystore-passphrase-file", true);
    checkUsabilityKeystorePasswordFile.addLongIdentifier(
         "keystorePassphraseFile", true);
    checkUsabilityKeystorePasswordFile.addLongIdentifier("keystore-pin-file",
         true);
    checkUsabilityKeystorePasswordFile.addLongIdentifier("keystorePINFile",
         true);
    checkUsabilityParser.addArgument(checkUsabilityKeystorePasswordFile);

    final BooleanArgument checkUsabilityPromptForKeystorePassword =
         new BooleanArgument(null, "prompt-for-keystore-password",
        INFO_MANAGE_CERTS_SC_CHECK_USABILITY_ARG_PROMPT_FOR_KS_PW_DESC.get());
    checkUsabilityPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassword", true);
    checkUsabilityPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-passphrase", true);
    checkUsabilityPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePassphrase", true);
    checkUsabilityPromptForKeystorePassword.addLongIdentifier(
         "prompt-for-keystore-pin", true);
    checkUsabilityPromptForKeystorePassword.addLongIdentifier(
         "promptForKeystorePIN", true);
    checkUsabilityParser.addArgument(checkUsabilityPromptForKeystorePassword);

    final StringArgument checkUsabilityKeystoreType = new StringArgument(null,
         "keystore-type", false, 1, INFO_MANAGE_CERTS_PLACEHOLDER_TYPE.get(),
         INFO_MANAGE_CERTS_SC_CHECK_USABILITY_ARG_KS_TYPE_DESC.get(),
         ALLOWED_KEYSTORE_TYPE_VALUES);
    checkUsabilityKeystoreType.addLongIdentifier("keystoreType", true);
    checkUsabilityKeystoreType.addLongIdentifier("storetype", true);
    checkUsabilityParser.addArgument(checkUsabilityKeystoreType);

    final StringArgument checkUsabilityAlias = new StringArgument(null, "alias",
         true, 1, INFO_MANAGE_CERTS_PLACEHOLDER_ALIAS.get(),
         INFO_MANAGE_CERTS_SC_CHECK_USABILITY_ARG_ALIAS_DESC.get());
    checkUsabilityAlias.addLongIdentifier("nickname", true);
    checkUsabilityParser.addArgument(checkUsabilityAlias);

    final BooleanArgument checkUsabilityIgnoreSHA1Signature =
         new BooleanArgument(null,
              "allow-sha-1-signature-for-issuer-certificates", 1,
              INFO_MANAGE_CERTS_SC_CHECK_USABILITY_IGNORE_SHA1_WARNING_DESC.
                   get());
    checkUsabilityIgnoreSHA1Signature.addLongIdentifier(
         "allow-sha1-signature-for-issuer-certificates", true);
    checkUsabilityIgnoreSHA1Signature.addLongIdentifier(
         "allowSHA1SignatureForIssuerCertificates", true);
    checkUsabilityParser.addArgument(checkUsabilityIgnoreSHA1Signature);

    checkUsabilityParser.addRequiredArgumentSet(checkUsabilityKeystorePassword,
         checkUsabilityKeystorePasswordFile,
         checkUsabilityPromptForKeystorePassword);
    checkUsabilityParser.addExclusiveArgumentSet(checkUsabilityKeystorePassword,
         checkUsabilityKeystorePasswordFile,
         checkUsabilityPromptForKeystorePassword);

    final LinkedHashMap<String[],String> checkUsabilityExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));
    checkUsabilityExamples.put(
         new String[]
         {
           "check-certificate-usability",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--keystore-password-file",
                getPlatformSpecificPath("config", "keystore.pin"),
           "--alias", "server-cert"
         },
         INFO_MANAGE_CERTS_SC_CHECK_USABILITY_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "keystore")));

    final SubCommand checkUsabilitySubCommand = new SubCommand(
         "check-certificate-usability",
         INFO_MANAGE_CERTS_SC_CHECK_USABILITY_DESC.get(), checkUsabilityParser,
         checkUsabilityExamples);
    checkUsabilitySubCommand.addName("checkCertificateUsability", true);
    checkUsabilitySubCommand.addName("check-usability", true);
    checkUsabilitySubCommand.addName("checkUsability", true);

    parser.addSubCommand(checkUsabilitySubCommand);


    // Define the "display-certificate-file" subcommand and all of its
    // arguments.
    final ArgumentParser displayCertParser = new ArgumentParser(
         "display-certificate-file",
         INFO_MANAGE_CERTS_SC_DISPLAY_CERT_DESC.get());

    final FileArgument displayCertFile = new FileArgument(null,
         "certificate-file", true, 1, null,
         INFO_MANAGE_CERTS_SC_DISPLAY_CERT_ARG_FILE_DESC.get(), true, true,
         true, false);
    displayCertFile.addLongIdentifier("certificateFile", true);
    displayCertFile.addLongIdentifier("input-file", true);
    displayCertFile.addLongIdentifier("inputFile", true);
    displayCertFile.addLongIdentifier("file", true);
    displayCertFile.addLongIdentifier("filename", true);
    displayCertParser.addArgument(displayCertFile);

    final BooleanArgument displayCertVerbose = new BooleanArgument(null,
         "verbose", 1,
         INFO_MANAGE_CERTS_SC_DISPLAY_CERT_ARG_VERBOSE_DESC.get());
    displayCertParser.addArgument(displayCertVerbose);

    final BooleanArgument displayCertDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_DISPLAY_CERT_ARG_DISPLAY_COMMAND_DESC.get());
    displayCertDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    displayCertDisplayCommand.addLongIdentifier("show-keytool-command", true);
    displayCertDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    displayCertParser.addArgument(displayCertDisplayCommand);

    final LinkedHashMap<String[],String> displayCertExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));
    displayCertExamples.put(
         new String[]
         {
           "display-certificate-file",
           "--certificate-file", "certificate.pem",
         },
         INFO_MANAGE_CERTS_SC_DISPLAY_CERT_EXAMPLE_1.get("certificate.pem"));
    displayCertExamples.put(
         new String[]
         {
           "display-certificate-file",
           "--certificate-file", "certificate.pem",
           "--verbose",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_DISPLAY_CERT_EXAMPLE_2.get("certificate.pem"));

    final SubCommand displayCertSubCommand = new SubCommand(
         "display-certificate-file",
         INFO_MANAGE_CERTS_SC_DISPLAY_CERT_DESC.get(), displayCertParser,
         displayCertExamples);
    displayCertSubCommand.addName("displayCertificateFile", true);
    displayCertSubCommand.addName("display-certificate", true);
    displayCertSubCommand.addName("displayCertificate", true);
    displayCertSubCommand.addName("display-certificates", true);
    displayCertSubCommand.addName("displayCertificates", true);
    displayCertSubCommand.addName("show-certificate", true);
    displayCertSubCommand.addName("showCertificate", true);
    displayCertSubCommand.addName("show-certificate-file", true);
    displayCertSubCommand.addName("showCertificateFile", true);
    displayCertSubCommand.addName("show-certificates", true);
    displayCertSubCommand.addName("showCertificates", true);
    displayCertSubCommand.addName("print-certificate-file", true);
    displayCertSubCommand.addName("printCertificateFile", true);
    displayCertSubCommand.addName("print-certificate", true);
    displayCertSubCommand.addName("printCertificate", true);
    displayCertSubCommand.addName("print-certificates", true);
    displayCertSubCommand.addName("printCertificates", true);
    displayCertSubCommand.addName("printcert", true);

    parser.addSubCommand(displayCertSubCommand);


    // Define the "display-certificate-signing-request-file" subcommand and all
    // of its arguments.
    final ArgumentParser displayCSRParser = new ArgumentParser(
         "display-certificate-signing-request-file",
         INFO_MANAGE_CERTS_SC_DISPLAY_CSR_DESC.get());

    final FileArgument displayCSRFile = new FileArgument(null,
         "certificate-signing-request-file", true, 1, null,
         INFO_MANAGE_CERTS_SC_DISPLAY_CSR_ARG_FILE_DESC.get(), true, true,
         true, false);
    displayCSRFile.addLongIdentifier("certificateSigningRequestFile", true);
    displayCSRFile.addLongIdentifier("request-file", true);
    displayCSRFile.addLongIdentifier("requestFile", true);
    displayCSRFile.addLongIdentifier("input-file", true);
    displayCSRFile.addLongIdentifier("inputFile", true);
    displayCSRFile.addLongIdentifier("file", true);
    displayCSRFile.addLongIdentifier("filename", true);
    displayCSRParser.addArgument(displayCSRFile);

    final BooleanArgument displayCSRVerbose = new BooleanArgument(null,
         "verbose", 1,
         INFO_MANAGE_CERTS_SC_DISPLAY_CSR_ARG_VERBOSE_DESC.get());
    displayCSRParser.addArgument(displayCSRVerbose);

    final BooleanArgument displayCSRDisplayCommand = new BooleanArgument(null,
         "display-keytool-command", 1,
         INFO_MANAGE_CERTS_SC_DISPLAY_CSR_ARG_DISPLAY_COMMAND_DESC.get());
    displayCSRDisplayCommand.addLongIdentifier("displayKeytoolCommand", true);
    displayCSRDisplayCommand.addLongIdentifier("show-keytool-command", true);
    displayCSRDisplayCommand.addLongIdentifier("showKeytoolCommand", true);
    displayCSRParser.addArgument(displayCSRDisplayCommand);

    final LinkedHashMap<String[],String> displayCSRExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    displayCSRExamples.put(
         new String[]
         {
           "display-certificate-signing-request-file",
           "--certificate-signing-request-file", "server-cert.csr",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_DISPLAY_CSR_EXAMPLE_1.get("server-cert.csr"));

    final SubCommand displayCSRSubCommand = new SubCommand(
         "display-certificate-signing-request-file",
         INFO_MANAGE_CERTS_SC_DISPLAY_CSR_DESC.get(), displayCSRParser,
         displayCSRExamples);
    displayCSRSubCommand.addName("displayCertificateSigningRequestFile", true);
    displayCSRSubCommand.addName("display-certificate-signing-request", true);
    displayCSRSubCommand.addName("displayCertificateSigningRequest", true);
    displayCSRSubCommand.addName("display-certificate-request-file", true);
    displayCSRSubCommand.addName("displayCertificateRequestFile", true);
    displayCSRSubCommand.addName("display-certificate-request", true);
    displayCSRSubCommand.addName("displayCertificateRequest", true);
    displayCSRSubCommand.addName("display-csr-file", true);
    displayCSRSubCommand.addName("displayCSRFile", true);
    displayCSRSubCommand.addName("display-csr", true);
    displayCSRSubCommand.addName("displayCSR", true);
    displayCSRSubCommand.addName("show-certificate-signing-request-file", true);
    displayCSRSubCommand.addName("showCertificateSigningRequestFile", true);
    displayCSRSubCommand.addName("show-certificate-signing-request", true);
    displayCSRSubCommand.addName("showCertificateSigningRequest", true);
    displayCSRSubCommand.addName("show-certificate-request-file", true);
    displayCSRSubCommand.addName("showCertificateRequestFile", true);
    displayCSRSubCommand.addName("show-certificate-request", true);
    displayCSRSubCommand.addName("showCertificateRequest", true);
    displayCSRSubCommand.addName("show-csr-file", true);
    displayCSRSubCommand.addName("showCSRFile", true);
    displayCSRSubCommand.addName("show-csr", true);
    displayCSRSubCommand.addName("showCSR", true);
    displayCSRSubCommand.addName("print-certificate-signing-request-file",
         true);
    displayCSRSubCommand.addName("printCertificateSigningRequestFile", true);
    displayCSRSubCommand.addName("print-certificate-signing-request", true);
    displayCSRSubCommand.addName("printCertificateSigningRequest", true);
    displayCSRSubCommand.addName("print-certificate-request-file", true);
    displayCSRSubCommand.addName("printCertificateRequestFile", true);
    displayCSRSubCommand.addName("print-certificate-request", true);
    displayCSRSubCommand.addName("printCertificateRequest", true);
    displayCSRSubCommand.addName("print-csr-file", true);
    displayCSRSubCommand.addName("printCSRFile", true);
    displayCSRSubCommand.addName("print-csr", true);
    displayCSRSubCommand.addName("printCSR", true);
    displayCSRSubCommand.addName("printcertreq", true);

    parser.addSubCommand(displayCSRSubCommand);
  }



  /**
   * Constructs a platform-specific relative path from the provided elements.
   *
   * @param  pathElements  The elements of the path to construct.  It must not
   *                       be {@code null} or empty.
   *
   * @return  The constructed path.
   */
  @NotNull()
  private static String getPlatformSpecificPath(
                             @NotNull final String... pathElements)
  {
    final StringBuilder buffer = new StringBuilder();
    for (int i=0; i < pathElements.length; i++)
    {
      if (i > 0)
      {
        buffer.append(File.separatorChar);
      }

      buffer.append(pathElements[i]);
    }

    return buffer.toString();
  }



  /**
   * Performs the core set of processing for this tool.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    final SubCommand selectedSubCommand = globalParser.getSelectedSubCommand();
    if (selectedSubCommand == null)
    {
      // This should never happen.
      wrapErr(0, WRAP_COLUMN, ERR_MANAGE_CERTS_NO_SUBCOMMAND.get());
      return ResultCode.PARAM_ERROR;
    }

    subCommandParser = selectedSubCommand.getArgumentParser();

    if (selectedSubCommand.hasName("list-certificates"))
    {
      return doListCertificates();
    }
    else if (selectedSubCommand.hasName("export-certificate"))
    {
      return doExportCertificate();
    }
    else if (selectedSubCommand.hasName("export-private-key"))
    {
      return doExportPrivateKey();
    }
    else if (selectedSubCommand.hasName("import-certificate"))
    {
      return doImportCertificate();
    }
    else if (selectedSubCommand.hasName("delete-certificate"))
    {
      return doDeleteCertificate();
    }
    else if (selectedSubCommand.hasName("generate-self-signed-certificate"))
    {
      return doGenerateOrSignCertificateOrCSR();
    }
    else if (selectedSubCommand.hasName("generate-certificate-signing-request"))
    {
      return doGenerateOrSignCertificateOrCSR();
    }
    else if (selectedSubCommand.hasName("sign-certificate-signing-request"))
    {
      return doGenerateOrSignCertificateOrCSR();
    }
    else if (selectedSubCommand.hasName("change-certificate-alias"))
    {
      return doChangeCertificateAlias();
    }
    else if (selectedSubCommand.hasName("change-keystore-password"))
    {
      return doChangeKeystorePassword();
    }
    else if (selectedSubCommand.hasName("change-private-key-password"))
    {
      return doChangePrivateKeyPassword();
    }
    else if (selectedSubCommand.hasName("retrieve-server-certificate"))
    {
      return doRetrieveServerCertificate();
    }
    else if (selectedSubCommand.hasName("trust-server-certificate"))
    {
      return doTrustServerCertificate();
    }
    else if (selectedSubCommand.hasName("check-certificate-usability"))
    {
      return doCheckCertificateUsability();
    }
    else if (selectedSubCommand.hasName("display-certificate-file"))
    {
      return doDisplayCertificateFile();
    }
    else if (selectedSubCommand.hasName(
         "display-certificate-signing-request-file"))
    {
      return doDisplayCertificateSigningRequestFile();
    }
    else
    {
      // This should never happen.
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_UNKNOWN_SUBCOMMAND.get(
                selectedSubCommand.getPrimaryName()));
      return ResultCode.PARAM_ERROR;
    }
  }



  /**
   * Performs the necessary processing for the list-certificates subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doListCertificates()
  {
    // Get the values of a number of configured arguments.
    final BooleanArgument displayPEMArgument =
         subCommandParser.getBooleanArgument("display-pem-certificate");
    final boolean displayPEM =
         ((displayPEMArgument != null) && displayPEMArgument.isPresent());

    final BooleanArgument verboseArgument =
         subCommandParser.getBooleanArgument("verbose");
    final boolean verbose =
         ((verboseArgument != null) && verboseArgument.isPresent());

    final Map<String,String> missingAliases;
    final Set<String> aliases;
    final StringArgument aliasArgument =
         subCommandParser.getStringArgument("alias");
    if ((aliasArgument == null) || (! aliasArgument.isPresent()))
    {
      aliases = Collections.emptySet();
      missingAliases = Collections.emptyMap();
    }
    else
    {
      final List<String> values = aliasArgument.getValues();
      aliases = new LinkedHashSet<>(StaticUtils.computeMapCapacity(
           values.size()));
      missingAliases =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(values.size()));
      for (final String alias : values)
      {
        final String lowerAlias = StaticUtils.toLowerCase(alias);
        aliases.add(StaticUtils.toLowerCase(lowerAlias));
        missingAliases.put(lowerAlias, alias);
      }
    }

    final String keystoreType;
    final File keystorePath = getKeystorePath();
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    if ((displayKeytoolCommandArgument != null) &&
        displayKeytoolCommandArgument.isPresent())
    {
      final ArrayList<String> keytoolArgs = new ArrayList<>(10);
      keytoolArgs.add("-list");

      keytoolArgs.add("-keystore");
      keytoolArgs.add(keystorePath.getAbsolutePath());
      keytoolArgs.add("-storetype");
      keytoolArgs.add(keystoreType);

      if (keystorePassword != null)
      {
        keytoolArgs.add("-storepass");
        keytoolArgs.add("*****REDACTED*****");
      }

      for (final String alias : missingAliases.values())
      {
        keytoolArgs.add("-alias");
        keytoolArgs.add(alias);
      }

      if (displayPEM)
      {
        keytoolArgs.add("-rfc");
      }

      if (verbose)
      {
        keytoolArgs.add("-v");
      }

      displayKeytoolCommand(keytoolArgs);
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Iterate through the keystore and display the appropriate certificates.
    final Enumeration<String> aliasEnumeration;
    try
    {
      aliasEnumeration = keystore.aliases();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      err();
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_LIST_CERTS_CANNOT_GET_ALIASES.get(
                keystorePath.getAbsolutePath()));
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }

    int listedCount = 0;
    ResultCode resultCode = ResultCode.SUCCESS;
    while (aliasEnumeration.hasMoreElements())
    {
      final String alias = aliasEnumeration.nextElement();
      final String lowerAlias = StaticUtils.toLowerCase(alias);
      if ((!aliases.isEmpty()) && (missingAliases.remove(lowerAlias) == null))
      {
        // We don't care about this alias.
        continue;
      }

      final X509Certificate[] certificateChain;
      try
      {
        // NOTE:  Keystore entries that have private keys may have a certificate
        // chain associated with them (the end certificate plus all of the
        // issuer certificates).  In that case all of those certificates in the
        // chain will be stored under the same alias, and the only way we can
        // access them is to call the getCertificateChain method.  However, if
        // the keystore only has a certificate for the alias but no private key,
        // then the entry will not have a chain, and the call to
        // getCertificateChain will return null for that alias.  We want to be
        // able to handle both of these cases, so we will first try
        // getCertificateChain to see if we can get a complete chain, but if
        // that returns null, then use getCertificate to see if we can get a
        // single certificate.  That call to getCertificate can also return null
        // because the entry with this alias might be some other type of entry,
        // like a secret key entry.
        Certificate[] chain = keystore.getCertificateChain(alias);
        if ((chain == null) || (chain.length == 0))
        {
          final Certificate cert = keystore.getCertificate(alias);
          if (cert == null)
          {
            continue;
          }
          else
          {
            chain = new Certificate[] { cert };
          }
        }

        certificateChain = new X509Certificate[chain.length];
        for (int i = 0; i < chain.length; i++)
        {
          certificateChain[i] = new X509Certificate(chain[i].getEncoded());
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err();
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_LIST_CERTS_ERROR_GETTING_CERT.get(alias,
                  StaticUtils.getExceptionMessage(e)));
        resultCode = ResultCode.LOCAL_ERROR;
        continue;
      }

      listedCount++;
      for (int i = 0; i < certificateChain.length; i++)
      {
        out();
        if (certificateChain.length == 1)
        {
          out(INFO_MANAGE_CERTS_LIST_CERTS_LABEL_ALIAS_WITHOUT_CHAIN.get(
               alias));
        }
        else
        {
          out(INFO_MANAGE_CERTS_LIST_CERTS_LABEL_ALIAS_WITH_CHAIN.get(alias,
               (i + 1), certificateChain.length));
        }

        printCertificate(certificateChain[i], "", verbose);

        if (i == 0)
        {
          if (hasKeyAlias(keystore, alias))
          {
            out(INFO_MANAGE_CERTS_LIST_CERTS_LABEL_HAS_PK_YES.get());
          }
          else
          {
            out(INFO_MANAGE_CERTS_LIST_CERTS_LABEL_HAS_PK_NO.get());
          }
        }

        CertException signatureVerificationException = null;
        if (certificateChain[i].isSelfSigned())
        {
          try
          {
            certificateChain[i].verifySignature(null);
          }
          catch (final CertException ce)
          {
            Debug.debugException(ce);
            signatureVerificationException = ce;
          }
        }
        else
        {
          X509Certificate issuerCertificate = null;
          try
          {
            final AtomicReference<KeyStore> jvmDefaultTrustStoreRef =
                 new AtomicReference<>();
            final AtomicReference<DN> missingIssuerRef =
                 new AtomicReference<>();
            issuerCertificate = getIssuerCertificate(certificateChain[i],
                 keystore, jvmDefaultTrustStoreRef, missingIssuerRef);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }

          if (issuerCertificate == null)
          {
            signatureVerificationException = new CertException(
                 ERR_MANAGE_CERTS_LIST_CERTS_VERIFY_SIGNATURE_NO_ISSUER.get(
                      certificateChain[i].getIssuerDN()));
          }
          else
          {
            try
            {
              certificateChain[i].verifySignature(issuerCertificate);
            }
            catch (final CertException ce)
            {
              Debug.debugException(ce);
              signatureVerificationException = ce;
            }
          }
        }

        if (signatureVerificationException == null)
        {
          wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_LIST_CERTS_SIGNATURE_VALID.get());
        }
        else
        {
          wrapErr(0, WRAP_COLUMN,
               signatureVerificationException.getMessage());
        }

        if (displayPEM)
        {
          out(INFO_MANAGE_CERTS_LIST_CERTS_LABEL_PEM.get());
          writePEMCertificate(getOut(),
               certificateChain[i].getX509CertificateBytes());
        }
      }
    }

    if (! missingAliases.isEmpty())
    {
      err();
      for (final String missingAlias : missingAliases.values())
      {
        wrapErr(0, WRAP_COLUMN,
             WARN_MANAGE_CERTS_LIST_CERTS_ALIAS_NOT_IN_KS.get(missingAlias,
                  keystorePath.getAbsolutePath()));
        resultCode = ResultCode.PARAM_ERROR;
      }
    }
    else if (listedCount == 0)
    {
      out();
      if (keystorePassword == null)
      {
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_LIST_CERTS_NO_CERTS_OR_KEYS_WITHOUT_PW.get());
      }
      else
      {
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_LIST_CERTS_NO_CERTS_OR_KEYS_WITH_PW.get());
      }
    }

    return resultCode;
  }



  /**
   * Performs the necessary processing for the export-certificate subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doExportCertificate()
  {
    // Get the values of a number of configured arguments.
    final StringArgument aliasArgument =
         subCommandParser.getStringArgument("alias");
    final String alias = aliasArgument.getValue();

    final BooleanArgument exportChainArgument =
         subCommandParser.getBooleanArgument("export-certificate-chain");
    final boolean exportChain =
         ((exportChainArgument != null) && exportChainArgument.isPresent());

    final BooleanArgument separateFilePerCertificateArgument =
         subCommandParser.getBooleanArgument("separate-file-per-certificate");
    final boolean separateFilePerCertificate =
         ((separateFilePerCertificateArgument != null) &&
          separateFilePerCertificateArgument.isPresent());

    boolean exportPEM = true;
    final StringArgument outputFormatArgument =
         subCommandParser.getStringArgument("output-format");
    if ((outputFormatArgument != null) && outputFormatArgument.isPresent())
    {
      final String format = outputFormatArgument.getValue().toLowerCase();
      if (format.equals("der") || format.equals("binary") ||
          format.equals("bin"))
      {
        exportPEM = false;
      }
    }

    File outputFile = null;
    final FileArgument outputFileArgument =
         subCommandParser.getFileArgument("output-file");
    if ((outputFileArgument != null) && outputFileArgument.isPresent())
    {
      outputFile = outputFileArgument.getValue();
    }

    if ((outputFile == null) && (! exportPEM))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_EXPORT_CERT_NO_FILE_WITH_DER.get());
      return ResultCode.PARAM_ERROR;
    }

    final String keystoreType;
    final File keystorePath = getKeystorePath();
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    if ((displayKeytoolCommandArgument != null) &&
        displayKeytoolCommandArgument.isPresent())
    {
      final ArrayList<String> keytoolArgs = new ArrayList<>(10);
      keytoolArgs.add("-list");

      keytoolArgs.add("-keystore");
      keytoolArgs.add(keystorePath.getAbsolutePath());
      keytoolArgs.add("-storetype");
      keytoolArgs.add(keystoreType);

      if (keystorePassword != null)
      {
        keytoolArgs.add("-storepass");
        keytoolArgs.add("*****REDACTED*****");
      }

      keytoolArgs.add("-alias");
      keytoolArgs.add(alias);

      if (exportPEM)
      {
        keytoolArgs.add("-rfc");
      }

      if (outputFile != null)
      {
        keytoolArgs.add("-file");
        keytoolArgs.add(outputFile.getAbsolutePath());
      }

      displayKeytoolCommand(keytoolArgs);
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the certificates to export.  If the --export-certificate-chain
    // argument was provided, this can be multiple certificates.  Otherwise, it
    // there will only be one.
    DN missingIssuerDN = null;
    final X509Certificate[] certificatesToExport;
    if (exportChain)
    {
      try
      {
        final AtomicReference<DN> missingIssuerRef = new AtomicReference<>();
        certificatesToExport =
             getCertificateChain(alias, keystore, missingIssuerRef);
        missingIssuerDN = missingIssuerRef.get();
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        wrapErr(0, WRAP_COLUMN, le.getMessage());
        return le.getResultCode();
      }
    }
    else
    {
      try
      {
        final Certificate cert = keystore.getCertificate(alias);
        if (cert == null)
        {
          certificatesToExport = new X509Certificate[0];
        }
        else
        {
          certificatesToExport = new X509Certificate[]
          {
            new X509Certificate(cert.getEncoded())
          };
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_EXPORT_CERT_ERROR_GETTING_CERT.get(alias,
                  keystorePath.getAbsolutePath()));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }
    }

    if (certificatesToExport.length == 0)
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_EXPORT_CERT_NO_CERT_WITH_ALIAS.get(alias,
                keystorePath.getAbsolutePath()));
      return ResultCode.PARAM_ERROR;
    }


    // Get a PrintStream to use for the output.
    int fileCounter = 1;
    String filename = null;
    PrintStream printStream;
    if (outputFile == null)
    {
      printStream = getOut();
    }
    else
    {
      try
      {
        if ((certificatesToExport.length > 1) && separateFilePerCertificate)
        {
          filename = outputFile.getAbsolutePath() + '.' + fileCounter;
        }
        else
        {
          filename = outputFile.getAbsolutePath();
        }
        printStream = new PrintStream(filename);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_EXPORT_CERT_ERROR_OPENING_OUTPUT.get(
                  outputFile.getAbsolutePath()));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }
    }

    try
    {
      for (final X509Certificate certificate : certificatesToExport)
      {
        try
        {
          if (separateFilePerCertificate && (certificatesToExport.length > 1))
          {
            if (fileCounter > 1)
            {
              printStream.close();
              filename = outputFile.getAbsolutePath() + '.' + fileCounter;
              printStream = new PrintStream(filename);
            }

            fileCounter++;
          }

          if (exportPEM)
          {
            writePEMCertificate(printStream,
                 certificate.getX509CertificateBytes());
          }
          else
          {
            printStream.write(certificate.getX509CertificateBytes());
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_EXPORT_CERT_ERROR_WRITING_CERT.get(alias,
                    certificate.getSubjectDN()));
          e.printStackTrace(getErr());
          return ResultCode.LOCAL_ERROR;
        }

        if (outputFile != null)
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_EXPORT_CERT_EXPORT_SUCCESSFUL.get(filename));
          printCertificate(certificate, "", false);
        }
      }
    }
    finally
    {
      printStream.flush();
      if (outputFile != null)
      {
        printStream.close();
      }
    }

    if (missingIssuerDN != null)
    {
      err();
      wrapErr(0, WRAP_COLUMN,
           WARN_MANAGE_CERTS_EXPORT_CERT_MISSING_CERT_IN_CHAIN.get(
                missingIssuerDN, keystorePath.getAbsolutePath()));
      return ResultCode.NO_SUCH_OBJECT;
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the export-private-key subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doExportPrivateKey()
  {
    // Get the values of a number of configured arguments.
    final StringArgument aliasArgument =
         subCommandParser.getStringArgument("alias");
    final String alias = aliasArgument.getValue();

    boolean exportPEM = true;
    final StringArgument outputFormatArgument =
         subCommandParser.getStringArgument("output-format");
    if ((outputFormatArgument != null) && outputFormatArgument.isPresent())
    {
      final String format = outputFormatArgument.getValue().toLowerCase();
      if (format.equals("der") || format.equals("binary") ||
          format.equals("bin"))
      {
        exportPEM = false;
      }
    }

    File outputFile = null;
    final FileArgument outputFileArgument =
         subCommandParser.getFileArgument("output-file");
    if ((outputFileArgument != null) && outputFileArgument.isPresent())
    {
      outputFile = outputFileArgument.getValue();
    }

    if ((outputFile == null) && (! exportPEM))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_EXPORT_KEY_NO_FILE_WITH_DER.get());
      return ResultCode.PARAM_ERROR;
    }

    final String keystoreType;
    final File keystorePath = getKeystorePath();
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // See if we need to use a private key password that is different from the
    // keystore password.
    final char[] privateKeyPassword;
    try
    {
      privateKeyPassword =
           getPrivateKeyPassword(keystore, alias, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the private key to export.
    final PrivateKey privateKey;
    try
    {
      final Key key = keystore.getKey(alias, privateKeyPassword);
      if (key == null)
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_EXPORT_KEY_NO_KEY_WITH_ALIAS.get(alias,
                  keystorePath.getAbsolutePath()));
        return ResultCode.PARAM_ERROR;
      }

      privateKey = (PrivateKey) key;
    }
    catch (final UnrecoverableKeyException e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_EXPORT_KEY_WRONG_KEY_PW.get(alias,
                keystorePath.getAbsolutePath()));
      return ResultCode.PARAM_ERROR;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_EXPORT_KEY_ERROR_GETTING_KEY.get(alias,
                keystorePath.getAbsolutePath()));
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }


    // Get a PrintStream to use for the output.
    final PrintStream printStream;
    if (outputFile == null)
    {
      printStream = getOut();
    }
    else
    {
      try
      {
        printStream = new PrintStream(outputFile);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_EXPORT_KEY_ERROR_OPENING_OUTPUT.get(
                  outputFile.getAbsolutePath()));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }
    }

    try
    {
      try
      {
        if (exportPEM)
        {
          writePEMPrivateKey(printStream, privateKey.getEncoded());
        }
        else
        {
          printStream.write(privateKey.getEncoded());
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_EXPORT_KEY_ERROR_WRITING_KEY.get(alias));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }

      if (outputFile != null)
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_EXPORT_KEY_EXPORT_SUCCESSFUL.get());
      }
    }
    finally
    {
      printStream.flush();
      if (outputFile != null)
      {
        printStream.close();
      }
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the import-certificate subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doImportCertificate()
  {
    // Get the values of a number of configured arguments.
    final StringArgument aliasArgument =
         subCommandParser.getStringArgument("alias");
    final String alias = aliasArgument.getValue();

    final FileArgument certificateFileArgument =
         subCommandParser.getFileArgument("certificate-file");
    final List<File> certFiles = certificateFileArgument.getValues();

    final File privateKeyFile;
    final FileArgument privateKeyFileArgument =
         subCommandParser.getFileArgument("private-key-file");
    if ((privateKeyFileArgument != null) && privateKeyFileArgument.isPresent())
    {
      privateKeyFile = privateKeyFileArgument.getValue();
    }
    else
    {
      privateKeyFile = null;
    }

    final BooleanArgument noPromptArgument =
         subCommandParser.getBooleanArgument("no-prompt");
    final boolean noPrompt =
         ((noPromptArgument != null) && noPromptArgument.isPresent());

    final String keystoreType;
    final File keystorePath = getKeystorePath();
    final boolean isNewKeystore = (! keystorePath.exists());
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Read the contents of the certificate files.
    final ArrayList<X509Certificate> certList = new ArrayList<>(5);
    for (final File certFile : certFiles)
    {
      try
      {
        final List<X509Certificate> certs = readCertificatesFromFile(certFile);
        if (certs.isEmpty())
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_IMPORT_CERT_NO_CERTS_IN_FILE.get(
                    certFile.getAbsolutePath()));
          return ResultCode.PARAM_ERROR;
        }

        certList.addAll(certs);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        wrapErr(0, WRAP_COLUMN, le.getMessage());
        return le.getResultCode();
      }
    }


    // If a private key file was specified, then read the private key.
    final PKCS8PrivateKey privateKey;
    if (privateKeyFile == null)
    {
      privateKey = null;
    }
    else
    {
      try
      {
        privateKey = readPrivateKeyFromFile(privateKeyFile);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        wrapErr(0, WRAP_COLUMN, le.getMessage());
        return le.getResultCode();
      }
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // If there is a private key, then see if we need to use a private key
    // password that is different from the keystore password.
    final char[] privateKeyPassword;
    try
    {
      privateKeyPassword =
           getPrivateKeyPassword(keystore, alias, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // If we should display an equivalent keytool command, then do that now.
    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    if ((displayKeytoolCommandArgument != null) &&
        displayKeytoolCommandArgument.isPresent())
    {
      final ArrayList<String> keytoolArgs = new ArrayList<>(10);
      keytoolArgs.add("-import");

      keytoolArgs.add("-keystore");
      keytoolArgs.add(keystorePath.getAbsolutePath());
      keytoolArgs.add("-storetype");
      keytoolArgs.add(keystoreType);
      keytoolArgs.add("-storepass");
      keytoolArgs.add("*****REDACTED*****");
      keytoolArgs.add("-keypass");
      keytoolArgs.add("*****REDACTED*****");
      keytoolArgs.add("-alias");
      keytoolArgs.add(alias);
      keytoolArgs.add("-file");
      keytoolArgs.add(certFiles.get(0).getAbsolutePath());
      keytoolArgs.add("-trustcacerts");

      displayKeytoolCommand(keytoolArgs);
    }


    // Look at all the certificates to be imported.  Make sure that every
    // subsequent certificate in the chain is the issuer for the previous.
    final Iterator<X509Certificate> certIterator = certList.iterator();
    X509Certificate subjectCert = certIterator.next();
    while (true)
    {
      if (subjectCert.isSelfSigned())
      {
        if (certIterator.hasNext())
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_IMPORT_CERT_SELF_SIGNED_NOT_LAST.get(
                    subjectCert.getSubjectDN()));
          return ResultCode.PARAM_ERROR;
        }
      }

      if (! certIterator.hasNext())
      {
        break;
      }

      final X509Certificate issuerCert = certIterator.next();
      final StringBuilder notIssuerReason = new StringBuilder();
      if (! issuerCert.isIssuerFor(subjectCert, notIssuerReason))
      {
        // In some cases, the process of signing a certificate can put two
        // certificates in the output file (both the signed certificate and its
        // issuer.  If the same certificate is in the chain twice, then we'll
        // silently ignore it.
        if (Arrays.equals(issuerCert.getX509CertificateBytes(),
                 subjectCert.getX509CertificateBytes()))
        {
          certIterator.remove();
        }
        else
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_IMPORT_CERT_NEXT_NOT_ISSUER_OF_PREV.get(
                    notIssuerReason.toString()));
          return ResultCode.PARAM_ERROR;
        }
      }

      subjectCert = issuerCert;
    }


    // If the last certificate in the chain is not self-signed, then make sure
    // that we can complete the chain using other certificates in the keystore
    // or in the JVM's set of default trusted issuers.  If we can't complete
    // the chain, then that's an error, although we'll go ahead and proceed
    // anyway with the import if we're not also importing a private key.
    final ArrayList<X509Certificate> chain;
    if (certList.get(certList.size() - 1).isSelfSigned())
    {
      chain = certList;
    }
    else
    {
      chain = new ArrayList<>(certList.size() + 5);
      chain.addAll(certList);

      final AtomicReference<KeyStore> jvmDefaultTrustStoreRef =
           new AtomicReference<>();
      final AtomicReference<DN> missingIssuerRef = new AtomicReference<>();

      X509Certificate c = certList.get(certList.size() - 1);
      while (! c.isSelfSigned())
      {
        final X509Certificate issuer;
        try
        {
          issuer = getIssuerCertificate(c, keystore, jvmDefaultTrustStoreRef,
               missingIssuerRef);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_IMPORT_CERT_CANNOT_GET_ISSUER.get(
                    c.getIssuerDN()));
          e.printStackTrace(getErr());
          return ResultCode.LOCAL_ERROR;
        }

        if (issuer == null)
        {
          final byte[] authorityKeyIdentifier = getAuthorityKeyIdentifier(c);

          // We couldn't find the issuer certificate.  If we're importing a
          // private key, or if the keystore already has a key entry with the
          // same alias that we're going to use, then this is definitely an
          // error because we can only write a key entry if we have a complete
          // certificate chain.
          //
          // If we weren't explicitly provided with a private key, then it's
          // still an undesirable thing to import a certificate without having
          // the complete set of issuers, but we'll go ahead and let it slide
          // with just a warning.
          if ((privateKey != null) || hasKeyAlias(keystore, alias))
          {
            if (authorityKeyIdentifier == null)
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   ERR_MANAGE_CERTS_IMPORT_CERT_NO_ISSUER_NO_AKI.get(
                        c.getIssuerDN()));
            }
            else
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   ERR_MANAGE_CERTS_IMPORT_CERT_NO_ISSUER_WITH_AKI.get(
                        c.getIssuerDN(),
                        toColonDelimitedHex(authorityKeyIdentifier)));
            }

            return ResultCode.PARAM_ERROR;
          }
          else
          {
            if (authorityKeyIdentifier == null)
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   WARN_MANAGE_CERTS_IMPORT_CERT_NO_ISSUER_NO_AKI.get(
                        c.getIssuerDN()));
            }
            else
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   WARN_MANAGE_CERTS_IMPORT_CERT_NO_ISSUER_WITH_AKI.get(
                        c.getIssuerDN(),
                        toColonDelimitedHex(authorityKeyIdentifier)));
            }

            break;
          }
        }
        else
        {
          chain.add(issuer);
          c = issuer;
        }
      }
    }


    // If we're going to import a private key with a certificate chain, then
    // perform the necessary validation and do the import.
    if (privateKey != null)
    {
      // Make sure that the keystore doesn't already have a key or certificate
      // with the specified alias.
      if (hasKeyAlias(keystore, alias))
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_WITH_PK_KEY_ALIAS_CONFLICT.get(
                  alias));
        return ResultCode.PARAM_ERROR;
      }
      else if (hasCertificateAlias(keystore, alias))
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_WITH_PK_CERT_ALIAS_CONFLICT.get(
                  alias));
        return ResultCode.PARAM_ERROR;
      }


      // Make sure that the private key has a key algorithm of either RSA or EC,
      // and convert it into a Java PrivateKey object.
      final PrivateKey javaPrivateKey;
      try
      {
        javaPrivateKey = privateKey.toPrivateKey();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_ERROR_CONVERTING_KEY.get(
                  privateKeyFile.getAbsolutePath()));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }


      // Convert the certificate chain into a Java Certificate[].
      final Certificate[] javaCertificateChain = new Certificate[chain.size()];
      for (int i=0; i < javaCertificateChain.length; i++)
      {
        final X509Certificate c = chain.get(i);
        try
        {
          javaCertificateChain[i] = c.toCertificate();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_IMPORT_CERT_ERROR_CONVERTING_CERT.get(
                    c.getSubjectDN()));
          e.printStackTrace(getErr());
          return ResultCode.LOCAL_ERROR;
        }
      }


      // Prompt the user to confirm the import, if appropriate.
      if (! noPrompt)
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_IMPORT_CERT_CONFIRM_IMPORT_CHAIN_NEW_KEY.get(
                  alias));

        for (final X509Certificate c : chain)
        {
          out();
          printCertificate(c, "", false);
        }

        out();

        try
        {
          if (! promptForYesNo(
               INFO_MANAGE_CERTS_IMPORT_CERT_PROMPT_IMPORT_CHAIN.get()))
          {
            wrapErr(0, WRAP_COLUMN,
                 ERR_MANAGE_CERTS_IMPORT_CERT_CANCELED.get());
            return ResultCode.USER_CANCELED;
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          err();
          wrapErr(0, WRAP_COLUMN, le.getMessage());
          return le.getResultCode();
        }
      }


      // Set the private key entry in the keystore.
      try
      {
        keystore.setKeyEntry(alias, javaPrivateKey, privateKeyPassword,
             javaCertificateChain);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_ERROR_UPDATING_KS_WITH_CHAIN.get(
                  alias));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }


      // Write the updated keystore to disk.
      try
      {
        writeKeystore(keystore, keystorePath, keystorePassword);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        wrapErr(0, WRAP_COLUMN, le.getMessage());
        return le.getResultCode();
      }

      if (isNewKeystore)
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_IMPORT_CERT_CREATED_KEYSTORE.get(
                  getUserFriendlyKeystoreType(keystoreType)));
      }

      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_IMPORT_CERT_IMPORTED_CHAIN_WITH_PK.get());
      return ResultCode.SUCCESS;
    }


    // If we've gotten here, then we were given one or more certificates but no
    // private key.  See if the keystore already has a certificate entry with
    // the specified alias.  If so, then that's always an error.
    if (hasCertificateAlias(keystore, alias))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_IMPORT_CERT_WITH_CONFLICTING_CERT_ALIAS.get(alias));
      return ResultCode.PARAM_ERROR;
    }


    // See if the keystore already has a key entry with the specified alias.
    // If so, then it may or may not be an error.  This can happen if we
    // generated a certificate signing request from an existing key pair, and
    // now want to import the signed certificate.  If that is the case, then we
    // will replace the existing key entry with a new one that contains the full
    // new certificate chain and the existing private key, but only if the
    // new certificate uses the same public key as the certificate at the head
    // of the existing chain in that alias.
    if (hasKeyAlias(keystore, alias))
    {
      // Make sure that the existing key pair uses the same public key as the
      // new certificate we are importing.
      final PrivateKey existingPrivateKey;
      final Certificate[] existingChain;
      final X509Certificate existingEndCertificate;
      try
      {
        existingPrivateKey =
             (PrivateKey) keystore.getKey(alias, privateKeyPassword);
        existingChain = keystore.getCertificateChain(alias);
        existingEndCertificate =
             new X509Certificate(existingChain[0].getEncoded());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_INTO_KEY_ALIAS_CANNOT_GET_KEY.get(
                  alias));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }

      final boolean[] existingPublicKeyBits =
           existingEndCertificate.getEncodedPublicKey().getBits();
      final boolean[] newPublicKeyBits =
           chain.get(0).getEncodedPublicKey().getBits();
      if (! Arrays.equals(existingPublicKeyBits, newPublicKeyBits))
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_INTO_KEY_ALIAS_KEY_MISMATCH.get(
                  alias));
        return ResultCode.PARAM_ERROR;
      }


      // Prepare the new certificate chain to store in the alias.
      final Certificate[] newChain = new Certificate[chain.size()];
      for (int i=0; i < chain.size(); i++)
      {
        final X509Certificate c = chain.get(i);
        try
        {
          newChain[i] = c.toCertificate();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_IMPORT_CERT_ERROR_CONVERTING_CERT.get(
                    c.getSubjectDN()));
          e.printStackTrace(getErr());
          return ResultCode.LOCAL_ERROR;
        }
      }


      // Prompt the user to confirm the import, if appropriate.
      if (! noPrompt)
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_IMPORT_CERT_CONFIRM_IMPORT_CHAIN_EXISTING_KEY.
                  get(alias));

        for (final X509Certificate c : chain)
        {
          out();
          printCertificate(c, "", false);
        }

        out();

        try
        {
          if (! promptForYesNo(
               INFO_MANAGE_CERTS_IMPORT_CERT_PROMPT_IMPORT_CHAIN.get()))
          {
            wrapErr(0, WRAP_COLUMN,
                 ERR_MANAGE_CERTS_IMPORT_CERT_CANCELED.get());
            return ResultCode.USER_CANCELED;
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          err();
          wrapErr(0, WRAP_COLUMN, le.getMessage());
          return le.getResultCode();
        }
      }


      // Set the private key entry in the keystore.
      try
      {
        keystore.setKeyEntry(alias, existingPrivateKey, privateKeyPassword,
             newChain);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_ERROR_UPDATING_KS_WITH_CHAIN.get(
                  alias));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }


      // Write the updated keystore to disk.
      try
      {
        writeKeystore(keystore, keystorePath, keystorePassword);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        wrapErr(0, WRAP_COLUMN, le.getMessage());
        return le.getResultCode();
      }

      out();

      if (isNewKeystore)
      {
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_IMPORT_CERT_CREATED_KEYSTORE.get(
                  getUserFriendlyKeystoreType(keystoreType)));
      }

      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_IMPORT_CERT_IMPORTED_CHAIN_WITHOUT_PK.get());
      return ResultCode.SUCCESS;
    }


    // If we've gotten here, then we know that we're just going to add
    // certificate entries to the keystore.  Iterate through the certificates
    // and add them to the keystore under the appropriate aliases, first making
    // sure that the alias isn't already in use.
    final LinkedHashMap<String,X509Certificate> certMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(certList.size()));
    for (int i=0; i < certList.size(); i++)
    {
      final X509Certificate x509Certificate = certList.get(i);
      final Certificate javaCertificate;
      try
      {
        javaCertificate = x509Certificate.toCertificate();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_ERROR_CONVERTING_CERT.get(
                  x509Certificate.getSubjectDN()));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }

      final String certAlias;
      if (i == 0)
      {
        certAlias = alias;
      }
      else if (certList.size() > 2)
      {
        certAlias = alias + "-issuer-" + i;
      }
      else
      {
        certAlias = alias + "-issuer";
      }

      certMap.put(certAlias, x509Certificate);

      if (hasKeyAlias(keystore, certAlias) ||
          hasCertificateAlias(keystore, certAlias))
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_WITH_CONFLICTING_ISSUER_ALIAS.get(
                  x509Certificate.getSubjectDN(), certAlias));
        return ResultCode.PARAM_ERROR;
      }

      try
      {
        keystore.setCertificateEntry(certAlias, javaCertificate);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_IMPORT_CERT_ERROR_UPDATING_KS_WITH_CERT.get(
                  x509Certificate.getSubjectDN(), alias));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }
    }


    // Prompt about whether to perform the import, if appropriate.
    if (! noPrompt)
    {
      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_IMPORT_CERT_CONFIRM_IMPORT_CHAIN_NO_KEY.
                get(alias));

      for (final Map.Entry<String,X509Certificate> e : certMap.entrySet())
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_IMPORT_CERT_LABEL_ALIAS.get(e.getKey()));
        printCertificate(e.getValue(), "", false);
      }

      out();

      try
      {
        if (! promptForYesNo(
             INFO_MANAGE_CERTS_IMPORT_CERT_PROMPT_IMPORT_CHAIN.get()))
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_IMPORT_CERT_CANCELED.get());
          return ResultCode.USER_CANCELED;
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err();
        wrapErr(0, WRAP_COLUMN, le.getMessage());
        return le.getResultCode();
      }
    }


    // Write the updated keystore to disk.
    try
    {
      writeKeystore(keystore, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    out();

    if (isNewKeystore)
    {
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_IMPORT_CERT_CREATED_KEYSTORE.get(
                getUserFriendlyKeystoreType(keystoreType)));
    }

    wrapOut(0, WRAP_COLUMN,
         INFO_MANAGE_CERTS_IMPORT_CERT_IMPORTED_CHAIN_WITHOUT_PK.get());
    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the delete-certificate subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doDeleteCertificate()
  {
    // Get the values of a number of configured arguments.
    final StringArgument aliasArgument =
         subCommandParser.getStringArgument("alias");
    final String alias = aliasArgument.getValue();

    final BooleanArgument noPromptArgument =
         subCommandParser.getBooleanArgument("no-prompt");
    final boolean noPrompt =
         ((noPromptArgument != null) && noPromptArgument.isPresent());

    final String keystoreType;
    final File keystorePath = getKeystorePath();
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    if ((displayKeytoolCommandArgument != null) &&
         displayKeytoolCommandArgument.isPresent())
    {
      final ArrayList<String> keytoolArgs = new ArrayList<>(10);
      keytoolArgs.add("-delete");

      keytoolArgs.add("-keystore");
      keytoolArgs.add(keystorePath.getAbsolutePath());
      keytoolArgs.add("-storetype");
      keytoolArgs.add(keystoreType);
      keytoolArgs.add("-storepass");
      keytoolArgs.add("*****REDACTED*****");
      keytoolArgs.add("-alias");
      keytoolArgs.add(alias);

      displayKeytoolCommand(keytoolArgs);
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the entry for the specified alias.
    final boolean hasPrivateKey;
    final ArrayList<X509Certificate> certList = new ArrayList<>(5);
    if (hasCertificateAlias(keystore, alias))
    {
      try
      {
        hasPrivateKey = false;
        certList.add(
             new X509Certificate(keystore.getCertificate(alias).getEncoded()));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_DELETE_CERT_ERROR_GETTING_CERT.get(alias));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }
    }
    else if (hasKeyAlias(keystore, alias))
    {
      try
      {
        hasPrivateKey = true;
        for (final Certificate c : keystore.getCertificateChain(alias))
        {
          certList.add(new X509Certificate(c.getEncoded()));
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_DELETE_CERT_ERROR_GETTING_CHAIN.get(alias));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }
    }
    else
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_DELETE_CERT_ERROR_ALIAS_NOT_CERT_OR_KEY.get(alias));
      return ResultCode.PARAM_ERROR;
    }


    // Prompt about whether to perform the delete, if appropriate.
    if (! noPrompt)
    {
      out();
      if (! hasPrivateKey)
      {
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_DELETE_CERT_CONFIRM_DELETE_CERT.get());
      }
      else
      {
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_DELETE_CERT_CONFIRM_DELETE_CHAIN.get());
      }

      for (final X509Certificate c : certList)
      {
        out();
        printCertificate(c, "", false);
      }

      out();

      try
      {
        if (! promptForYesNo(
             INFO_MANAGE_CERTS_DELETE_CERT_PROMPT_DELETE.get()))
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_DELETE_CERT_CANCELED.get());
          return ResultCode.USER_CANCELED;
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err();
        wrapErr(0, WRAP_COLUMN, le.getMessage());
        return le.getResultCode();
      }
    }


    // Delete the entry from the keystore.
    try
    {
      keystore.deleteEntry(alias);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_DELETE_CERT_DELETE_ERROR.get(alias));
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }


    // Write the updated keystore to disk.
    try
    {
      writeKeystore(keystore, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    if (certList.size() == 1)
    {
      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_DELETE_CERT_DELETED_CERT.get());
    }
    else
    {
      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_DELETE_CERT_DELETED_CHAIN.get());
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the generate-self-signed-certificate,
   * generate-certificate-signing-request, and sign-certificate-signing-request
   * subcommands.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doGenerateOrSignCertificateOrCSR()
  {
    // Figure out which subcommand we're processing.
    final boolean isGenerateCertificate;
    final boolean isGenerateCSR;
    final boolean isSignCSR;
    final SubCommand selectedSubCommand = globalParser.getSelectedSubCommand();
    if (selectedSubCommand.hasName("generate-self-signed-certificate"))
    {
      isGenerateCertificate = true;
      isGenerateCSR = false;
      isSignCSR = false;
    }
    else if (selectedSubCommand.hasName("generate-certificate-signing-request"))
    {
      isGenerateCertificate = false;
      isGenerateCSR = true;
      isSignCSR = false;
    }
    else
    {
      Validator.ensureTrue(
           selectedSubCommand.hasName("sign-certificate-signing-request"));
      isGenerateCertificate = false;
      isGenerateCSR = false;
      isSignCSR = true;
    }


    // Get the values of a number of configured arguments.
    final StringArgument aliasArgument =
         subCommandParser.getStringArgument("alias");
    final String alias = aliasArgument.getValue();

    final File keystorePath = getKeystorePath();
    final boolean isNewKeystore = (! keystorePath.exists());

    DN subjectDN = null;
    final DNArgument subjectDNArgument =
         subCommandParser.getDNArgument("subject-dn");
    if ((subjectDNArgument != null) && subjectDNArgument.isPresent())
    {
      subjectDN = subjectDNArgument.getValue();
    }

    File inputFile = null;
    final FileArgument inputFileArgument =
         subCommandParser.getFileArgument("input-file");
    if ((inputFileArgument != null) && inputFileArgument.isPresent())
    {
      inputFile = inputFileArgument.getValue();
    }

    File outputFile = null;
    final FileArgument outputFileArgument =
         subCommandParser.getFileArgument("output-file");
    if ((outputFileArgument != null) && outputFileArgument.isPresent())
    {
      outputFile = outputFileArgument.getValue();
    }

    boolean outputPEM = true;
    final StringArgument outputFormatArgument =
         subCommandParser.getStringArgument("output-format");
    if ((outputFormatArgument != null) && outputFormatArgument.isPresent())
    {
      final String format = outputFormatArgument.getValue().toLowerCase();
      if (format.equals("der") || format.equals("binary") ||
          format.equals("bin"))
      {
        outputPEM = false;
      }
    }

    if ((! outputPEM) && (outputFile == null))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_GEN_CERT_NO_FILE_WITH_DER.get());
      return ResultCode.PARAM_ERROR;
    }

    final BooleanArgument replaceExistingCertificateArgument =
         subCommandParser.getBooleanArgument("replace-existing-certificate");
    final boolean replaceExistingCertificate =
         ((replaceExistingCertificateArgument != null) &&
              replaceExistingCertificateArgument.isPresent());
    if (replaceExistingCertificate && (! keystorePath.exists()))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_GEN_CERT_REPLACE_WITHOUT_KS.get());
      return ResultCode.PARAM_ERROR;
    }

    final BooleanArgument inheritExtensionsArgument =
         subCommandParser.getBooleanArgument("inherit-extensions");
    final boolean inheritExtensions =
         ((inheritExtensionsArgument != null) &&
              inheritExtensionsArgument.isPresent());

    final BooleanArgument includeRequestedExtensionsArgument =
         subCommandParser.getBooleanArgument("include-requested-extensions");
    final boolean includeRequestedExtensions =
         ((includeRequestedExtensionsArgument != null) &&
              includeRequestedExtensionsArgument.isPresent());

    final BooleanArgument noPromptArgument =
         subCommandParser.getBooleanArgument("no-prompt");
    final boolean noPrompt =
         ((noPromptArgument != null) && noPromptArgument.isPresent());

    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    final boolean displayKeytoolCommand =
         ((displayKeytoolCommandArgument != null) &&
          displayKeytoolCommandArgument.isPresent());

    int daysValid = 365;
    final IntegerArgument daysValidArgument =
         subCommandParser.getIntegerArgument("days-valid");
    if ((daysValidArgument != null) && daysValidArgument.isPresent())
    {
      daysValid = daysValidArgument.getValue();
    }

    Date validityStartTime = null;
    final TimestampArgument validityStartTimeArgument =
         subCommandParser.getTimestampArgument("validity-start-time");
    if ((validityStartTimeArgument != null) &&
         validityStartTimeArgument.isPresent())
    {
      validityStartTime = validityStartTimeArgument.getValue();
    }

    PublicKeyAlgorithmIdentifier keyAlgorithmIdentifier = null;
    String keyAlgorithmName = null;
    final StringArgument keyAlgorithmArgument =
         subCommandParser.getStringArgument("key-algorithm");
    if ((keyAlgorithmArgument != null) && keyAlgorithmArgument.isPresent())
    {
      final String name = keyAlgorithmArgument.getValue();
      keyAlgorithmIdentifier = PublicKeyAlgorithmIdentifier.forName(name);
      if (keyAlgorithmIdentifier == null)
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_UNKNOWN_KEY_ALG.get(name));
        return ResultCode.PARAM_ERROR;
      }
      else
      {
        keyAlgorithmName = keyAlgorithmIdentifier.getName();
      }
    }

    Integer keySizeBits = null;
    final IntegerArgument keySizeBitsArgument =
         subCommandParser.getIntegerArgument("key-size-bits");
    if ((keySizeBitsArgument != null) && keySizeBitsArgument.isPresent())
    {
      keySizeBits = keySizeBitsArgument.getValue();
    }

    if ((keyAlgorithmIdentifier != null) &&
        (keyAlgorithmIdentifier != PublicKeyAlgorithmIdentifier.RSA) &&
        (keySizeBits == null))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_GEN_CERT_NO_KEY_SIZE_FOR_NON_RSA_KEY.get());
      return ResultCode.PARAM_ERROR;
    }

    String signatureAlgorithmName = null;
    SignatureAlgorithmIdentifier signatureAlgorithmIdentifier = null;
    final StringArgument signatureAlgorithmArgument =
         subCommandParser.getStringArgument("signature-algorithm");
    if ((signatureAlgorithmArgument != null) &&
        signatureAlgorithmArgument.isPresent())
    {
      final String name = signatureAlgorithmArgument.getValue();
      signatureAlgorithmIdentifier = SignatureAlgorithmIdentifier.forName(name);
      if (signatureAlgorithmIdentifier == null)
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_UNKNOWN_SIG_ALG.get(name));
        return ResultCode.PARAM_ERROR;
      }
      else
      {
        signatureAlgorithmName = signatureAlgorithmIdentifier.getJavaName();
      }
    }

    if ((keyAlgorithmIdentifier != null) &&
        (keyAlgorithmIdentifier != PublicKeyAlgorithmIdentifier.RSA) &&
        (signatureAlgorithmIdentifier == null))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_GEN_CERT_NO_SIG_ALG_FOR_NON_RSA_KEY.get());
      return ResultCode.PARAM_ERROR;
    }


    // Build a subject alternative name extension, if appropriate.
    final ArrayList<X509CertificateExtension> extensionList =
         new ArrayList<>(10);
    final GeneralNamesBuilder sanBuilder = new GeneralNamesBuilder();
    final LinkedHashSet<String> sanValues =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(10));
    final StringArgument sanDNSArgument =
         subCommandParser.getStringArgument("subject-alternative-name-dns");
    if ((sanDNSArgument != null) && sanDNSArgument.isPresent())
    {
      for (final String value : sanDNSArgument.getValues())
      {
        sanBuilder.addDNSName(value);
        sanValues.add("DNS:" + value);
      }
    }

    final StringArgument sanIPArgument = subCommandParser.getStringArgument(
         "subject-alternative-name-ip-address");
    if ((sanIPArgument != null) && sanIPArgument.isPresent())
    {
      for (final String value : sanIPArgument.getValues())
      {
        try
        {
          sanBuilder.addIPAddress(LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.
               getByName(value));
          sanValues.add("IP:" + value);
        }
        catch (final Exception e)
        {
          // This should never happen.
          Debug.debugException(e);
          throw new RuntimeException(e);
        }
      }
    }

    final StringArgument sanEmailArgument = subCommandParser.getStringArgument(
         "subject-alternative-name-email-address");
    if ((sanEmailArgument != null) && sanEmailArgument.isPresent())
    {
      for (final String value : sanEmailArgument.getValues())
      {
        sanBuilder.addRFC822Name(value);
        sanValues.add("EMAIL:" + value);
      }
    }

    final StringArgument sanURIArgument =
         subCommandParser.getStringArgument("subject-alternative-name-uri");
    if ((sanURIArgument != null) && sanURIArgument.isPresent())
    {
      for (final String value : sanURIArgument.getValues())
      {
        sanBuilder.addUniformResourceIdentifier(value);
        sanValues.add("URI:" + value);
      }
    }

    final StringArgument sanOIDArgument =
         subCommandParser.getStringArgument("subject-alternative-name-oid");
    if ((sanOIDArgument != null) && sanOIDArgument.isPresent())
    {
      for (final String value : sanOIDArgument.getValues())
      {
        sanBuilder.addRegisteredID(new OID(value));
        sanValues.add("OID:" + value);
      }
    }

    if (! sanValues.isEmpty())
    {
      try
      {
        extensionList.add(
             new SubjectAlternativeNameExtension(false, sanBuilder.build()));
      }
      catch (final Exception e)
      {
        // This should never happen.
        Debug.debugException(e);
        throw new RuntimeException(e);
      }
    }

    // Build a set of issuer alternative name extension values.
    final GeneralNamesBuilder ianBuilder = new GeneralNamesBuilder();
    final LinkedHashSet<String> ianValues =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(10));
    final StringArgument ianDNSArgument =
         subCommandParser.getStringArgument("issuer-alternative-name-dns");
    if ((ianDNSArgument != null) && ianDNSArgument.isPresent())
    {
      for (final String value : ianDNSArgument.getValues())
      {
        ianBuilder.addDNSName(value);
        ianValues.add("DNS:" + value);
      }
    }

    final StringArgument ianIPArgument = subCommandParser.getStringArgument(
         "issuer-alternative-name-ip-address");
    if ((ianIPArgument != null) && ianIPArgument.isPresent())
    {
      for (final String value : ianIPArgument.getValues())
      {
        try
        {
          ianBuilder.addIPAddress(LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.
               getByName(value));
          ianValues.add("IP:" + value);
        }
        catch (final Exception e)
        {
          // This should never happen.
          Debug.debugException(e);
          throw new RuntimeException(e);
        }
      }
    }

    final StringArgument ianEmailArgument = subCommandParser.getStringArgument(
         "issuer-alternative-name-email-address");
    if ((ianEmailArgument != null) && ianEmailArgument.isPresent())
    {
      for (final String value : ianEmailArgument.getValues())
      {
        ianBuilder.addRFC822Name(value);
        ianValues.add("EMAIL:" + value);
      }
    }

    final StringArgument ianURIArgument =
         subCommandParser.getStringArgument("issuer-alternative-name-uri");
    if ((ianURIArgument != null) && ianURIArgument.isPresent())
    {
      for (final String value : ianURIArgument.getValues())
      {
        ianBuilder.addUniformResourceIdentifier(value);
        ianValues.add("URI:" + value);
      }
    }

    final StringArgument ianOIDArgument =
         subCommandParser.getStringArgument("issuer-alternative-name-oid");
    if ((ianOIDArgument != null) && ianOIDArgument.isPresent())
    {
      for (final String value : ianOIDArgument.getValues())
      {
        ianBuilder.addRegisteredID(new OID(value));
        ianValues.add("OID:" + value);
      }
    }

    if (! ianValues.isEmpty())
    {
      try
      {
        extensionList.add(
             new IssuerAlternativeNameExtension(false, ianBuilder.build()));
      }
      catch (final Exception e)
      {
        // This should never happen.
        Debug.debugException(e);
        throw new RuntimeException(e);
      }
    }


    // Build a basic constraints extension, if appropriate.
    BasicConstraintsExtension basicConstraints = null;
    final BooleanValueArgument basicConstraintsIsCAArgument =
         subCommandParser.getBooleanValueArgument("basic-constraints-is-ca");
    if ((basicConstraintsIsCAArgument != null) &&
         basicConstraintsIsCAArgument.isPresent())
    {
      final boolean isCA = basicConstraintsIsCAArgument.getValue();

      Integer pathLength = null;
      final IntegerArgument pathLengthArgument =
           subCommandParser.getIntegerArgument(
                "basic-constraints-maximum-path-length");
      if ((pathLengthArgument != null) && pathLengthArgument.isPresent())
      {
        if (isCA)
        {
          pathLength = pathLengthArgument.getValue();
        }
        else
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_BC_PATH_LENGTH_WITHOUT_CA.get());
          return ResultCode.PARAM_ERROR;
        }
      }

      basicConstraints = new BasicConstraintsExtension(false, isCA, pathLength);
      extensionList.add(basicConstraints);
    }


    // Build a key usage extension, if appropriate.
    KeyUsageExtension keyUsage = null;
    final StringArgument keyUsageArgument =
         subCommandParser.getStringArgument("key-usage");
    if ((keyUsageArgument != null) && keyUsageArgument.isPresent())
    {
      boolean digitalSignature = false;
      boolean nonRepudiation = false;
      boolean keyEncipherment = false;
      boolean dataEncipherment = false;
      boolean keyAgreement = false;
      boolean keyCertSign = false;
      boolean crlSign = false;
      boolean encipherOnly = false;
      boolean decipherOnly = false;

      for (final String value : keyUsageArgument.getValues())
      {
        if (value.equalsIgnoreCase("digital-signature") ||
             value.equalsIgnoreCase("digitalSignature"))
        {
          digitalSignature = true;
        }
        else if (value.equalsIgnoreCase("non-repudiation") ||
             value.equalsIgnoreCase("nonRepudiation") ||
             value.equalsIgnoreCase("content-commitment") ||
             value.equalsIgnoreCase("contentCommitment"))
        {
          nonRepudiation = true;
        }
        else if (value.equalsIgnoreCase("key-encipherment") ||
             value.equalsIgnoreCase("keyEncipherment"))
        {
          keyEncipherment = true;
        }
        else if (value.equalsIgnoreCase("data-encipherment") ||
             value.equalsIgnoreCase("dataEncipherment"))
        {
          dataEncipherment = true;
        }
        else if (value.equalsIgnoreCase("key-agreement") ||
             value.equalsIgnoreCase("keyAgreement"))
        {
          keyAgreement = true;
        }
        else if (value.equalsIgnoreCase("key-cert-sign") ||
             value.equalsIgnoreCase("keyCertSign"))
        {
          keyCertSign = true;
        }
        else if (value.equalsIgnoreCase("crl-sign") ||
             value.equalsIgnoreCase("crlSign"))
        {
          crlSign = true;
        }
        else if (value.equalsIgnoreCase("encipher-only") ||
             value.equalsIgnoreCase("encipherOnly"))
        {
          encipherOnly = true;
        }
        else if (value.equalsIgnoreCase("decipher-only") ||
             value.equalsIgnoreCase("decipherOnly"))
        {
          decipherOnly = true;
        }
        else
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_INVALID_KEY_USAGE.get(value));
          return ResultCode.PARAM_ERROR;
        }
      }

      keyUsage = new KeyUsageExtension(false, digitalSignature, nonRepudiation,
           keyEncipherment, dataEncipherment, keyAgreement, keyCertSign,
           crlSign, encipherOnly, decipherOnly);
      extensionList.add(keyUsage);
    }


    // Build an extended key usage extension, if appropriate.
    ExtendedKeyUsageExtension extendedKeyUsage = null;
    final StringArgument extendedKeyUsageArgument =
         subCommandParser.getStringArgument("extended-key-usage");
    if ((extendedKeyUsageArgument != null) &&
         extendedKeyUsageArgument.isPresent())
    {
      final List<String> values = extendedKeyUsageArgument.getValues();
      final ArrayList<OID> keyPurposeIDs = new ArrayList<>(values.size());
      for (final String value : values)
      {
        if (value.equalsIgnoreCase("server-auth") ||
             value.equalsIgnoreCase("serverAuth") ||
             value.equalsIgnoreCase("server-authentication") ||
             value.equalsIgnoreCase("serverAuthentication") ||
             value.equalsIgnoreCase("tls-server-authentication") ||
             value.equalsIgnoreCase("tlsServerAuthentication"))
        {
          keyPurposeIDs.add(
               ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID());
        }
        else if (value.equalsIgnoreCase("client-auth") ||
             value.equalsIgnoreCase("clientAuth") ||
             value.equalsIgnoreCase("client-authentication") ||
             value.equalsIgnoreCase("clientAuthentication") ||
             value.equalsIgnoreCase("tls-client-authentication") ||
             value.equalsIgnoreCase("tlsClientAuthentication"))
        {
          keyPurposeIDs.add(
               ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID());
        }
        else if (value.equalsIgnoreCase("code-signing") ||
             value.equalsIgnoreCase("codeSigning"))
        {
          keyPurposeIDs.add(ExtendedKeyUsageID.CODE_SIGNING.getOID());
        }
        else if (value.equalsIgnoreCase("email-protection") ||
             value.equalsIgnoreCase("emailProtection"))
        {
          keyPurposeIDs.add(ExtendedKeyUsageID.EMAIL_PROTECTION.getOID());
        }
        else if (value.equalsIgnoreCase("time-stamping") ||
             value.equalsIgnoreCase("timeStamping"))
        {
          keyPurposeIDs.add(ExtendedKeyUsageID.TIME_STAMPING.getOID());
        }
        else if (value.equalsIgnoreCase("ocsp-signing") ||
             value.equalsIgnoreCase("ocspSigning"))
        {
          keyPurposeIDs.add(ExtendedKeyUsageID.OCSP_SIGNING.getOID());
        }
        else if (OID.isStrictlyValidNumericOID(value))
        {
          keyPurposeIDs.add(new OID(value));
        }
        else
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_INVALID_EXTENDED_KEY_USAGE.get(value));
          return ResultCode.PARAM_ERROR;
        }
      }

      try
      {
        extendedKeyUsage = new ExtendedKeyUsageExtension(false, keyPurposeIDs);
      }
      catch (final Exception e)
      {
        // This should never happen.
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_EXTENDED_KEY_USAGE_ERROR.get());
        e.printStackTrace(getErr());
        return ResultCode.PARAM_ERROR;
      }

      extensionList.add(extendedKeyUsage);
    }


    // Build a list of generic extensions.
    final ArrayList<X509CertificateExtension> genericExtensions =
         new ArrayList<>(5);
    final StringArgument extensionArgument =
         subCommandParser.getStringArgument("extension");
    if ((extensionArgument != null) && extensionArgument.isPresent())
    {
      for (final String value : extensionArgument.getValues())
      {
        try
        {
          final int firstColonPos = value.indexOf(':');
          final int secondColonPos = value.indexOf(':', firstColonPos + 1);
          final OID oid = new OID(value.substring(0, firstColonPos));
          if (! oid.isStrictlyValidNumericOID())
          {
            wrapErr(0, WRAP_COLUMN,
                 ERR_MANAGE_CERTS_GEN_CERT_EXT_MALFORMED_OID.get(value,
                      oid.toString()));
            return ResultCode.PARAM_ERROR;
          }

          final boolean criticality;
          final String criticalityString =
               value.substring(firstColonPos + 1, secondColonPos);
          if (criticalityString.equalsIgnoreCase("true") ||
               criticalityString.equalsIgnoreCase("t") ||
               criticalityString.equalsIgnoreCase("yes") ||
               criticalityString.equalsIgnoreCase("y") ||
               criticalityString.equalsIgnoreCase("on") ||
               criticalityString.equalsIgnoreCase("1"))
          {
            criticality = true;
          }
          else if (criticalityString.equalsIgnoreCase("false") ||
               criticalityString.equalsIgnoreCase("f") ||
               criticalityString.equalsIgnoreCase("no") ||
               criticalityString.equalsIgnoreCase("n") ||
               criticalityString.equalsIgnoreCase("off") ||
               criticalityString.equalsIgnoreCase("0"))
          {
            criticality = false;
          }
          else
          {
            wrapErr(0, WRAP_COLUMN,
                 ERR_MANAGE_CERTS_GEN_CERT_EXT_INVALID_CRITICALITY.get(
                      value, criticalityString));
            return ResultCode.PARAM_ERROR;
          }

          final byte[] valueBytes;
          try
          {
            valueBytes = StaticUtils.fromHex(value.substring(secondColonPos+1));
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            wrapErr(0, WRAP_COLUMN,
                 ERR_MANAGE_CERTS_GEN_CERT_EXT_INVALID_VALUE.get(value));
            return ResultCode.PARAM_ERROR;
          }

          final X509CertificateExtension extension =
               new X509CertificateExtension(oid, criticality, valueBytes);
          genericExtensions.add(extension);
          extensionList.add(extension);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_EXT_MALFORMED.get(value));
          return ResultCode.PARAM_ERROR;
        }
      }
    }


    final String keystoreType;
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // If there is a private key, then see if we need to use a private key
    // password that is different from the keystore password.
    final char[] privateKeyPassword;
    try
    {
      privateKeyPassword =
           getPrivateKeyPassword(keystore, alias, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // If we're going to replace an existing certificate in the keystore, then
    // perform the appropriate processing for that.
    if (replaceExistingCertificate)
    {
      // Make sure that the keystore already has a private key entry with the
      // specified alias.
      if (! hasKeyAlias(keystore, alias))
      {
        if (hasCertificateAlias(keystore, alias))
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_REPLACE_ALIAS_IS_CERT.get(alias,
                    keystorePath.getAbsolutePath()));
          return ResultCode.PARAM_ERROR;
        }
        else
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_REPLACE_NO_SUCH_ALIAS.get(alias,
                    keystorePath.getAbsolutePath()));
          return ResultCode.PARAM_ERROR;
        }
      }


      // Get the certificate to replace, along with its key pair.
      final X509Certificate certToReplace;
      final KeyPair keyPair;
      try
      {
        final Certificate[] chain = keystore.getCertificateChain(alias);
        certToReplace = new X509Certificate(chain[0].getEncoded());

        final PublicKey publicKey = chain[0].getPublicKey();
        final PrivateKey privateKey =
             (PrivateKey) keystore.getKey(alias, privateKeyPassword);
        keyPair = new KeyPair(publicKey, privateKey);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_REPLACE_COULD_NOT_GET_CERT.get(alias));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }


      // Assign the remaining values using information in the existing
      // certificate.
      signatureAlgorithmIdentifier = SignatureAlgorithmIdentifier.forOID(
           certToReplace.getSignatureAlgorithmOID());
      if (signatureAlgorithmIdentifier == null)
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_UNKNOWN_SIG_ALG_IN_CERT.get(
                  certToReplace.getSignatureAlgorithmOID()));
        return ResultCode.PARAM_ERROR;
      }
      else
      {
        signatureAlgorithmName = signatureAlgorithmIdentifier.getJavaName();
      }

      if (subjectDN == null)
      {
        subjectDN = certToReplace.getSubjectDN();
      }

      if (inheritExtensions)
      {
        for (final X509CertificateExtension extension :
             certToReplace.getExtensions())
        {
          if ((extension instanceof AuthorityKeyIdentifierExtension) ||
              (extension instanceof IssuerAlternativeNameExtension))
          {
            // This extension applies to the issuer.  We won't include this in
            // the set of inherited extensions.
          }
          else if (extension instanceof SubjectKeyIdentifierExtension)
          {
            // The generated certificate will automatically include a subject
            // key identifier extension, so we don't need to include it.
          }
          else if (extension instanceof BasicConstraintsExtension)
          {
            // Don't override a value already provided on the command line.
            if (basicConstraints == null)
            {
              basicConstraints = (BasicConstraintsExtension) extension;
              extensionList.add(basicConstraints);
            }
          }
          else if (extension instanceof ExtendedKeyUsageExtension)
          {
            // Don't override a value already provided on the command line.
            if (extendedKeyUsage == null)
            {
              extendedKeyUsage = (ExtendedKeyUsageExtension) extension;
              extensionList.add(extendedKeyUsage);
            }
          }
          else if (extension instanceof KeyUsageExtension)
          {
            // Don't override a value already provided on the command line.
            if (keyUsage == null)
            {
              keyUsage = (KeyUsageExtension) extension;
              extensionList.add(keyUsage);
            }
          }
          else if (extension instanceof SubjectAlternativeNameExtension)
          {
            // Although we could merge values, it's safer to not do that if any
            // subject alternative name values were provided on the command
            // line.
            if (sanValues.isEmpty())
            {
              final SubjectAlternativeNameExtension e =
                   (SubjectAlternativeNameExtension) extension;
              for (final String dnsName : e.getDNSNames())
              {
                sanValues.add("DNS:" + dnsName);
              }

              for (final InetAddress ipAddress : e.getIPAddresses())
              {
                sanValues.add("IP:" + ipAddress.getHostAddress());
              }

              for (final String emailAddress : e.getRFC822Names())
              {
                sanValues.add("EMAIL:" + emailAddress);
              }

              for (final String uri : e.getUniformResourceIdentifiers())
              {
                sanValues.add("URI:" + uri);
              }

              for (final OID oid : e.getRegisteredIDs())
              {
                sanValues.add("OID:" + oid.toString());
              }

              extensionList.add(extension);
            }
          }
          else
          {
            genericExtensions.add(extension);
            extensionList.add(extension);
          }
        }
      }


      // Create an array with the final set of extensions to include in the
      // certificate or certificate signing request.
      final X509CertificateExtension[] extensions =
           new X509CertificateExtension[extensionList.size()];
      extensionList.toArray(extensions);


      // If we're generating a self-signed certificate or a certificate signing
      // request, then we should now have everything we need to do that.  Build
      // a keytool command that we could use to accomplish it.
      if (isGenerateCertificate)
      {
        if (displayKeytoolCommand)
        {
          final ArrayList<String> keytoolArguments = new ArrayList<>(30);
          keytoolArguments.add("-selfcert");
          keytoolArguments.add("-keystore");
          keytoolArguments.add(keystorePath.getAbsolutePath());
          keytoolArguments.add("-storetype");
          keytoolArguments.add(keystoreType);
          keytoolArguments.add("-storepass");
          keytoolArguments.add("*****REDACTED*****");
          keytoolArguments.add("-keypass");
          keytoolArguments.add("*****REDACTED*****");
          keytoolArguments.add("-alias");
          keytoolArguments.add(alias);
          keytoolArguments.add("-dname");
          keytoolArguments.add(subjectDN.toString());
          keytoolArguments.add("-sigalg");
          keytoolArguments.add(signatureAlgorithmName);
          keytoolArguments.add("-validity");
          keytoolArguments.add(String.valueOf(daysValid));

          if (validityStartTime != null)
          {
            keytoolArguments.add("-startdate");
            keytoolArguments.add(formatValidityStartTime(validityStartTime));
          }

          addExtensionArguments(keytoolArguments, basicConstraints, keyUsage,
               extendedKeyUsage, sanValues, ianValues, genericExtensions);

          displayKeytoolCommand(keytoolArguments);
        }


        // Generate the self-signed certificate.
        final long notBefore;
        if (validityStartTime == null)
        {
          notBefore = System.currentTimeMillis();
        }
        else
        {
          notBefore = validityStartTime.getTime();
        }

        final long notAfter = notBefore + TimeUnit.DAYS.toMillis(daysValid);

        final X509Certificate certificate;
        final Certificate[] chain;
        try
        {
          certificate = X509Certificate.generateSelfSignedCertificate(
               signatureAlgorithmIdentifier, keyPair, subjectDN, notBefore,
               notAfter, extensions);
          chain = new Certificate[] { certificate.toCertificate() };
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_ERROR_GENERATING_CERT.get());
          e.printStackTrace(getErr());
          return ResultCode.LOCAL_ERROR;
        }


        // Update the keystore with the new certificate.
        try
        {
          keystore.setKeyEntry(alias, keyPair.getPrivate(), privateKeyPassword,
               chain);
          writeKeystore(keystore, keystorePath, keystorePassword);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_ERROR_UPDATING_KEYSTORE.get());
          e.printStackTrace(getErr());
          return ResultCode.LOCAL_ERROR;
        }


        // Display the certificate we just generated to the end user.
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_GEN_CERT_SUCCESSFULLY_GENERATED_SELF_CERT.
                  get());
        printCertificate(certificate, "", false);
        return ResultCode.SUCCESS;
      }
      else
      {
        // Build the keytool command used to generate the certificate signing
        // request.
        Validator.ensureTrue(isGenerateCSR);
        if (displayKeytoolCommand)
        {
          final ArrayList<String> keytoolArguments = new ArrayList<>(30);
          keytoolArguments.add("-certreq");
          keytoolArguments.add("-keystore");
          keytoolArguments.add(keystorePath.getAbsolutePath());
          keytoolArguments.add("-storetype");
          keytoolArguments.add(keystoreType);
          keytoolArguments.add("-storepass");
          keytoolArguments.add("*****REDACTED*****");
          keytoolArguments.add("-keypass");
          keytoolArguments.add("*****REDACTED*****");
          keytoolArguments.add("-alias");
          keytoolArguments.add(alias);
          keytoolArguments.add("-dname");
          keytoolArguments.add(subjectDN.toString());
          keytoolArguments.add("-sigalg");
          keytoolArguments.add(signatureAlgorithmName);

          addExtensionArguments(keytoolArguments, basicConstraints, keyUsage,
               extendedKeyUsage, sanValues, ianValues, genericExtensions);

          if (outputFile != null)
          {
            keytoolArguments.add("-file");
            keytoolArguments.add(outputFile.getAbsolutePath());
          }

          displayKeytoolCommand(keytoolArguments);
        }


        // Generate the certificate signing request.
        final PKCS10CertificateSigningRequest certificateSigningRequest;
        try
        {
          certificateSigningRequest = PKCS10CertificateSigningRequest.
               generateCertificateSigningRequest(signatureAlgorithmIdentifier,
                    keyPair, subjectDN, extensions);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_ERROR_GENERATING_CSR.get());
          e.printStackTrace(getErr());
          return ResultCode.LOCAL_ERROR;
        }


        // Write the generated certificate signing request to the appropriate
        // location.
        try
        {
          final PrintStream ps;
          if (outputFile == null)
          {
            ps = getOut();
          }
          else
          {
            ps = new PrintStream(outputFile);
          }

          if (outputPEM)
          {
            writePEMCertificateSigningRequest(ps,
                 certificateSigningRequest.
                      getPKCS10CertificateSigningRequestBytes());
          }
          else
          {
            ps.write(certificateSigningRequest.
                 getPKCS10CertificateSigningRequestBytes());
          }

          if (outputFile != null)
          {
            ps.close();
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_ERROR_WRITING_CSR.get());
          e.printStackTrace(getErr());
          return ResultCode.LOCAL_ERROR;
        }


        // If the certificate signing request was written to an output file,
        // then let the user know that it was successful.  If it was written to
        // standard output, then we don't need to tell them because they'll be
        // able to see it.
        if (outputFile != null)
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_GEN_CERT_SUCCESSFULLY_GENERATED_CSR.get(
                    outputFile.getAbsolutePath()));
        }

        return ResultCode.SUCCESS;
      }
    }


    // If we've gotten here, then we know we're not replacing an existing
    // certificate.  Perform any remaining argument assignment and validation.
    if ((subjectDN == null) && (! isSignCSR))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_GEN_CERT_NO_SUBJECT_DN_WITHOUT_REPLACE.get());
      return ResultCode.PARAM_ERROR;
    }

    if (keyAlgorithmIdentifier == null)
    {
      keyAlgorithmIdentifier = PublicKeyAlgorithmIdentifier.RSA;
      keyAlgorithmName = keyAlgorithmIdentifier.getName();
    }

    if (keySizeBits == null)
    {
      keySizeBits = 2048;
    }

    if ((signatureAlgorithmIdentifier == null) && (! isSignCSR))
    {
      signatureAlgorithmIdentifier =
           SignatureAlgorithmIdentifier.SHA_256_WITH_RSA;
      signatureAlgorithmName = signatureAlgorithmIdentifier.getJavaName();
    }


    // If we're going to generate a self-signed certificate or a certificate
    // signing request, then we first need to generate a key pair.  Put together
    // the appropriate set of keytool arguments and then generate a self-signed
    // certificate.
    if (isGenerateCertificate || isGenerateCSR)
    {
      // Make sure that the specified alias is not already in use in the
      // keystore.
      if (hasKeyAlias(keystore, alias) || hasCertificateAlias(keystore, alias))
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_ALIAS_EXISTS_WITHOUT_REPLACE.get(alias));
        return ResultCode.PARAM_ERROR;
      }


      if (displayKeytoolCommand)
      {
        final ArrayList<String> keytoolArguments = new ArrayList<>(30);
        keytoolArguments.add("-genkeypair");
        keytoolArguments.add("-keystore");
        keytoolArguments.add(keystorePath.getAbsolutePath());
        keytoolArguments.add("-storetype");
        keytoolArguments.add(keystoreType);
        keytoolArguments.add("-storepass");
        keytoolArguments.add("*****REDACTED*****");
        keytoolArguments.add("-keypass");
        keytoolArguments.add("*****REDACTED*****");
        keytoolArguments.add("-alias");
        keytoolArguments.add(alias);
        keytoolArguments.add("-dname");
        keytoolArguments.add(subjectDN.toString());
        keytoolArguments.add("-keyalg");
        keytoolArguments.add(keyAlgorithmName);
        keytoolArguments.add("-keysize");
        keytoolArguments.add(String.valueOf(keySizeBits));
        keytoolArguments.add("-sigalg");
        keytoolArguments.add(signatureAlgorithmName);
        keytoolArguments.add("-validity");
        keytoolArguments.add(String.valueOf(daysValid));

        if (validityStartTime != null)
        {
          keytoolArguments.add("-startdate");
          keytoolArguments.add(formatValidityStartTime(validityStartTime));
        }

        addExtensionArguments(keytoolArguments, basicConstraints,
             keyUsage, extendedKeyUsage, sanValues, ianValues,
             genericExtensions);

        displayKeytoolCommand(keytoolArguments);
      }


      // Generate the self-signed certificate.
      final long notBefore;
      if (validityStartTime == null)
      {
        notBefore = System.currentTimeMillis();
      }
      else
      {
        notBefore = validityStartTime.getTime();
      }

      final long notAfter = notBefore + TimeUnit.DAYS.toMillis(daysValid);

      final X509CertificateExtension[] extensions =
           new X509CertificateExtension[extensionList.size()];
      extensionList.toArray(extensions);

      final Certificate[] chain;
      final KeyPair keyPair;
      final X509Certificate certificate;
      try
      {
        final ObjectPair<X509Certificate,KeyPair> p =
             X509Certificate.generateSelfSignedCertificate(
                  signatureAlgorithmIdentifier, keyAlgorithmIdentifier,
                  keySizeBits, subjectDN, notBefore, notAfter, extensions);
        certificate = p.getFirst();
        chain = new Certificate[] { certificate.toCertificate() };
        keyPair = p.getSecond();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_ERROR_GENERATING_CERT.get());
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }


      // Update the keystore with the new certificate.
      try
      {
        keystore.setKeyEntry(alias, keyPair.getPrivate(), privateKeyPassword,
             chain);
        writeKeystore(keystore, keystorePath, keystorePassword);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_ERROR_UPDATING_KEYSTORE.get());
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }

      if (isNewKeystore)
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_GEN_CERT_CERT_CREATED_KEYSTORE.get(
                  getUserFriendlyKeystoreType(keystoreType)));
      }


      // If we're just generating a self-signed certificate, then display the
      // certificate that we generated.
      if (isGenerateCertificate)
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_GEN_CERT_SUCCESSFULLY_GENERATED_SELF_CERT.get());
        printCertificate(certificate, "", false);

        return ResultCode.SUCCESS;
      }


      // If we're generating a certificate signing request, then put together
      // the appropriate set of arguments for that.
      Validator.ensureTrue(isGenerateCSR);
      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_GEN_CERT_SUCCESSFULLY_GENERATED_KEYPAIR.get());

      if (displayKeytoolCommand)
      {
        final ArrayList<String> keytoolArguments = new ArrayList<>(30);
        keytoolArguments.add("-certreq");
        keytoolArguments.add("-keystore");
        keytoolArguments.add(keystorePath.getAbsolutePath());
        keytoolArguments.add("-storetype");
        keytoolArguments.add(keystoreType);
        keytoolArguments.add("-storepass");
        keytoolArguments.add("*****REDACTED*****");
        keytoolArguments.add("-keypass");
        keytoolArguments.add("*****REDACTED*****");
        keytoolArguments.add("-alias");
        keytoolArguments.add(alias);
        keytoolArguments.add("-dname");
        keytoolArguments.add(subjectDN.toString());
        keytoolArguments.add("-sigalg");
        keytoolArguments.add(signatureAlgorithmName);

        addExtensionArguments(keytoolArguments, basicConstraints, keyUsage,
             extendedKeyUsage, sanValues, ianValues, genericExtensions);

        if (outputFile != null)
        {
          keytoolArguments.add("-file");
          keytoolArguments.add(outputFile.getAbsolutePath());
        }

        displayKeytoolCommand(keytoolArguments);
      }


      // Generate the certificate signing request.
      final PKCS10CertificateSigningRequest certificateSigningRequest;
      try
      {
        certificateSigningRequest = PKCS10CertificateSigningRequest.
             generateCertificateSigningRequest(signatureAlgorithmIdentifier,
                  keyPair, subjectDN, extensions);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_ERROR_GENERATING_CSR.get());
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }


      // Write the generated certificate signing request to the appropriate
      // location.
      try
      {
        final PrintStream ps;
        if (outputFile == null)
        {
          ps = getOut();
        }
        else
        {
          ps = new PrintStream(outputFile);
        }

        if (outputPEM)
        {
          writePEMCertificateSigningRequest(ps,
               certificateSigningRequest.
                    getPKCS10CertificateSigningRequestBytes());
        }
        else
        {
          ps.write(certificateSigningRequest.
               getPKCS10CertificateSigningRequestBytes());
        }

        if (outputFile != null)
        {
          ps.close();
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_ERROR_WRITING_CSR.get());
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }


      // If the certificate signing request was written to an output file,
      // then let the user know that it was successful.  If it was written to
      // standard output, then we don't need to tell them because they'll be
      // able to see it.
      if (outputFile != null)
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_GEN_CERT_SUCCESSFULLY_GENERATED_CSR.get(
                  outputFile.getAbsolutePath()));
      }

      return ResultCode.SUCCESS;
    }


    // If we've gotten here, then we should be signing a certificate signing
    // request.  Make sure that the keystore already has a private key entry
    // with the specified alias.
    Validator.ensureTrue(isSignCSR);
    if (! hasKeyAlias(keystore, alias))
    {
      if (hasCertificateAlias(keystore, alias))
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_SIGN_ALIAS_IS_CERT.get(alias,
                  keystorePath.getAbsolutePath()));
        return ResultCode.PARAM_ERROR;
      }
      else
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_GEN_CERT_SIGN_NO_SUCH_ALIAS.get(alias,
                  keystorePath.getAbsolutePath()));
        return ResultCode.PARAM_ERROR;
      }
    }


    // Get the signing certificate and its key pair.
    final PrivateKey issuerPrivateKey;
    final X509Certificate issuerCertificate;
    try
    {
      final Certificate[] chain = keystore.getCertificateChain(alias);
      issuerCertificate = new X509Certificate(chain[0].getEncoded());

      issuerPrivateKey =
           (PrivateKey) keystore.getKey(alias, privateKeyPassword);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_GEN_CERT_SIGN_CANNOT_GET_SIGNING_CERT.get(alias));
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }


    // Make sure that we can decode the certificate signing request.
    final PKCS10CertificateSigningRequest csr;
    try
    {
      csr = readCertificateSigningRequestFromFile(inputFile);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Make sure that we can verify the certificate signing request's signature.
    try
    {
      csr.verifySignature();
    }
    catch (final CertException ce)
    {
      Debug.debugException(ce);
      wrapErr(0, WRAP_COLUMN, ce.getMessage());
      return ResultCode.PARAM_ERROR;
    }


    // Prompt about whether to sign the request, if appropriate.
    if (! noPrompt)
    {
      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_GEN_CERT_SIGN_CONFIRM.get());
      out();
      printCertificateSigningRequest(csr, false, "");
      out();

      try
      {
        if (! promptForYesNo(
             INFO_MANAGE_CERTS_GEN_CERT_PROMPT_SIGN.get()))
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_SIGN_CANCELED.get());
          return ResultCode.USER_CANCELED;
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err();
        wrapErr(0, WRAP_COLUMN, le.getMessage());
        return le.getResultCode();
      }
    }


    // Read the certificate signing request and see if we need to take values
    // from it.
    if ((subjectDN == null) || (signatureAlgorithmIdentifier == null) ||
        includeRequestedExtensions)
    {
      if (subjectDN == null)
      {
        subjectDN = csr.getSubjectDN();
      }

      if (signatureAlgorithmIdentifier == null)
      {
        signatureAlgorithmIdentifier = SignatureAlgorithmIdentifier.forOID(
             csr.getSignatureAlgorithmOID());
        if (signatureAlgorithmIdentifier == null)
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_GEN_CERT_UNKNOWN_SIG_ALG_IN_CSR.get(
                    csr.getSignatureAlgorithmOID()));
          return ResultCode.PARAM_ERROR;
        }
        else
        {
          signatureAlgorithmName = signatureAlgorithmIdentifier.getJavaName();
        }
      }

      if (includeRequestedExtensions)
      {
        for (final X509CertificateExtension extension : csr.getExtensions())
        {
          if ((extension instanceof AuthorityKeyIdentifierExtension) ||
              (extension instanceof IssuerAlternativeNameExtension))
          {
            // This extension applies to the issuer.  We won't include this in
            // the set of inherited extensions.
          }
          else if (extension instanceof SubjectKeyIdentifierExtension)
          {
            // The generated certificate will automatically include a subject
            // key identifier extension, so we don't need to include it.
          }
          else if (extension instanceof BasicConstraintsExtension)
          {
            // Don't override a value already provided on the command line.
            if (basicConstraints == null)
            {
              basicConstraints = (BasicConstraintsExtension) extension;
              extensionList.add(basicConstraints);
            }
          }
          else if (extension instanceof ExtendedKeyUsageExtension)
          {
            // Don't override a value already provided on the command line.
            if (extendedKeyUsage == null)
            {
              extendedKeyUsage = (ExtendedKeyUsageExtension) extension;
              extensionList.add(extendedKeyUsage);
            }
          }
          else if (extension instanceof KeyUsageExtension)
          {
            // Don't override a value already provided on the command line.
            if (keyUsage == null)
            {
              keyUsage = (KeyUsageExtension) extension;
              extensionList.add(keyUsage);
            }
          }
          else if (extension instanceof SubjectAlternativeNameExtension)
          {
            // Although we could merge values, it's safer to not do that if any
            // subject alternative name values were provided on the command
            // line.
            if (sanValues.isEmpty())
            {
              final SubjectAlternativeNameExtension e =
                   (SubjectAlternativeNameExtension) extension;
              for (final String dnsName : e.getDNSNames())
              {
                sanBuilder.addDNSName(dnsName);
                sanValues.add("DNS:" + dnsName);
              }

              for (final InetAddress ipAddress : e.getIPAddresses())
              {
                sanBuilder.addIPAddress(ipAddress);
                sanValues.add("IP:" + ipAddress.getHostAddress());
              }

              for (final String emailAddress : e.getRFC822Names())
              {
                sanBuilder.addRFC822Name(emailAddress);
                sanValues.add("EMAIL:" + emailAddress);
              }

              for (final String uri : e.getUniformResourceIdentifiers())
              {
                sanBuilder.addUniformResourceIdentifier(uri);
                sanValues.add("URI:" + uri);
              }

              for (final OID oid : e.getRegisteredIDs())
              {
                sanBuilder.addRegisteredID(oid);
                sanValues.add("OID:" + oid.toString());
              }

              try
              {
                extensionList.add(
                     new SubjectAlternativeNameExtension(false,
                          sanBuilder.build()));
              }
              catch (final Exception ex)
              {
                // This should never happen.
                Debug.debugException(ex);
                throw new RuntimeException(ex);
              }
            }
          }
          else
          {
            genericExtensions.add(extension);
            extensionList.add(extension);
          }
        }
      }
    }


    // Generate the keytool arguments to use to sign the requested certificate.
    final ArrayList<String> keytoolArguments = new ArrayList<>(30);
    keytoolArguments.add("-gencert");
    keytoolArguments.add("-keystore");
    keytoolArguments.add(keystorePath.getAbsolutePath());
    keytoolArguments.add("-storetype");
    keytoolArguments.add(keystoreType);
    keytoolArguments.add("-storepass");
    keytoolArguments.add("*****REDACTED*****");
    keytoolArguments.add("-keypass");
    keytoolArguments.add("*****REDACTED*****");
    keytoolArguments.add("-alias");
    keytoolArguments.add(alias);
    keytoolArguments.add("-dname");
    keytoolArguments.add(subjectDN.toString());
    keytoolArguments.add("-sigalg");
    keytoolArguments.add(signatureAlgorithmName);
    keytoolArguments.add("-validity");
    keytoolArguments.add(String.valueOf(daysValid));

    if (validityStartTime != null)
    {
      keytoolArguments.add("-startdate");
      keytoolArguments.add(formatValidityStartTime(validityStartTime));
    }

    addExtensionArguments(keytoolArguments, basicConstraints, keyUsage,
         extendedKeyUsage, sanValues, ianValues, genericExtensions);

    keytoolArguments.add("-infile");
    keytoolArguments.add(inputFile.getAbsolutePath());

    if (outputFile != null)
    {
      keytoolArguments.add("-outfile");
      keytoolArguments.add(outputFile.getAbsolutePath());
    }

    if (outputPEM)
    {
      keytoolArguments.add("-rfc");
    }

    if (displayKeytoolCommand)
    {
      displayKeytoolCommand(keytoolArguments);
    }


    // Generate the signed certificate.
    final long notBefore;
    if (validityStartTime == null)
    {
      notBefore = System.currentTimeMillis();
    }
    else
    {
      notBefore = validityStartTime.getTime();
    }

    final long notAfter = notBefore + TimeUnit.DAYS.toMillis(daysValid);

    final X509CertificateExtension[] extensions =
         new X509CertificateExtension[extensionList.size()];
    extensionList.toArray(extensions);

    final X509Certificate signedCertificate;
    try
    {
      signedCertificate = X509Certificate.generateIssuerSignedCertificate(
           signatureAlgorithmIdentifier, issuerCertificate, issuerPrivateKey,
           csr.getPublicKeyAlgorithmOID(),
           csr.getPublicKeyAlgorithmParameters(), csr.getEncodedPublicKey(),
           csr.getDecodedPublicKey(), subjectDN, notBefore, notAfter,
           extensions);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_GEN_CERT_ERROR_SIGNING_CERT.get());
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }


    // Write the signed certificate signing request to the appropriate location.
    try
    {
      final PrintStream ps;
      if (outputFile == null)
      {
        ps = getOut();
      }
      else
      {
        ps = new PrintStream(outputFile);
      }

      if (outputPEM)
      {
        writePEMCertificate(ps, signedCertificate.getX509CertificateBytes());
      }
      else
      {
        ps.write(signedCertificate.getX509CertificateBytes());
      }

      if (outputFile != null)
      {
        ps.close();
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_GEN_CERT_ERROR_WRITING_SIGNED_CERT.get());
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }


    // If the certificate signing request was written to an output file,
    // then let the user know that it was successful.  If it was written to
    // standard output, then we don't need to tell them because they'll be
    // able to see it.
    if (outputFile != null)
    {
      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_GEN_CERT_SUCCESSFULLY_SIGNED_CERT.get(
                outputFile.getAbsolutePath()));
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the change-certificate-alias
   * subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doChangeCertificateAlias()
  {
    // Get the values of a number of configured arguments.
    final StringArgument currentAliasArgument =
         subCommandParser.getStringArgument("current-alias");
    final String currentAlias = currentAliasArgument.getValue();

    final StringArgument newAliasArgument =
         subCommandParser.getStringArgument("new-alias");
    final String newAlias = newAliasArgument.getValue();

    final String keystoreType;
    final File keystorePath = getKeystorePath();
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // See if we need to use a private key password that is different from the
    // keystore password.
    final char[] privateKeyPassword;
    try
    {
      privateKeyPassword =
           getPrivateKeyPassword(keystore, currentAlias, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Make sure that the keystore has an existing entry with the current alias.
    // It must be either a certificate entry or a private key entry.
    final Certificate existingCertificate;
    final Certificate[] existingCertificateChain;
    final PrivateKey existingPrivateKey;
    try
    {
      if (hasCertificateAlias(keystore, currentAlias))
      {
        existingCertificate = keystore.getCertificate(currentAlias);
        existingCertificateChain = null;
        existingPrivateKey = null;
      }
      else if (hasKeyAlias(keystore, currentAlias))
      {
        existingCertificateChain = keystore.getCertificateChain(currentAlias);
        existingPrivateKey =
             (PrivateKey) keystore.getKey(currentAlias, privateKeyPassword);
        existingCertificate = null;
      }
      else
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_CHANGE_ALIAS_NO_SUCH_ALIAS.get(currentAlias));
        return ResultCode.PARAM_ERROR;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHANGE_ALIAS_CANNOT_GET_EXISTING_ENTRY.get(
                currentAlias));
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }


    // Make sure that the keystore does not have an entry with the new alias.
    if (hasCertificateAlias(keystore, newAlias) ||
         hasKeyAlias(keystore, newAlias))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHANGE_ALIAS_NEW_ALIAS_IN_USE.get(newAlias));
      return ResultCode.PARAM_ERROR;
    }


    // Generate the keytool arguments to use to change the certificate alias.
    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    if ((displayKeytoolCommandArgument != null) &&
          displayKeytoolCommandArgument.isPresent())
    {
      final ArrayList<String> keytoolArguments = new ArrayList<>(30);
      keytoolArguments.add("-changealias");
      keytoolArguments.add("-keystore");
      keytoolArguments.add(keystorePath.getAbsolutePath());
      keytoolArguments.add("-storetype");
      keytoolArguments.add(keystoreType);
      keytoolArguments.add("-storepass");
      keytoolArguments.add("*****REDACTED*****");
      keytoolArguments.add("-keypass");
      keytoolArguments.add("*****REDACTED*****");
      keytoolArguments.add("-alias");
      keytoolArguments.add(currentAlias);
      keytoolArguments.add("-destalias");
      keytoolArguments.add(newAlias);

      displayKeytoolCommand(keytoolArguments);
    }


    // Update the keystore to remove the entry with the current alias and
    // re-write it with the new alias.
    try
    {
      keystore.deleteEntry(currentAlias);
      if (existingCertificate != null)
      {
        keystore.setCertificateEntry(newAlias, existingCertificate);
      }
      else
      {
        keystore.setKeyEntry(newAlias, existingPrivateKey,
             privateKeyPassword, existingCertificateChain);
      }

      writeKeystore(keystore, keystorePath, keystorePassword);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHANGE_ALIAS_CANNOT_UPDATE_KEYSTORE.get());
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }

    wrapOut(0, WRAP_COLUMN,
         INFO_MANAGE_CERTS_CHANGE_ALIAS_SUCCESSFUL.get(currentAlias,
              newAlias));
    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the change-keystore-password
   * subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doChangeKeystorePassword()
  {
    // Get the values of a number of configured arguments.
    final String keystoreType;
    final File keystorePath = getKeystorePath();
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] currentKeystorePassword;
    try
    {
      currentKeystorePassword = getKeystorePassword(keystorePath, "current");
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] newKeystorePassword;
    try
    {
      newKeystorePassword = getKeystorePassword(keystorePath, "new");
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath,
           currentKeystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Generate the keytool arguments to use to change the keystore password.
    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    if ((displayKeytoolCommandArgument != null) &&
          displayKeytoolCommandArgument.isPresent())
    {
      final ArrayList<String> keytoolArguments = new ArrayList<>(30);
      keytoolArguments.add("-storepasswd");
      keytoolArguments.add("-keystore");
      keytoolArguments.add(keystorePath.getAbsolutePath());
      keytoolArguments.add("-storetype");
      keytoolArguments.add(keystoreType);
      keytoolArguments.add("-storepass");
      keytoolArguments.add("*****REDACTED*****");
      keytoolArguments.add("-new");
      keytoolArguments.add("*****REDACTED*****");

      displayKeytoolCommand(keytoolArguments);
    }


    // Rewrite the keystore with the new password.
    try
    {
      writeKeystore(keystore, keystorePath, newKeystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    wrapOut(0, WRAP_COLUMN,
         INFO_MANAGE_CERTS_CHANGE_KS_PW_SUCCESSFUL.get(
              keystorePath.getAbsolutePath()));
    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the change-private-key-password
   * subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doChangePrivateKeyPassword()
  {
    // Get the values of a number of configured arguments.
    final StringArgument aliasArgument =
         subCommandParser.getStringArgument("alias");
    final String alias = aliasArgument.getValue();

    final String keystoreType;
    final File keystorePath = getKeystorePath();
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Make sure that the keystore has a key entry with the specified alias.
    if (hasCertificateAlias(keystore, alias))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHANGE_PK_PW_ALIAS_IS_CERT.get(alias));
      return ResultCode.PARAM_ERROR;
    }
    else if (! hasKeyAlias(keystore, alias))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHANGE_PK_PW_NO_SUCH_ALIAS.get(alias));
      return ResultCode.PARAM_ERROR;
    }


    // Get the current and new private key passwords.
    final char[] currentPrivateKeyPassword;
    try
    {
      currentPrivateKeyPassword =
           getPrivateKeyPassword(keystore, alias, "current", keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] newPrivateKeyPassword;
    try
    {
      newPrivateKeyPassword =
           getPrivateKeyPassword(keystore, alias, "new", keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Generate the keytool arguments to use to change the private key.
    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    if ((displayKeytoolCommandArgument != null) &&
          displayKeytoolCommandArgument.isPresent())
    {
      final ArrayList<String> keytoolArguments = new ArrayList<>(30);
      keytoolArguments.add("-keypasswd");
      keytoolArguments.add("-keystore");
      keytoolArguments.add(keystorePath.getAbsolutePath());
      keytoolArguments.add("-storetype");
      keytoolArguments.add(keystoreType);
      keytoolArguments.add("-storepass");
      keytoolArguments.add("*****REDACTED*****");
      keytoolArguments.add("-alias");
      keytoolArguments.add(alias);
      keytoolArguments.add("-keypass");
      keytoolArguments.add("*****REDACTED*****");
      keytoolArguments.add("-new");
      keytoolArguments.add("*****REDACTED*****");

      displayKeytoolCommand(keytoolArguments);
    }


    // Get the contents of the private key entry.
    final Certificate[] chain;
    final PrivateKey privateKey;
    try
    {
      chain = keystore.getCertificateChain(alias);
      privateKey =
           (PrivateKey) keystore.getKey(alias, currentPrivateKeyPassword);
    }
    catch (final UnrecoverableKeyException e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHANGE_PK_PW_WRONG_PK_PW.get(alias));
      return ResultCode.PARAM_ERROR;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHANGE_PK_PW_CANNOT_GET_PK.get(alias));
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }


    // Remove the existing key entry and re-add it with the new password.
    try
    {
      keystore.deleteEntry(alias);
      keystore.setKeyEntry(alias, privateKey, newPrivateKeyPassword, chain);
      writeKeystore(keystore, keystorePath, keystorePassword);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHANGE_PK_PW_CANNOT_UPDATE_KS.get());
      e.printStackTrace(getErr());
      return ResultCode.LOCAL_ERROR;
    }

    wrapOut(0, WRAP_COLUMN,
         INFO_MANAGE_CERTS_CHANGE_PK_PW_SUCCESSFUL.get(alias));
    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the retrieve-server-certificate
   * subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doRetrieveServerCertificate()
  {
    // Get the values of a number of configured arguments.
    final StringArgument hostnameArgument =
         subCommandParser.getStringArgument("hostname");
    final String hostname = hostnameArgument.getValue();

    final IntegerArgument portArgument =
         subCommandParser.getIntegerArgument("port");
    final int port = portArgument.getValue();

    final BooleanArgument useLDAPStartTLSArgument =
         subCommandParser.getBooleanArgument("use-ldap-start-tls");
    final boolean useLDAPStartTLS =
         ((useLDAPStartTLSArgument != null) &&
          useLDAPStartTLSArgument.isPresent());

    final BooleanArgument onlyPeerArgument =
         subCommandParser.getBooleanArgument("only-peer-certificate");
    final boolean onlyPeer =
         ((onlyPeerArgument != null) && onlyPeerArgument.isPresent());

    final BooleanArgument verboseArgument =
         subCommandParser.getBooleanArgument("verbose");
    final boolean verbose =
         ((verboseArgument != null) && verboseArgument.isPresent());

    boolean outputPEM = true;
    final StringArgument outputFormatArgument =
         subCommandParser.getStringArgument("output-format");
    if ((outputFormatArgument != null) && outputFormatArgument.isPresent())
    {
      final String format = outputFormatArgument.getValue().toLowerCase();
      if (format.equals("der") || format.equals("binary") ||
          format.equals("bin"))
      {
        outputPEM = false;
      }
    }

    File outputFile = null;
    final FileArgument outputFileArgument =
         subCommandParser.getFileArgument("output-file");
    if ((outputFileArgument != null) && outputFileArgument.isPresent())
    {
      outputFile = outputFileArgument.getValue();
    }


    // Spawn a background thread to establish a connection and get the
    // certificate chain from the target server.
    final LinkedBlockingQueue<Object> responseQueue =
         new LinkedBlockingQueue<>(10);
    final ManageCertificatesServerCertificateCollector certificateCollector =
         new ManageCertificatesServerCertificateCollector(this, hostname, port,
              useLDAPStartTLS, verbose, responseQueue);
    certificateCollector.start();

    Object responseObject =
         ERR_MANAGE_CERTS_RETRIEVE_CERT_NO_CERT_CHAIN_RECEIVED.get(
              hostname + ':' + port);
    try
    {
      responseObject = responseQueue.poll(90L, TimeUnit.SECONDS);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    final X509Certificate[] chain;
    if (responseObject instanceof  X509Certificate[])
    {
      chain = (X509Certificate[]) responseObject;
      if (chain.length == 0)
      {
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_RETRIEVE_CERT_EMPTY_CHAIN.get());
        return ResultCode.NO_RESULTS_RETURNED;
      }
    }
    else if (responseObject instanceof CertException)
    {
      // The error message will have already been recorded by the collector
      // thread, so we can just return a non-success result.
      return ResultCode.LOCAL_ERROR;
    }
    else
    {
      wrapErr(0, WRAP_COLUMN, String.valueOf(responseObject));
      return ResultCode.LOCAL_ERROR;
    }

    try
    {
      certificateCollector.join(10_000L);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // If the certificates should be written to a file, then do that now.
    if (outputFile != null)
    {
      try (PrintStream s = new PrintStream(outputFile))
      {
        for (final X509Certificate c : chain)
        {
          if (outputPEM)
          {
            writePEMCertificate(s, c.getX509CertificateBytes());
          }
          else
          {
            s.write(c.getX509CertificateBytes());
          }

          if (onlyPeer)
          {
            break;
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_RETRIEVE_CERT_CANNOT_WRITE_TO_FILE.get(
                  outputFile.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)));
        return ResultCode.LOCAL_ERROR;
      }
    }


    // Display information about the certificates.
    for (int i=0; i < chain.length; i++)
    {
      if (verbose || (i > 0))
      {
        out();
        out();
      }

      if ((! onlyPeer) && (chain.length > 1))
      {
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_RETRIEVE_CERT_DISPLAY_HEADER.get((i+1),
                  chain.length));
        out();
      }

      final X509Certificate c = chain[i];
      writePEMCertificate(getOut(), c.getX509CertificateBytes());
      out();
      printCertificate(c, "", verbose);

      if (onlyPeer)
      {
        break;
      }
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the trust-server-certificate
   * subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doTrustServerCertificate()
  {
    // Get the values of a number of configured arguments.
    final StringArgument hostnameArgument =
         subCommandParser.getStringArgument("hostname");
    final String hostname = hostnameArgument.getValue();

    final IntegerArgument portArgument =
         subCommandParser.getIntegerArgument("port");
    final int port = portArgument.getValue();

    final String alias;
    final StringArgument aliasArgument =
         subCommandParser.getStringArgument("alias");
    if ((aliasArgument != null) && aliasArgument.isPresent())
    {
      alias = aliasArgument.getValue();
    }
    else
    {
      alias = hostname + ':' + port;
    }

    final BooleanArgument useLDAPStartTLSArgument =
         subCommandParser.getBooleanArgument("use-ldap-start-tls");
    final boolean useLDAPStartTLS =
         ((useLDAPStartTLSArgument != null) &&
          useLDAPStartTLSArgument.isPresent());

    final BooleanArgument issuersOnlyArgument =
         subCommandParser.getBooleanArgument("issuers-only");
    final boolean issuersOnly =
         ((issuersOnlyArgument != null) && issuersOnlyArgument.isPresent());

    final BooleanArgument noPromptArgument =
         subCommandParser.getBooleanArgument("no-prompt");
    final boolean noPrompt =
         ((noPromptArgument != null) && noPromptArgument.isPresent());

    final BooleanArgument verboseArgument =
         subCommandParser.getBooleanArgument("verbose");
    final boolean verbose =
         ((verboseArgument != null) && verboseArgument.isPresent());

    final String keystoreType;
    final File keystorePath = getKeystorePath();
    final boolean isNewKeystore = (! keystorePath.exists());
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Make sure that the specified alias is not already in use.
    if (hasCertificateAlias(keystore, alias) ||
         hasKeyAlias(keystore, alias))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_TRUST_SERVER_ALIAS_IN_USE.get(alias));
      return ResultCode.PARAM_ERROR;
    }


    // Spawn a background thread to establish a connection and get the
    // certificate chain from the target server.
    final LinkedBlockingQueue<Object> responseQueue =
         new LinkedBlockingQueue<>(10);
    final ManageCertificatesServerCertificateCollector certificateCollector =
         new ManageCertificatesServerCertificateCollector(this, hostname, port,
              useLDAPStartTLS, verbose, responseQueue);
    certificateCollector.start();

    Object responseObject =
         ERR_MANAGE_CERTS_TRUST_SERVER_NO_CERT_CHAIN_RECEIVED.get(
              hostname + ':' + port);
    try
    {
      responseObject = responseQueue.poll(90L, TimeUnit.SECONDS);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    final X509Certificate[] chain;
    if (responseObject instanceof  X509Certificate[])
    {
      chain = (X509Certificate[]) responseObject;
    }
    else if (responseObject instanceof CertException)
    {
      // The error message will have already been recorded by the collector
      // thread, so we can just return a non-success result.
      return ResultCode.LOCAL_ERROR;
    }
    else
    {
      wrapErr(0, WRAP_COLUMN, String.valueOf(responseObject));
      return ResultCode.LOCAL_ERROR;
    }

    try
    {
      certificateCollector.join(10_000L);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // If we should prompt the user about whether to trust the certificates,
    // then do so now.
    if (! noPrompt)
    {
      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_TRUST_SERVER_RETRIEVED_CHAIN.get(
                hostname + ':' + port));

      boolean isFirst = true;
      for (final X509Certificate c : chain)
      {
        out();

        if (isFirst)
        {
          isFirst = false;
          if (issuersOnly && (chain.length > 1))
          {
            wrapOut(0, WRAP_COLUMN,
                 INFO_MANAGE_CERTS_TRUST_SERVER_NOTE_OMITTED.get());
            out();
          }
        }

        printCertificate(c, "", verbose);
      }

      out();

      try
      {
        if (! promptForYesNo(INFO_MANAGE_CERTS_TRUST_SERVER_PROMPT_TRUST.get()))
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_TRUST_SERVER_CHAIN_REJECTED.get());
          return ResultCode.USER_CANCELED;
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err();
        wrapErr(0, WRAP_COLUMN, le.getMessage());
        return le.getResultCode();
      }
    }


    // Add the certificates to the keystore.
    final LinkedHashMap<String,X509Certificate> certsByAlias =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(chain.length));
    for (int i=0; i < chain.length; i++)
    {
      if (i == 0)
      {
        if (issuersOnly && (chain.length > 1))
        {
          continue;
        }

        certsByAlias.put(alias, chain[i]);
      }
      else if ((i == 1) && (chain.length == 2))
      {
        certsByAlias.put(alias + "-issuer", chain[i]);
      }
      else
      {
        certsByAlias.put(alias + "-issuer-" + i, chain[i]);
      }
    }

    for (final Map.Entry<String,X509Certificate> e : certsByAlias.entrySet())
    {
      final String certAlias = e.getKey();
      final X509Certificate cert = e.getValue();

      try
      {
        Validator.ensureFalse(
             (hasCertificateAlias(keystore, certAlias) ||
                  hasKeyAlias(keystore, certAlias)),
             "ERROR:  Alias '" + certAlias + "' is already in use in the " +
                  "keystore.");
        keystore.setCertificateEntry(certAlias, cert.toCertificate());
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_TRUST_SERVER_ERROR_ADDING_CERT_TO_KS.get(
                  cert.getSubjectDN()));
        ex.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }
    }


    // Save the updated keystore.
    try
    {
      writeKeystore(keystore, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    if (isNewKeystore)
    {
      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_TRUST_SERVER_CERT_CREATED_KEYSTORE.get(
                getUserFriendlyKeystoreType(keystoreType)));
    }

    out();
    if (certsByAlias.size() == 1)
    {
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_TRUST_SERVER_ADDED_CERT_TO_KS.get());
    }
    else
    {
      wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_TRUST_SERVER_ADDED_CERTS_TO_KS.get(
                certsByAlias.size()));
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the check-certificate-usability
   * subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doCheckCertificateUsability()
  {
    // Get the values of a number of configured arguments.
    final StringArgument aliasArgument =
         subCommandParser.getStringArgument("alias");
    final String alias = aliasArgument.getValue();

    final String keystoreType;
    final File keystorePath = getKeystorePath();
    try
    {
      keystoreType = inferKeystoreType(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    final char[] keystorePassword;
    try
    {
      keystorePassword = getKeystorePassword(keystorePath);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Get the keystore.
    final KeyStore keystore;
    try
    {
      keystore = getKeystore(keystoreType, keystorePath, keystorePassword);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // Make sure that the specified entry exists in the keystore and is
    // associated with a certificate chain and a private key.
    final X509Certificate[] chain;
    if (hasKeyAlias(keystore, alias))
    {
      try
      {
        final Certificate[] genericChain = keystore.getCertificateChain(alias);
        Validator.ensureTrue((genericChain.length > 0),
             "ERROR:  The keystore has a private key entry for alias '" +
                  alias + "', but the associated certificate chain is empty.");

        chain = new X509Certificate[genericChain.length];
        for (int i=0; i < genericChain.length; i++)
        {
          chain[i] = new X509Certificate(genericChain[i].getEncoded());
        }

        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_CHECK_USABILITY_GOT_CHAIN.get(alias));

        for (final X509Certificate c : chain)
        {
          out();
          printCertificate(c, "", false);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_CHECK_USABILITY_CANNOT_GET_CHAIN.get(alias));
        e.printStackTrace(getErr());
        return ResultCode.LOCAL_ERROR;
      }
    }
    else if (hasCertificateAlias(keystore, alias))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHECK_USABILITY_NO_PRIVATE_KEY.get(alias));
      return ResultCode.PARAM_ERROR;
    }
    else
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHECK_USABILITY_NO_SUCH_ALIAS.get(alias));
      return ResultCode.PARAM_ERROR;
    }


    // Check to see if the certificate is self-signed.  If so, then that's a
    // warning.  If not, then make sure that the chain is complete and that each
    // subsequent certificate is the issuer of the previous.
    int numWarnings = 0;
    int numErrors = 0;
    if (chain[0].isSelfSigned())
    {
      err();
      wrapErr(0, WRAP_COLUMN,
           WARN_MANAGE_CERTS_CHECK_USABILITY_CERT_IS_SELF_SIGNED.get(
                chain[0].getSubjectDN()));
      numWarnings++;
    }
    else if ((chain.length == 1) || (! chain[chain.length - 1].isSelfSigned()))
    {
      err();
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_CHECK_USABILITY_END_OF_CHAIN_NOT_SELF_SIGNED.get(
                alias));
      numErrors++;
    }
    else
    {
      boolean chainError = false;
      final StringBuilder nonMatchReason = new StringBuilder();
      for (int i=1; i < chain.length; i++)
      {
        if (! chain[i].isIssuerFor(chain[i-1], nonMatchReason))
        {
          err();
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_CHECK_USABILITY_CHAIN_ISSUER_MISMATCH.get(
                    alias, chain[i].getSubjectDN(), chain[i-1].getSubjectDN(),
                    nonMatchReason));
          numErrors++;
          chainError = true;
        }
      }

      if (! chainError)
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_CHECK_USABILITY_CHAIN_COMPLETE.get());
      }
    }


    // If there are multiple certificates in the chain, and if the last
    // certificate in the chain is self-signed, then check to see if it is
    // contained in the JVM-default trust manager.  If it isn't, then we'll
    // display a notice, but we won't consider it a warning in and of itself.
    if ((chain.length > 1) && chain[chain.length-1].isSelfSigned())
    {
      final X509Certificate caCert = chain[chain.length-1];

      try
      {
        final String jvmDefaultTrustStoreType =
             inferKeystoreType(JVM_DEFAULT_CACERTS_FILE);
        final KeyStore jvmDefaultTrustStore =
             CryptoHelper.getKeyStore(jvmDefaultTrustStoreType);
        try (FileInputStream inputStream =
                  new FileInputStream(JVM_DEFAULT_CACERTS_FILE))
        {
          jvmDefaultTrustStore.load(inputStream, null);
        }

        boolean found = false;
        final Enumeration<String> aliases = jvmDefaultTrustStore.aliases();
        while (aliases.hasMoreElements())
        {
          final String jvmDefaultCertAlias = aliases.nextElement();
          if (jvmDefaultTrustStore.isCertificateEntry(jvmDefaultCertAlias))
          {
            final Certificate c =
                 jvmDefaultTrustStore.getCertificate(jvmDefaultCertAlias);
            final X509Certificate xc = new X509Certificate(c.getEncoded());
            if ((caCert.getSubjectDN().equals(xc.getSubjectDN())) &&
                 Arrays.equals(caCert.getSignatureValue().getBits(),
                      xc.getSignatureValue().getBits()))
            {
              found = true;
              break;
            }
          }
        }

        if (found)
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_CHECK_USABILITY_CA_TRUSTED_OK.get(
                    caCert.getSubjectDN()));
        }
        else
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_CHECK_USABILITY_CA_NOT_IN_JVM_DEFAULT_TS.get(
                    caCert.getSubjectDN()));
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err();
        wrapErr(0, WRAP_COLUMN,
             WARN_MANAGE_CERTS_CHECK_USABILITY_CHECK_CA_IN_TS_ERROR.get(
                  caCert.getSubjectDN(), StaticUtils.getExceptionMessage(e)));
        numWarnings++;
      }
    }


    // Make sure that the signature is valid for each certificate in the
    // chain.  If any certificate has an invalid signature, then that's an
    // error.
    for (int i=0; i < chain.length; i++)
    {
      final X509Certificate c = chain[i];

      try
      {
        if (c.isSelfSigned())
        {
          c.verifySignature(null);
        }
        else if ((i + 1) < chain.length)
        {
          c.verifySignature(chain[i+1]);
        }

        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_CHECK_USABILITY_CERT_SIGNATURE_VALID.get(
                  c.getSubjectDN()));
      }
      catch (final CertException ce)
      {
        err();
        wrapErr(0, WRAP_COLUMN, ce.getMessage());
        numErrors++;
      }
    }


    // Check the validity window for each certificate in the chain.  If any of
    // them is expired or not yet valid, then that's an error.  If any of them
    // will expire in the near future, then that's a warning.
    final long currentTime = System.currentTimeMillis();
    final long thirtyDaysFromNow =
         currentTime + (30L * 24L * 60L * 60L * 1000L);
    for (int i=0; i < chain.length; i++)
    {
      final X509Certificate c = chain[i];
      if (c.getNotBeforeTime() > currentTime)
      {
        err();
        if (i == 0)
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_CHECK_USABILITY_END_CERT_NOT_YET_VALID.get(
                    c.getSubjectDN(), formatDateAndTime(c.getNotBeforeDate())));
        }
        else
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_CHECK_USABILITY_ISSUER_CERT_NOT_YET_VALID.get(
                    c.getSubjectDN(), formatDateAndTime(c.getNotBeforeDate())));
        }

        numErrors++;
      }
      else if (c.getNotAfterTime() < currentTime)
      {
        err();
        if (i == 0)
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_CHECK_USABILITY_END_CERT_EXPIRED.get(
                    c.getSubjectDN(), formatDateAndTime(c.getNotAfterDate())));
        }
        else
        {
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_CHECK_USABILITY_ISSUER_CERT_EXPIRED.get(
                    c.getSubjectDN(), formatDateAndTime(c.getNotAfterDate())));
        }

        numErrors++;
      }
      else if (c.getNotAfterTime() < thirtyDaysFromNow)
      {
        err();
        if (i == 0)
        {
          wrapErr(0, WRAP_COLUMN,
               WARN_MANAGE_CERTS_CHECK_USABILITY_END_CERT_NEAR_EXPIRATION.get(
                    c.getSubjectDN(), formatDateAndTime(c.getNotAfterDate())));
        }
        else
        {
          wrapErr(0, WRAP_COLUMN,
               WARN_MANAGE_CERTS_CHECK_USABILITY_ISSUER_CERT_NEAR_EXPIRATION.
                    get(c.getSubjectDN(),
                         formatDateAndTime(c.getNotAfterDate())));
        }

        numWarnings++;
      }
      else
      {
        if (i == 0)
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_CHECK_USABILITY_END_CERT_VALIDITY_OK.get(
                    c.getSubjectDN(), formatDateAndTime(c.getNotAfterDate())));
        }
        else
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_CHECK_USABILITY_ISSUER_CERT_VALIDITY_OK.get(
                    c.getSubjectDN(), formatDateAndTime(c.getNotAfterDate())));
        }
      }
    }


    // Look at all of the extensions for all of the certificates and perform the
    // following validation:
    // - If the certificate at the head of the chain has an extended key usage
    //   extension, then make sure it includes the serverAuth usage.  If it
    //   does not include an extended key usage extension, then warn that it
    //   should.
    // - If any of the issuer certificates has a basic constraints extension,
    //   then make sure it indicates that the associated certificate is a
    //   certification authority.  Further, if it has a path length constraint,
    //   then make sure the chain does not exceed that length.  If any issuer
    //   certificate does not have a basic constraints extension, then warn that
    //   it should.
    // - If any of the issuer certificates has a key usage extension, then
    //   make sure it has the certSign usage.  If any issuer certificate does
    //   not have a key usage extension, then warn that it should.
    // - TODO:  If any certificate has a CRL distribution points extension, then
    //   retrieve the CRL and make sure the certificate hasn't been revoked.
    // - TODO:  If any certificate has an authority information access
    //   extension that points to an OCSP service, then consult that service to
    //   determine whether the certificate has been revoked.
    for (int i=0; i < chain.length; i++)
    {
      boolean basicConstraintsFound = false;
      boolean extendedKeyUsageFound = false;
      boolean keyUsageFound = false;
      final X509Certificate c = chain[i];
      for (final X509CertificateExtension extension : c.getExtensions())
      {
        if (extension instanceof ExtendedKeyUsageExtension)
        {
          extendedKeyUsageFound = true;
          if (i == 0)
          {
            final ExtendedKeyUsageExtension e =
                 (ExtendedKeyUsageExtension) extension;
            if (!e.getKeyPurposeIDs().contains(
                 ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID()))
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   ERR_MANAGE_CERTS_CHECK_USABILITY_END_CERT_BAD_EKU.get(
                        c.getSubjectDN()));
              numErrors++;
            }
            else
            {
              out();
              wrapOut(0, WRAP_COLUMN,
                   INFO_MANAGE_CERTS_CHECK_USABILITY_END_CERT_GOOD_EKU.get(
                        c.getSubjectDN()));
            }
          }
        }
        else if (extension instanceof BasicConstraintsExtension)
        {
          basicConstraintsFound = true;
          if (i > 0)
          {
            final BasicConstraintsExtension e =
                 (BasicConstraintsExtension) extension;
            if (!e.isCA())
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   ERR_MANAGE_CERTS_CHECK_USABILITY_ISSUER_CERT_BAD_BC_CA.get(
                        c.getSubjectDN()));
              numErrors++;
            }
            else if ((e.getPathLengthConstraint() != null) &&
                 ((i - 1) > e.getPathLengthConstraint()))
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   ERR_MANAGE_CERTS_CHECK_USABILITY_ISSUER_CERT_BAD_BC_LENGTH.
                        get(c.getSubjectDN(), e.getPathLengthConstraint(),
                             chain[0].getSubjectDN(), (i-1)));
              numErrors++;
            }
            else
            {
              out();
              wrapOut(0, WRAP_COLUMN,
                   INFO_MANAGE_CERTS_CHECK_USABILITY_ISSUER_CERT_GOOD_BC.get(
                        c.getSubjectDN()));
            }
          }
        }
        else if (extension instanceof KeyUsageExtension)
        {
          keyUsageFound = true;
          if (i > 0)
          {
            final KeyUsageExtension e = (KeyUsageExtension) extension;
            if (! e.isKeyCertSignBitSet())
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   ERR_MANAGE_CERTS_CHECK_USABILITY_ISSUER_NO_CERT_SIGN_KU.get(
                        c.getSubjectDN()));
              numErrors++;
            }
            else
            {
              out();
              wrapOut(0, WRAP_COLUMN,
                   INFO_MANAGE_CERTS_CHECK_USABILITY_ISSUER_GOOD_KU.get(
                        c.getSubjectDN()));
            }
          }
        }
      }

      if (i == 0)
      {
        if (! extendedKeyUsageFound)
        {
          err();
          wrapErr(0, WRAP_COLUMN,
               WARN_MANAGE_CERTS_CHECK_USABILITY_NO_EKU.get(
                    c.getSubjectDN()));
          numWarnings++;
        }
      }
      else
      {
        if (! basicConstraintsFound)
        {
          err();
          wrapErr(0, WRAP_COLUMN,
               WARN_MANAGE_CERTS_CHECK_USABILITY_NO_BC.get(
                    c.getSubjectDN()));
          numWarnings++;
        }

        if (! keyUsageFound)
        {
          err();
          wrapErr(0, WRAP_COLUMN,
               WARN_MANAGE_CERTS_CHECK_USABILITY_NO_KU.get(
                    c.getSubjectDN()));
          numWarnings++;
        }
      }
    }


    // Make sure that none of the certificates has a signature algorithm that
    // uses MD5 or SHA-1.  If it uses an unrecognized signature algorithm, then
    // that's a warning.
    boolean isIssuer = false;
    final BooleanArgument ignoreSHA1WarningArg =
         subCommandParser.getBooleanArgument(
              "allow-sha-1-signature-for-issuer-certificates");
    final boolean ignoreSHA1SignatureWarningForIssuerCertificates =
         ((ignoreSHA1WarningArg != null) && ignoreSHA1WarningArg.isPresent());
    for (final X509Certificate c : chain)
    {
      final OID signatureAlgorithmOID = c.getSignatureAlgorithmOID();
      final SignatureAlgorithmIdentifier id =
           SignatureAlgorithmIdentifier.forOID(signatureAlgorithmOID);
      if (id == null)
      {
        err();
        wrapErr(0, WRAP_COLUMN,
             WARN_MANAGE_CERTS_CHECK_USABILITY_UNKNOWN_SIG_ALG.get(
                  c.getSubjectDN(), signatureAlgorithmOID));
        numWarnings++;
      }
      else
      {
        switch (id)
        {
          case MD2_WITH_RSA:
          case MD5_WITH_RSA:
            err();
            wrapErr(0, WRAP_COLUMN,
                 ERR_MANAGE_CERTS_CHECK_USABILITY_WEAK_SIG_ALG.get(
                      c.getSubjectDN(), id.getUserFriendlyName()));
            numErrors++;
            break;

          case SHA_1_WITH_RSA:
          case SHA_1_WITH_DSA:
          case SHA_1_WITH_ECDSA:
            if (isIssuer && ignoreSHA1SignatureWarningForIssuerCertificates)
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   WARN_MANAGE_CERTS_CHECK_USABILITY_ISSUER_WITH_SHA1_SIG.get(
                        c.getSubjectDN(), id.getUserFriendlyName(),
                        ignoreSHA1WarningArg.getIdentifierString()));
            }
            else
            {
              err();
              wrapErr(0, WRAP_COLUMN,
                   ERR_MANAGE_CERTS_CHECK_USABILITY_WEAK_SIG_ALG.get(
                        c.getSubjectDN(), id.getUserFriendlyName()));
              numErrors++;
            }
            break;

          case SHA_224_WITH_RSA:
          case SHA_224_WITH_DSA:
          case SHA_224_WITH_ECDSA:
          case SHA_256_WITH_RSA:
          case SHA_256_WITH_DSA:
          case SHA_256_WITH_ECDSA:
          case SHA_384_WITH_RSA:
          case SHA_384_WITH_ECDSA:
          case SHA_512_WITH_RSA:
          case SHA_512_WITH_ECDSA:
            out();
            wrapOut(0, WRAP_COLUMN,
                 INFO_MANAGE_CERTS_CHECK_USABILITY_SIG_ALG_OK.get(
                      c.getSubjectDN(), id.getUserFriendlyName()));
            break;
        }
      }

      isIssuer = true;
    }


    // Make sure that none of the certificates that uses the RSA key algorithm
    // has a public modulus size smaller than 2048 bits.
    for (final X509Certificate c : chain)
    {
      if ((c.getDecodedPublicKey() != null) &&
          (c.getDecodedPublicKey() instanceof RSAPublicKey))
      {
        final RSAPublicKey rsaPublicKey =
             (RSAPublicKey) c.getDecodedPublicKey();
        final byte[] modulusBytes = rsaPublicKey.getModulus().toByteArray();
        int modulusSizeBits = modulusBytes.length * 8;
        if (((modulusBytes.length % 2) != 0) && (modulusBytes[0] == 0x00))
        {
          modulusSizeBits -= 8;
        }

        if (modulusSizeBits < 2048)
        {
          err();
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_CHECK_USABILITY_WEAK_RSA_MODULUS.get(
                    c.getSubjectDN(), modulusSizeBits));
          numErrors++;
        }
        else
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_CHECK_USABILITY_RSA_MODULUS_OK.get(
                    c.getSubjectDN(), modulusSizeBits));
        }
      }
    }


    switch (numErrors)
    {
      case 0:
        break;
      case 1:
        err();
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_CHECK_USABILITY_ONE_ERROR.get());
        return ResultCode.PARAM_ERROR;
      default:
        err();
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_CHECK_USABILITY_MULTIPLE_ERRORS.get(numErrors));
        return ResultCode.PARAM_ERROR;
    }

    switch (numWarnings)
    {
      case 0:
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_CHECK_USABILITY_NO_ERRORS_OR_WARNINGS.get());
        return ResultCode.SUCCESS;
      case 1:
        err();
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_CHECK_USABILITY_ONE_WARNING.get());
        return ResultCode.PARAM_ERROR;
      default:
        err();
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_CERTS_CHECK_USABILITY_MULTIPLE_WARNINGS.get(
                  numWarnings));
        return ResultCode.PARAM_ERROR;
    }
  }



  /**
   * Performs the necessary processing for the display-certificate-file
   * subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doDisplayCertificateFile()
  {
    // Get the values of a number of configured arguments.
    final FileArgument certificateFileArgument =
         subCommandParser.getFileArgument("certificate-file");
    final File certificateFile = certificateFileArgument.getValue();

    final BooleanArgument verboseArgument =
         subCommandParser.getBooleanArgument("verbose");
    final boolean verbose =
         ((verboseArgument != null) && verboseArgument.isPresent());

    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    if ((displayKeytoolCommandArgument != null) &&
        displayKeytoolCommandArgument.isPresent())
    {
      final ArrayList<String> keytoolArgs = new ArrayList<>(10);
      keytoolArgs.add("-printcert");
      keytoolArgs.add("-file");
      keytoolArgs.add(certificateFile.getAbsolutePath());

      if (verbose)
      {
        keytoolArgs.add("-v");
      }

      displayKeytoolCommand(keytoolArgs);
    }


    // Read the certificates from the specified file.
    final List<X509Certificate> certificates;
    try
    {
      certificates = readCertificatesFromFile(certificateFile);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }


    // If there aren't any certificates in the file, print that.
    if (certificates.isEmpty())
    {
      wrapOut(0, WRAP_COLUMN, INFO_MANAGE_CERTS_DISPLAY_CERT_NO_CERTS.get(
           certificateFile.getAbsolutePath()));
    }
    else
    {
      for (final X509Certificate c : certificates)
      {
        out();
        printCertificate(c, "", verbose);
      }
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary processing for the
   * display-certificate-signing-request-file subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doDisplayCertificateSigningRequestFile()
  {
    // Get the values of a number of configured arguments.
    final FileArgument csrFileArgument =
         subCommandParser.getFileArgument("certificate-signing-request-file");
    final File csrFile = csrFileArgument.getValue();

    final BooleanArgument verboseArgument =
         subCommandParser.getBooleanArgument("verbose");
    final boolean verbose =
         ((verboseArgument != null) && verboseArgument.isPresent());

    final BooleanArgument displayKeytoolCommandArgument =
         subCommandParser.getBooleanArgument("display-keytool-command");
    if ((displayKeytoolCommandArgument != null) &&
        displayKeytoolCommandArgument.isPresent())
    {
      final ArrayList<String> keytoolArgs = new ArrayList<>(10);
      keytoolArgs.add("-printcertreq");
      keytoolArgs.add("-file");
      keytoolArgs.add(csrFile.getAbsolutePath());
      keytoolArgs.add("-v");

      displayKeytoolCommand(keytoolArgs);
    }


    // Read the certificate signing request from the specified file.
    final PKCS10CertificateSigningRequest csr;
    try
    {
      csr = readCertificateSigningRequestFromFile(csrFile);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      wrapErr(0, WRAP_COLUMN, le.getMessage());
      return le.getResultCode();
    }

    out();
    printCertificateSigningRequest(csr, verbose, "");

    return ResultCode.SUCCESS;
  }



  /**
   * Prints a string representation of the provided certificate to standard
   * output.
   *
   * @param  certificate  The certificate to be printed.
   * @param  indent       The string to place at the beginning of each line to
   *                      indent that line.
   * @param  verbose      Indicates whether to display verbose information about
   *                      the certificate.
   */
  private void printCertificate(@NotNull final X509Certificate certificate,
                                @NotNull final String indent,
                                final boolean verbose)
  {
    if (verbose)
    {
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_VERSION.get(
                certificate.getVersion().getName()));
    }

    out(indent +
         INFO_MANAGE_CERTS_PRINT_CERT_LABEL_SUBJECT_DN.get(
              certificate.getSubjectDN()));
    out(indent +
         INFO_MANAGE_CERTS_PRINT_CERT_LABEL_ISSUER_DN.get(
              certificate.getIssuerDN()));

    if (verbose)
    {
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_SERIAL_NUMBER.get(
                toColonDelimitedHex(
                     certificate.getSerialNumber().toByteArray())));
    }

    out(indent +
         INFO_MANAGE_CERTS_PRINT_CERT_LABEL_VALIDITY_START.get(
              formatDateAndTime(certificate.getNotBeforeDate())));
    out(indent +
         INFO_MANAGE_CERTS_PRINT_CERT_LABEL_VALIDITY_END.get(
              formatDateAndTime(certificate.getNotAfterDate())));

    final long currentTime = System.currentTimeMillis();
    if (currentTime < certificate.getNotBeforeTime())
    {
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_VALIDITY_STATE_NOT_YET_VALID.
                get());
    }
    else if (currentTime > certificate.getNotAfterTime())
    {
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_VALIDITY_STATE_EXPIRED.get());
    }
    else
    {
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_VALIDITY_STATE_VALID.get());
    }

    out(indent +
         INFO_MANAGE_CERTS_PRINT_CERT_LABEL_SIG_ALG.get(
              certificate.getSignatureAlgorithmNameOrOID()));
    if (verbose)
    {
      String signatureString;
      try
      {
        signatureString =
             toColonDelimitedHex(certificate.getSignatureValue().getBytes());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        signatureString = certificate.getSignatureValue().toString();
      }
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_SIG_VALUE.get());
      for (final String line : StaticUtils.wrapLine(signatureString, 78))
      {
        out(indent + "     " + line);
      }
    }

    final String pkAlg;
    final String pkSummary = getPublicKeySummary(
         certificate.getPublicKeyAlgorithmOID(),
         certificate.getDecodedPublicKey(),
         certificate.getPublicKeyAlgorithmParameters());
    if (pkSummary == null)
    {
      pkAlg = certificate.getPublicKeyAlgorithmNameOrOID();
    }
    else
    {
      pkAlg = certificate.getPublicKeyAlgorithmNameOrOID() + " (" +
           pkSummary + ')';
    }
    out(indent + INFO_MANAGE_CERTS_PRINT_CERT_LABEL_PK_ALG.get(pkAlg));

    if (verbose)
    {
      printPublicKey(certificate.getEncodedPublicKey(),
           certificate.getDecodedPublicKey(),
           certificate.getPublicKeyAlgorithmParameters(), indent);

      if (certificate.getSubjectUniqueID() != null)
      {
        String subjectUniqueID;
        try
        {
          subjectUniqueID = toColonDelimitedHex(
               certificate.getSubjectUniqueID().getBytes());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          subjectUniqueID = certificate.getSubjectUniqueID().toString();
        }

        out(indent +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_SUBJECT_UNIQUE_ID.get());
        for (final String line : StaticUtils.wrapLine(subjectUniqueID, 78))
        {
          out(indent + "     " + line);
        }
      }

      if (certificate.getIssuerUniqueID() != null)
      {
        String issuerUniqueID;
        try
        {
          issuerUniqueID = toColonDelimitedHex(
               certificate.getIssuerUniqueID().getBytes());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          issuerUniqueID = certificate.getIssuerUniqueID().toString();
        }

        out(indent +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_ISSUER_UNIQUE_ID.get());
        for (final String line : StaticUtils.wrapLine(issuerUniqueID, 78))
        {
          out(indent + "     " + line);
        }
      }

      printExtensions(certificate.getExtensions(), indent);
    }

    try
    {
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_FINGERPRINT.get("SHA-1",
                toColonDelimitedHex(certificate.getSHA1Fingerprint())));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    try
    {
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_FINGERPRINT.get("SHA-256",
                toColonDelimitedHex(certificate.getSHA256Fingerprint())));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * Prints a string representation of the provided certificate signing request
   * to standard output.
   *
   * @param  csr      The certificate signing request to be printed.
   * @param  verbose  Indicates whether to display verbose information about
   *                  the contents of the request.
   * @param  indent   The string to place at the beginning of each line to
   *                  indent that line.
   */
  private void printCertificateSigningRequest(
                    @NotNull final PKCS10CertificateSigningRequest csr,
                    final boolean verbose, @NotNull final String indent)
  {
    out(indent +
         INFO_MANAGE_CERTS_PRINT_CSR_LABEL_VERSION.get(
              csr.getVersion().getName()));
    out(indent +
         INFO_MANAGE_CERTS_PRINT_CERT_LABEL_SUBJECT_DN.get(
              csr.getSubjectDN()));
    out(indent +
         INFO_MANAGE_CERTS_PRINT_CERT_LABEL_SIG_ALG.get(
              csr.getSignatureAlgorithmNameOrOID()));

    if (verbose)
    {
      String signatureString;
      try
      {
        signatureString =
             toColonDelimitedHex(csr.getSignatureValue().getBytes());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        signatureString = csr.getSignatureValue().toString();
      }
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_SIG_VALUE.get());
      for (final String line : StaticUtils.wrapLine(signatureString, 78))
      {
        out(indent + "     " + line);
      }
    }

    final String pkAlg;
    final String pkSummary = getPublicKeySummary(csr.getPublicKeyAlgorithmOID(),
         csr.getDecodedPublicKey(), csr.getPublicKeyAlgorithmParameters());
    if (pkSummary == null)
    {
      pkAlg = csr.getPublicKeyAlgorithmNameOrOID();
    }
    else
    {
      pkAlg = csr.getPublicKeyAlgorithmNameOrOID() + " (" +
           pkSummary + ')';
    }
    out(indent + INFO_MANAGE_CERTS_PRINT_CERT_LABEL_PK_ALG.get(pkAlg));

    if (verbose)
    {
      printPublicKey(csr.getEncodedPublicKey(), csr.getDecodedPublicKey(),
           csr.getPublicKeyAlgorithmParameters(), indent);
      printExtensions(csr.getExtensions(), indent);
    }
  }



  /**
   * Prints information about the provided public key.
   *
   * @param  encodedPublicKey  The encoded representation of the public key.
   *                           This must not be {@code null}.
   * @param  decodedPublicKey  The decoded representation of the public key, if
   *                           available.
   * @param  parameters        The public key algorithm parameters, if any.
   * @param  indent            The string to place at the beginning of each
   *                           line to indent that line.
   */
  private void printPublicKey(@NotNull final ASN1BitString encodedPublicKey,
                              @Nullable final DecodedPublicKey decodedPublicKey,
                              @Nullable final ASN1Element parameters,
                              @NotNull final String indent)
  {
    if (decodedPublicKey == null)
    {
      String pkString;
      try
      {
        pkString = toColonDelimitedHex(encodedPublicKey.getBytes());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        pkString = encodedPublicKey.toString();
      }

      out(indent + INFO_MANAGE_CERTS_PRINT_CERT_LABEL_ENCODED_PK.get());
      for (final String line : StaticUtils.wrapLine(pkString, 78))
      {
        out(indent + "     " + line);
      }

      return;
    }

    if (decodedPublicKey instanceof RSAPublicKey)
    {
      final RSAPublicKey rsaPublicKey = (RSAPublicKey) decodedPublicKey;
      final byte[] modulusBytes = rsaPublicKey.getModulus().toByteArray();

      int modulusSizeBits = modulusBytes.length * 8;
      if (((modulusBytes.length % 2) != 0) && (modulusBytes[0] == 0x00))
      {
        modulusSizeBits -= 8;
      }

      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_RSA_MODULUS.get(
                modulusSizeBits));
      final String modulusHex = toColonDelimitedHex(modulusBytes);
      for (final String line : StaticUtils.wrapLine(modulusHex, 78))
      {
        out(indent + "     " + line);
      }

      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_RSA_EXPONENT.get(
                toColonDelimitedHex(
                     rsaPublicKey.getPublicExponent().toByteArray())));
    }
    else if (decodedPublicKey instanceof EllipticCurvePublicKey)
    {
      final EllipticCurvePublicKey ecPublicKey =
           (EllipticCurvePublicKey) decodedPublicKey;

      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EC_IS_COMPRESSED.get(
                String.valueOf(ecPublicKey.usesCompressedForm())));
      out(indent +
           INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EC_X.get(
                String.valueOf(ecPublicKey.getXCoordinate())));
      if (ecPublicKey.getYCoordinate() == null)
      {
        out(indent +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EC_Y_IS_EVEN.get(
                  String.valueOf(ecPublicKey.yCoordinateIsEven())));
      }
      else
      {
        out(indent +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EC_Y.get(
                  String.valueOf(ecPublicKey.getYCoordinate())));
      }
    }
  }



  /**
   * Retrieves a short summary of the provided public key, if available.  For
   * RSA keys, this will be the modulus size in bits.  For elliptic curve keys,
   * this will be the named curve, if available.
   *
   * @param  publicKeyAlgorithmOID  The OID that identifies the type of public
   *                                key.
   * @param  publicKey              The decoded public key.  This may be
   *                                {@code null} if the decoded public key is
   *                                not available.
   * @param  parameters             The encoded public key algorithm parameters.
   *                                This may be {@code null} if no public key
   *                                algorithm parameters are available.
   *
   * @return  A short summary of the provided public key, or {@code null} if
   *          no summary is available.
   */
  @NotNull()
  private static String getPublicKeySummary(
                             @NotNull final OID publicKeyAlgorithmOID,
                             @Nullable final DecodedPublicKey publicKey,
                             @Nullable final ASN1Element parameters)
  {
    if (publicKey instanceof RSAPublicKey)
    {
      final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
      final byte[] modulusBytes = rsaPublicKey.getModulus().toByteArray();

      int modulusSizeBits = modulusBytes.length * 8;
      if (((modulusBytes.length % 2) != 0) && (modulusBytes[0] == 0x00))
      {
        modulusSizeBits -= 8;
      }

      return INFO_MANAGE_CERTS_GET_PK_SUMMARY_RSA_MODULUS_SIZE.get(
           modulusSizeBits);
    }
    else if ((parameters != null) &&
         publicKeyAlgorithmOID.equals(PublicKeyAlgorithmIdentifier.EC.getOID()))
    {
      try
      {
        final OID namedCurveOID =
             parameters.decodeAsObjectIdentifier().getOID();
        return NamedCurve.getNameOrOID(namedCurveOID);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return null;
  }



  /**
   * Prints information about the provided extensions.
   *
   * @param  extensions  The list of extensions to be printed.
   * @param  indent      The string to place at the beginning of each line to
   *                     indent that line.
   */
  void printExtensions(@NotNull final List<X509CertificateExtension> extensions,
                       @NotNull final String indent)
  {
    if (extensions.isEmpty())
    {
      return;
    }

    out(indent + INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXTENSIONS.get());
    for (final X509CertificateExtension extension : extensions)
    {
      if (extension instanceof AuthorityKeyIdentifierExtension)
      {
        out(indent + "     " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_AUTH_KEY_ID_EXT.get());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_OID.get(
                  extension.getOID().toString()));
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IS_CRITICAL.get(
                  String.valueOf(extension.isCritical())));

        final AuthorityKeyIdentifierExtension e =
             (AuthorityKeyIdentifierExtension) extension;
        if (e.getKeyIdentifier() != null)
        {
          out(indent + "          " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_AUTH_KEY_ID_ID.get());
          final String idHex =
               toColonDelimitedHex(e.getKeyIdentifier().getValue());
          for (final String line : StaticUtils.wrapLine(idHex, 78))
          {
            out(indent + "               " + line);
          }
        }

        if (e.getAuthorityCertIssuer() != null)
        {
          out(indent + "          " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_AUTH_KEY_ID_ISSUER.
                    get());
          printGeneralNames(e.getAuthorityCertIssuer(),
               indent + "               ");
        }

        if (e.getAuthorityCertSerialNumber() != null)
        {
          out(indent + "          " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_AUTH_KEY_ID_SERIAL.get(
                    toColonDelimitedHex(e.getAuthorityCertSerialNumber().
                         toByteArray())));
        }
      }
      else if (extension instanceof BasicConstraintsExtension)
      {
        out(indent + "     " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_BASIC_CONST_EXT.get());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_OID.get(
                  extension.getOID().toString()));
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IS_CRITICAL.get(
                  String.valueOf(extension.isCritical())));

        final BasicConstraintsExtension e =
             (BasicConstraintsExtension) extension;
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_BASIC_CONST_IS_CA.get(
                  String.valueOf(e.isCA())));

        if (e.getPathLengthConstraint() != null)
        {
          out(indent + "          " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_BASIC_CONST_LENGTH.get(
                    e.getPathLengthConstraint()));
        }
      }
      else if (extension instanceof CRLDistributionPointsExtension)
      {
        out(indent + "     " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_CRL_DP_EXT.get());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_OID.get(
                  extension.getOID().toString()));
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IS_CRITICAL.get(
                  String.valueOf(extension.isCritical())));

        final CRLDistributionPointsExtension crlDPE =
             (CRLDistributionPointsExtension) extension;
        for (final CRLDistributionPoint dp :
             crlDPE.getCRLDistributionPoints())
        {
          out(indent + "          " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_CRL_DP_HEADER.get());
          if (dp.getFullName() != null)
          {
            out(indent + "               " +
                 INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_CRL_DP_FULL_NAME.
                      get());
            printGeneralNames(dp.getFullName(),
                 indent + "                    ");
          }

          if (dp.getNameRelativeToCRLIssuer() != null)
          {
            out(indent + "               " +
                 INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_CRL_DP_REL_NAME.get(
                      dp.getNameRelativeToCRLIssuer()));
          }

          if (! dp.getPotentialRevocationReasons().isEmpty())
          {
            out(indent + "               " +
                 INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_CRL_DP_REASON.get());
            for (final CRLDistributionPointRevocationReason r :
                 dp.getPotentialRevocationReasons())
            {
              out(indent + "                    " + r.getName());
            }
          }

          if (dp.getCRLIssuer() != null)
          {
            out(indent + "              " +
                 INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_CRL_DP_CRL_ISSUER.
                      get());
            printGeneralNames(dp.getCRLIssuer(),
                 indent + "                    ");
          }
        }
      }
      else if (extension instanceof ExtendedKeyUsageExtension)
      {
        out(indent + "     " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_EKU_EXT.get());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_OID.get(
                  extension.getOID().toString()));
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IS_CRITICAL.get(
                  String.valueOf(extension.isCritical())));

        final ExtendedKeyUsageExtension e =
             (ExtendedKeyUsageExtension) extension;
        for (final OID oid : e.getKeyPurposeIDs())
        {
          final ExtendedKeyUsageID id = ExtendedKeyUsageID.forOID(oid);
          if (id == null)
          {
            out(indent + "          " +
                 INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_EKU_ID.get(oid));
          }
          else
          {
            out(indent + "          " +
                 INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_EKU_ID.get(
                      id.getName()));
          }
        }
      }
      else if (extension instanceof IssuerAlternativeNameExtension)
      {
        out(indent + "     " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IAN_EXT.get());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_OID.get(
                  extension.getOID().toString()));
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IS_CRITICAL.get(
                  String.valueOf(extension.isCritical())));

        final IssuerAlternativeNameExtension e =
             (IssuerAlternativeNameExtension) extension;
        printGeneralNames(e.getGeneralNames(), indent + "          ");
      }
      else if (extension instanceof KeyUsageExtension)
      {
        out(indent + "     " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_EXT.get());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_OID.get(
                  extension.getOID().toString()));
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IS_CRITICAL.get(
                  String.valueOf(extension.isCritical())));

        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_USAGES.get());
        final KeyUsageExtension kue = (KeyUsageExtension) extension;
        if (kue.isDigitalSignatureBitSet())
        {
          out(indent + "               " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_DS.get());
        }

        if (kue.isNonRepudiationBitSet())
        {
          out(indent + "               " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_NR.get());
        }

        if (kue.isKeyEnciphermentBitSet())
        {
          out(indent + "               " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_KE.get());
        }

        if (kue.isDataEnciphermentBitSet())
        {
          out(indent + "               " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_DE.get());
        }

        if (kue.isKeyAgreementBitSet())
        {
          out(indent + "               " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_KA.get());
        }

        if (kue.isKeyCertSignBitSet())
        {
          out(indent + "               " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_KCS.get());
        }

        if (kue.isCRLSignBitSet())
        {
          out(indent + "               " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_CRL_SIGN.get());
        }

        if (kue.isEncipherOnlyBitSet())
        {
          out(indent + "               " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_EO.get());
        }

        if (kue.isDecipherOnlyBitSet())
        {
          out(indent + "               " +
               INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_KU_DO.get());
        }
      }
      else if (extension instanceof SubjectAlternativeNameExtension)
      {
        out(indent + "     " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_SAN_EXT.get());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_OID.get(
                  extension.getOID().toString()));
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IS_CRITICAL.get(
                  String.valueOf(extension.isCritical())));

        final SubjectAlternativeNameExtension e =
             (SubjectAlternativeNameExtension) extension;
        printGeneralNames(e.getGeneralNames(), indent + "          ");
      }
      else if (extension instanceof SubjectKeyIdentifierExtension)
      {
        out(indent + "     " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_SKI_EXT.get());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_OID.get(
                  extension.getOID().toString()));
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IS_CRITICAL.get(
                  String.valueOf(extension.isCritical())));

        final SubjectKeyIdentifierExtension e =
             (SubjectKeyIdentifierExtension) extension;
        final String idHex =
             toColonDelimitedHex(e.getKeyIdentifier().getValue());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_SKI_ID.get());
        for (final String line  : StaticUtils.wrapLine(idHex, 78))
        {
          out(indent + "               " + line);
        }
      }
      else
      {
        out(indent + "     " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_GENERIC.get());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_OID.get(
                  extension.getOID().toString()));
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_IS_CRITICAL.get(
                  String.valueOf(extension.isCritical())));

        final String valueHex = toColonDelimitedHex(extension.getValue());
        out(indent + "          " +
             INFO_MANAGE_CERTS_PRINT_CERT_LABEL_EXT_VALUE.get());
        getOut().print(StaticUtils.toHexPlusASCII(extension.getValue(),
             (indent.length() + 15)));
      }
    }
  }



  /**
   * Prints information about the contents of the provided general names object.
   *
   * @param  generalNames  The general names object to print.
   * @param  indent        The string to place at the beginning of each line to
   *                       indent that line.
   */
  private void printGeneralNames(@NotNull final GeneralNames generalNames,
                                 @NotNull final String indent)
  {
    for (final String dnsName : generalNames.getDNSNames())
    {
      out(indent + INFO_MANAGE_CERTS_GENERAL_NAMES_LABEL_DNS.get(dnsName));
    }

    for (final InetAddress ipAddress : generalNames.getIPAddresses())
    {
      out(indent +
           INFO_MANAGE_CERTS_GENERAL_NAMES_LABEL_IP.get(
                ipAddress.getHostAddress()));
    }

    for (final String name : generalNames.getRFC822Names())
    {
      out(indent +
           INFO_MANAGE_CERTS_GENERAL_NAMES_LABEL_RFC_822_NAME.get(name));
    }

    for (final DN dn : generalNames.getDirectoryNames())
    {
      out(indent +
           INFO_MANAGE_CERTS_GENERAL_NAMES_LABEL_DIRECTORY_NAME.get(
                String.valueOf(dn)));
    }

    for (final String uri : generalNames.getUniformResourceIdentifiers())
    {
      out(indent + INFO_MANAGE_CERTS_GENERAL_NAMES_LABEL_URI.get(uri));
    }

    for (final OID oid : generalNames.getRegisteredIDs())
    {
      out(indent +
           INFO_MANAGE_CERTS_GENERAL_NAMES_LABEL_REGISTERED_ID.get(
                oid.toString()));
    }

    if (! generalNames.getOtherNames().isEmpty())
    {
      out(indent +
           INFO_MANAGE_CERTS_GENERAL_NAMES_LABEL_OTHER_NAME_COUNT.get(
                generalNames.getOtherNames().size()));
    }

    if (! generalNames.getX400Addresses().isEmpty())
    {
      out(indent +
           INFO_MANAGE_CERTS_GENERAL_NAMES_LABEL_X400_ADDR_COUNT.get(
                generalNames.getX400Addresses().size()));
    }

    if (! generalNames.getEDIPartyNames().isEmpty())
    {
      out(indent +
           INFO_MANAGE_CERTS_GENERAL_NAMES_LABEL_EDI_PARTY_NAME_COUNT.get(
                generalNames.getEDIPartyNames().size()));
    }
  }



  /**
   * Writes a PEM-encoded representation of the provided encoded certificate to
   * the given print stream.
   *
   * @param  printStream         The print stream to which the PEM-encoded
   *                             certificate should be written.  It must not be
   *                             {@code null}.
   * @param  encodedCertificate  The bytes that comprise the encoded
   *                             certificate.  It must not be {@code null}.
   */
  private static void writePEMCertificate(
                           @NotNull final PrintStream printStream,
                           @NotNull final byte[] encodedCertificate)
  {
    final String certBase64 = Base64.encode(encodedCertificate);
    printStream.println("-----BEGIN CERTIFICATE-----");
    for (final String line : StaticUtils.wrapLine(certBase64, 64))
    {
      printStream.println(line);
    }
    printStream.println("-----END CERTIFICATE-----");
  }



  /**
   * Writes a PEM-encoded representation of the provided encoded certificate
   * signing request to the given print stream.
   *
   * @param  printStream  The print stream to which the PEM-encoded certificate
   *                      signing request should be written.  It must not be
   *                      {@code null}.
   * @param  encodedCSR   The bytes that comprise the encoded certificate
   *                      signing request.  It must not be {@code null}.
   */
  private static void writePEMCertificateSigningRequest(
                           @NotNull final PrintStream printStream,
                           @NotNull final byte[] encodedCSR)
  {
    final String certBase64 = Base64.encode(encodedCSR);
    printStream.println("-----BEGIN CERTIFICATE REQUEST-----");
    for (final String line : StaticUtils.wrapLine(certBase64, 64))
    {
      printStream.println(line);
    }
    printStream.println("-----END CERTIFICATE REQUEST-----");
  }



  /**
   * Writes a PEM-encoded representation of the provided encoded private key to
   * the given print stream.
   *
   * @param  printStream        The print stream to which the PEM-encoded
   *                            private key should be written.  It must not be
   *                            {@code null}.
   * @param  encodedPrivateKey  The bytes that comprise the encoded private key.
   *                            It must not be {@code null}.
   */
  private static void writePEMPrivateKey(
                           @NotNull final PrintStream printStream,
                           @NotNull final byte[] encodedPrivateKey)
  {
    final String certBase64 = Base64.encode(encodedPrivateKey);
    printStream.println("-----BEGIN PRIVATE KEY-----");
    for (final String line : StaticUtils.wrapLine(certBase64, 64))
    {
      printStream.println(line);
    }
    printStream.println("-----END PRIVATE KEY-----");
  }



  /**
   * Displays the keytool command that can be invoked to produce approximately
   * equivalent functionality.
   *
   * @param  keytoolArgs  The arguments to provide to the keytool command.
   */
  private void displayKeytoolCommand(@NotNull final List<String> keytoolArgs)
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append("#      keytool");

    boolean lastWasArgName = false;
    for (final String arg : keytoolArgs)
    {
      if (arg.startsWith("-"))
      {
        buffer.append(' ');
        buffer.append(StaticUtils.getCommandLineContinuationString());
        buffer.append(StaticUtils.EOL);
        buffer.append("#           ");
        buffer.append(arg);
        lastWasArgName = true;
      }
      else if (lastWasArgName)
      {
        buffer.append(' ');
        buffer.append(StaticUtils.cleanExampleCommandLineArgument(arg));
        lastWasArgName = false;
      }
      else
      {
        buffer.append(' ');
        buffer.append(StaticUtils.getCommandLineContinuationString());
        buffer.append(StaticUtils.EOL);
        buffer.append("#           ");
        buffer.append(arg);
        lastWasArgName = false;
      }
    }

    out();
    out(INFO_MANAGE_CERTS_APPROXIMATE_KEYTOOL_COMMAND.get());
    out(buffer);
    out();
  }



  /**
   * Retrieves the path to the target keystore file.
   *
   * @return  The path to the target keystore file, or {@code null} if no
   *          keystore path was configured.
   */
  @Nullable()
  private File getKeystorePath()
  {
    final FileArgument keystoreArgument =
         subCommandParser.getFileArgument("keystore");
    if ((keystoreArgument != null) && keystoreArgument.isPresent())
    {
      return keystoreArgument.getValue();
    }

    final BooleanArgument useJVMDefaultTrustStoreArgument =
         subCommandParser.getBooleanArgument("useJVMDefaultTrustStore");
    if ((useJVMDefaultTrustStoreArgument != null) &&
         useJVMDefaultTrustStoreArgument.isPresent())
    {
      return JVM_DEFAULT_CACERTS_FILE;
    }

    return null;
  }



  /**
   * Retrieves the password needed to access the keystore.
   *
   * @param  keystoreFile  The path to the keystore file for which to get the
   *                       password.
   *
   * @return  The password needed to access the keystore, or {@code null} if
   *          no keystore password was configured.
   *
   * @throws  LDAPException  If a problem is encountered while trying to get the
   *                         keystore password.
   */
  @Nullable()
  private char[] getKeystorePassword(@NotNull final File keystoreFile)
          throws LDAPException
  {
    return getKeystorePassword(keystoreFile, null);
  }



  /**
   * Retrieves the password needed to access the keystore.
   *
   * @param  keystoreFile  The path to the keystore file for which to get the
   *                       password.
   * @param  prefix        The prefix string to use for the arguments.  This may
   *                       be {@code null} if no prefix is needed.
   *
   * @return  The password needed to access the keystore, or {@code null} if
   *          no keystore password was configured.
   *
   * @throws  LDAPException  If a problem is encountered while trying to get the
   *                         keystore password.
   */
  @Nullable()
  private char[] getKeystorePassword(@NotNull final File keystoreFile,
                                     @Nullable final String prefix)
          throws LDAPException
  {
    final String prefixDash;
    if (prefix == null)
    {
      prefixDash = "";
    }
    else
    {
      prefixDash = prefix + '-';
    }

    final StringArgument keystorePasswordArgument =
         subCommandParser.getStringArgument(prefixDash + "keystore-password");
    if ((keystorePasswordArgument != null) &&
         keystorePasswordArgument.isPresent())
    {
      final char[] keystorePWChars =
           keystorePasswordArgument.getValue().toCharArray();
      if ((! keystoreFile.exists()) && (keystorePWChars.length < 6))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MANAGE_CERTS_GET_KS_PW_TOO_SHORT.get());
      }

      return keystorePWChars;
    }


    final FileArgument keystorePasswordFileArgument =
         subCommandParser.getFileArgument(
              prefixDash + "keystore-password-file");
    if ((keystorePasswordFileArgument != null) &&
        keystorePasswordFileArgument.isPresent())
    {
      final File f = keystorePasswordFileArgument.getValue();
      try
      {
        final char[] passwordChars = getPasswordFileReader().readPassword(f);
        if (passwordChars.length < 6)
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_MANAGE_CERTS_GET_KS_PW_TOO_SHORT.get());
        }
        return passwordChars;
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw e;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MANAGE_CERTS_GET_KS_PW_ERROR_READING_FILE.get(
                  f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    final BooleanArgument promptArgument = subCommandParser.getBooleanArgument(
         "prompt-for-" + prefixDash + "keystore-password");
    if ((promptArgument != null) && promptArgument.isPresent())
    {
      out();
      if (keystoreFile.exists() && (! "new".equals(prefix)))
      {
        // We're only going to prompt once.
        if ((prefix != null) && prefix.equals("current"))
        {
          return promptForPassword(
               INFO_MANAGE_CERTS_KEY_KS_PW_EXISTING_CURRENT_PROMPT.get(
                    keystoreFile.getAbsolutePath()),
               false);
        }
        else
        {
          return promptForPassword(
               INFO_MANAGE_CERTS_KEY_KS_PW_EXISTING_PROMPT.get(
                    keystoreFile.getAbsolutePath()),
               false);
        }
      }
      else
      {
        // We're creating a new keystore, so we should prompt for the password
        // twice to prevent setting the wrong password because of a typo.
        while (true)
        {
          final String prompt1;
          if ("new".equals(prefix))
          {
            prompt1 = INFO_MANAGE_CERTS_KEY_KS_PW_EXISTING_NEW_PROMPT.get();
          }
          else
          {
            prompt1 = INFO_MANAGE_CERTS_KEY_KS_PW_NEW_PROMPT_1.get(
                 keystoreFile.getAbsolutePath());
          }
          final char[] pwChars = promptForPassword(prompt1, false);

          if (pwChars.length < 6)
          {
            wrapErr(0, WRAP_COLUMN,
                 ERR_MANAGE_CERTS_GET_KS_PW_TOO_SHORT.get());
            err();
            continue;
          }

          final char[] confirmChars = promptForPassword(
               INFO_MANAGE_CERTS_KEY_KS_PW_NEW_PROMPT_2.get(), true);

          if (Arrays.equals(pwChars, confirmChars))
          {
            Arrays.fill(confirmChars, '\u0000');
            return pwChars;
          }
          else
          {
            wrapErr(0, WRAP_COLUMN,
                 ERR_MANAGE_CERTS_KEY_KS_PW_PROMPT_MISMATCH.get());
            err();
          }
        }
      }
    }


    return null;
  }



  /**
   * Prompts for a password and retrieves the value that the user entered.
   *
   * @param  prompt      The prompt to display to the user.
   * @param  allowEmpty  Indicates whether to allow the password to be empty.
   *
   * @return  The password that was read, or an empty array if the user did not
   *          type a password before pressing ENTER.
   *
   * @throws  LDAPException  If a problem is encountered while reading the
   *                         password.
   */
  @NotNull()
  private char[] promptForPassword(@NotNull final String prompt,
                                   final boolean allowEmpty)
          throws LDAPException
  {
    final Iterator<String> iterator =
         StaticUtils.wrapLine(prompt, WRAP_COLUMN).iterator();
    while (iterator.hasNext())
    {
      final String line = iterator.next();
      if (iterator.hasNext())
      {
        out(line);
      }
      else
      {
        getOut().print(line);
      }
    }

    final char[] passwordChars = PasswordReader.readPasswordChars();
    if ((passwordChars.length == 0) && (! allowEmpty))
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_CERTS_PROMPT_FOR_PW_EMPTY_PW.get());
      err();
      return promptForPassword(prompt, allowEmpty);
    }

    return passwordChars;
  }



  /**
   * Prompts the user for a yes or no response.
   *
   * @param  prompt  The prompt to display to the end user.
   *
   * @return  {@code true} if the user chooses the "yes" response, or
   *          {@code false} if the user chooses the "no" throws.
   *
   * @throws  LDAPException  If a problem is encountered while reading data from
   *                         the client.
   */
  private boolean promptForYesNo(@NotNull final String prompt)
          throws LDAPException
  {
    while (true)
    {
      final List<String> lines =
           StaticUtils.wrapLine((prompt + ' '), WRAP_COLUMN);

      final Iterator<String> lineIterator = lines.iterator();
      while (lineIterator.hasNext())
      {
        final String line = lineIterator.next();
        if (lineIterator.hasNext())
        {
          out(line);
        }
        else
        {
          getOut().print(line);
        }
      }

      try
      {
        final String response = readLineFromIn();
        if (response.equalsIgnoreCase("yes") || response.equalsIgnoreCase("y"))
        {
          return true;
        }
        else if (response.equalsIgnoreCase("no") ||
             response.equalsIgnoreCase("n"))
        {
          return false;
        }
        else
        {
          err();
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_CERTS_PROMPT_FOR_YES_NO_INVALID_RESPONSE.get());
          err();
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MANAGE_CERTS_PROMPT_FOR_YES_NO_READ_ERROR.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
  }



  /**
   * Reads a line of input from standard input.
   *
   * @return  The line read from standard input.
   *
   * @throws  IOException  If a problem is encountered while reading from
   *                       standard input.
   */
  @NotNull()
  private String readLineFromIn()
          throws IOException
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    while (true)
    {
      final int byteRead = in.read();
      if (byteRead < 0)
      {
        if (buffer.isEmpty())
        {
          return null;
        }
        else
        {
          return buffer.toString();
        }
      }

      if (byteRead == '\n')
      {
        return buffer.toString();
      }
      else if (byteRead == '\r')
      {
        final int nextByteRead = in.read();
        Validator.ensureTrue(((nextByteRead < 0) || (nextByteRead == '\n')),
             "ERROR:  Read a carriage return from standard input that was " +
                  "not followed by a new line.");
        return buffer.toString();
      }
      else
      {
        buffer.append((byte) (byteRead & 0xFF));
      }
    }
  }



  /**
   * Retrieves the password needed to access the private key.
   *
   * @param  keystore          The keystore that contains the target private
   *                           key.  This must not be {@code null}.
   * @param  alias             The alias of the target private key.  This must
   *                           not be {@code null}.
   * @param  keystorePassword  The keystore password to use if no specific
   *                           private key password was provided.
   *
   * @return  The password needed to access the private key, or the provided
   *          keystore password if no arguments were provided to specify a
   *          different private key password.
   *
   * @throws  LDAPException  If a problem is encountered while trying to get the
   *                         private key password.
   */
  @Nullable()
  private char[] getPrivateKeyPassword(@NotNull final KeyStore keystore,
                                       @NotNull final String alias,
                                       @Nullable final char[] keystorePassword)
          throws LDAPException
  {
    return getPrivateKeyPassword(keystore, alias, null, keystorePassword);
  }



  /**
   * Retrieves the password needed to access the private key.
   *
   * @param  keystore          The keystore that contains the target private
   *                           key.  This must not be {@code null}.
   * @param  alias             The alias of the target private key.  This must
   *                           not be {@code null}.
   * @param  prefix            The prefix string to use for the arguments.  This
   *                           may be {@code null} if no prefix is needed.
   * @param  keystorePassword  The keystore password to use if no specific
   *                           private key password was provided.
   *
   * @return  The password needed to access the private key, or the provided
   *          keystore password if no arguments were provided to specify a
   *          different private key password.
   *
   * @throws  LDAPException  If a problem is encountered while trying to get the
   *                         private key password.
   */
  @Nullable()
  private char[] getPrivateKeyPassword(@NotNull final KeyStore keystore,
                                       @NotNull final String alias,
                                       @Nullable final String prefix,
                                       @Nullable final char[] keystorePassword)
          throws LDAPException
  {
    final String prefixDash;
    if (prefix == null)
    {
      prefixDash = "";
    }
    else
    {
      prefixDash = prefix + '-';
    }

    final StringArgument privateKeyPasswordArgument =
         subCommandParser.getStringArgument(
              prefixDash + "private-key-password");
    if ((privateKeyPasswordArgument != null) &&
         privateKeyPasswordArgument.isPresent())
    {
      final char[] pkPasswordChars =
           privateKeyPasswordArgument.getValue().toCharArray();
      if ((pkPasswordChars.length < 6) &&
          (! (hasCertificateAlias(keystore, alias) ||
              hasKeyAlias(keystore, alias))))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MANAGE_CERTS_GET_PK_PW_TOO_SHORT.get());
      }

      return pkPasswordChars;
    }


    final FileArgument privateKeyPasswordFileArgument =
         subCommandParser.getFileArgument(
              prefixDash + "private-key-password-file");
    if ((privateKeyPasswordFileArgument != null) &&
        privateKeyPasswordFileArgument.isPresent())
    {
      final File f = privateKeyPasswordFileArgument.getValue();
      try
      {
        final char[] passwordChars = getPasswordFileReader().readPassword(f);
        if (passwordChars.length < 6)
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_MANAGE_CERTS_GET_PK_PW_EMPTY_FILE.get(f.getAbsolutePath()));
        }

        return passwordChars;
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw e;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MANAGE_CERTS_GET_PK_PW_ERROR_READING_FILE.get(
                  f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    final BooleanArgument promptArgument =
         subCommandParser.getBooleanArgument(
              "prompt-for-" + prefixDash + "private-key-password");
    if ((promptArgument != null) && promptArgument.isPresent())
    {
      out();

      try
      {
        if ((hasKeyAlias(keystore, alias) ||
             hasCertificateAlias(keystore, alias)) &&
            (! "new".equals(prefix)))
        {
          // This means that the private key already exists, so we just need to
          // prompt once.
          final String prompt;
          if ("current".equals(prefix))
          {
            prompt =
                 INFO_MANAGE_CERTS_GET_PK_PW_CURRENT_PROMPT.get(alias);
          }
          else
          {
            prompt =
                 INFO_MANAGE_CERTS_GET_PK_PW_EXISTING_PROMPT.get(alias);
          }

          return promptForPassword(prompt, false);
        }
        else
        {
          // This means that we'll be creating a new private key, so we need to
          // prompt twice.
          while (true)
          {
            final String prompt;
            if ("new".equals(prefix))
            {
              prompt = INFO_MANAGE_CERTS_GET_PK_PW_NEW_PROMPT.get();
            }
            else
            {
              prompt = INFO_MANAGE_CERTS_GET_PK_PW_NEW_PROMPT_1.get(alias);
            }

            final char[] pwChars = promptForPassword(prompt, false);
            if (pwChars.length < 6)
            {
              wrapErr(0, WRAP_COLUMN,
                   ERR_MANAGE_CERTS_GET_PK_PW_TOO_SHORT.get());
              err();
              continue;
            }

            final char[] confirmChars = promptForPassword(
                 INFO_MANAGE_CERTS_GET_PK_PW_NEW_PROMPT_2.get(), true);

            if (Arrays.equals(pwChars, confirmChars))
            {
              Arrays.fill(confirmChars, '\u0000');
              return pwChars;
            }
            else
            {
              wrapErr(0, WRAP_COLUMN,
                   ERR_MANAGE_CERTS_GET_PK_PW_PROMPT_MISMATCH.get());
              err();
            }
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
             ERR_MANAGE_CERTS_GET_PK_PW_PROMPT_ERROR.get(alias,
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    return keystorePassword;
  }



  /**
   * Infers the keystore type from the provided keystore file.
   *
   * @param  keystorePath  The path to the file to examine.
   *
   * @return  The keystore type inferred from the provided keystore file.
   *
   * @throws  LDAPException  If a problem is encountered while trying to infer
   *                         the keystore type.
   */
  @NotNull()
  private String inferKeystoreType(@NotNull final File keystorePath)
          throws LDAPException
  {
    // If the keystore type argument was specified, then use its value.
    final StringArgument keystoreTypeArgument =
         subCommandParser.getStringArgument("keystore-type");
    if ((keystoreTypeArgument != null) && keystoreTypeArgument.isPresent())
    {
      final String ktaValue = keystoreTypeArgument.getValue();
      if (ktaValue.equalsIgnoreCase("PKCS12") ||
          ktaValue.equalsIgnoreCase("PKCS 12") ||
          ktaValue.equalsIgnoreCase("PKCS#12") ||
          ktaValue.equalsIgnoreCase("PKCS #12"))
      {
        return CryptoHelper.KEY_STORE_TYPE_PKCS_12;
      }
      else if (ktaValue.equalsIgnoreCase(BCFKS_KEYSTORE_TYPE))
      {
        return BCFKS_KEYSTORE_TYPE;
      }
      else
      {
        return CryptoHelper.KEY_STORE_TYPE_JKS;
      }
    }


    // If we've gotten here, then the keystore type was not explicitly specified
    // so we will need to infer it.  If the LDAP SDK is running in FIPS mode,
    // then we'll always use the BCFKS key store type.
    if (CryptoHelper.usingFIPSMode())
    {
      return BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE;
    }


    // If the key store file doesn't exist, then we must be creating it.  Use
    // the default key store type.
    if (! keystorePath.exists())
    {
      return DEFAULT_KEYSTORE_TYPE;
    }


    try (FileInputStream inputStream = new FileInputStream(keystorePath))
    {
      final int firstByte = inputStream.read();
      if (firstByte < 0)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MANAGE_CERTS_INFER_KS_TYPE_EMPTY_FILE.get(
                  keystorePath.getAbsolutePath()));
      }

      if (firstByte == 0x30)
      {
        // This suggests that the file is encoded as a DER sequence.  This
        // encoding is used for both the PKCS #12 and BCFKS key stores, but we
        // will always assume the PKCS #12 key store type unless we're running
        // in FIPS mode or the keystore-type argument was provided, and both of
        // those cases will have already been handled.
        return CryptoHelper.KEY_STORE_TYPE_PKCS_12;
      }
      else if (firstByte == 0xFE)
      {
        // This is the correct first byte of a Java JKS keystore, which starts
        // with bytes 0xFEEDFEED.
        return CryptoHelper.KEY_STORE_TYPE_JKS;
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MANAGE_CERTS_INFER_KS_TYPE_UNEXPECTED_FIRST_BYTE.get(
                  keystorePath.getAbsolutePath(),
                  StaticUtils.toHex((byte) (firstByte & 0xFF))));
      }
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MANAGE_CERTS_INFER_KS_TYPE_ERROR_READING_FILE.get(
                keystorePath.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves a user-friendly representation of the provided keystore type.
   *
   * @param  keystoreType  The keystore type for which to get the user-friendly
   *                       name.
   *
   * @return  "JKS" if the provided keystore type is for a JKS keystore,
   *          "PKCS #12" if the provided keystore type is for a PKCS #12
   *          keystore, or the provided string if it is for some other keystore
   *          type.
   */
  @NotNull()
  static String getUserFriendlyKeystoreType(@NotNull final String keystoreType)
  {
    if (keystoreType.equalsIgnoreCase("JKS"))
    {
      return "JKS";
    }
    else if (keystoreType.equalsIgnoreCase("PKCS12") ||
         keystoreType.equalsIgnoreCase("PKCS 12") ||
         keystoreType.equalsIgnoreCase("PKCS#12") ||
         keystoreType.equalsIgnoreCase("PKCS #12"))
    {
      return "PKCS #12";
    }
    else if (keystoreType.equalsIgnoreCase(BCFKS_KEYSTORE_TYPE))
    {
      return BCFKS_KEYSTORE_TYPE;
    }
    else
    {
      return keystoreType;
    }
  }



  /**
   * Gets access to a keystore based on information included in command-line
   * arguments.
   *
   * @param  keystoreType      The keystore type for the keystore to access.
   * @param  keystorePath      The path to the keystore file.
   * @param  keystorePassword  The password to use to access the keystore.
   *
   * @return  The configured keystore instance.
   *
   * @throws  LDAPException  If it is not possible to access the keystore.
   */
  @NotNull()
  static KeyStore getKeystore(@NotNull final String keystoreType,
                              @NotNull final File keystorePath,
                              @Nullable final char[] keystorePassword)
          throws LDAPException
  {
    // Instantiate a keystore instance of the desired keystore type.
    final KeyStore keystore;
    try
    {
      keystore = CryptoHelper.getKeyStore(keystoreType);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MANAGE_CERTS_CANNOT_INSTANTIATE_KS_TYPE.get(keystoreType,
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Get an input stream that may be used to access the keystore.
    final InputStream inputStream;
    try
    {
      if (keystorePath.exists())
      {
        inputStream = new FileInputStream(keystorePath);
      }
      else
      {
        inputStream = null;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MANAGE_CERTS_CANNOT_OPEN_KS_FILE_FOR_READING.get(
                keystorePath.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      keystore.load(inputStream, keystorePassword);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      final Throwable cause = e.getCause();
      if ((e instanceof IOException) && (cause != null) &&
          (cause instanceof UnrecoverableKeyException) &&
          (keystorePassword != null))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MANAGE_CERTS_CANNOT_LOAD_KS_WRONG_PW.get(
                  keystorePath.getAbsolutePath()),
             e);
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MANAGE_CERTS_ERROR_CANNOT_LOAD_KS.get(
                  keystorePath.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    finally
    {
      try
      {
        if (inputStream != null)
        {
          inputStream.close();
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return keystore;
  }



  /**
   * Reads all of the certificates contained in the specified file.  The file
   * must exist and may contain zero or more certificates that are either all in
   * PEM format or all in DER format.
   *
   * @param  f  The path to the certificate file to read.  It must not be
   *            {@code null}.
   *
   * @return  A list of the certificates read from the specified file.
   *
   * @throws  LDAPException  If a problem is encountered while reading
   *                         certificates from the specified file.
   */
  @NotNull()
  public static List<X509Certificate> readCertificatesFromFile(
                                           @NotNull final File f)
         throws LDAPException
  {
    // Read the first byte of the file to see if it contains DER-formatted data,
    // which we can determine by seeing if the first byte is 0x30.
    try (BufferedInputStream inputStream =
              new BufferedInputStream(new FileInputStream(f)))
    {
      inputStream.mark(1);
      final int firstByte = inputStream.read();

      if (firstByte < 0)
      {
        // This means that the file is empty.
        return Collections.emptyList();
      }
      else
      {
        inputStream.reset();
      }

      final ArrayList<X509Certificate> certList = new ArrayList<>(5);
      if ((firstByte & 0xFF) == 0x30)
      {
        // It is a DER-encoded file.  Read ASN.1 elements and decode them as
        // X.509 certificates.
        while (true)
        {
          final ASN1Element certElement;
          try
          {
            certElement = ASN1Element.readFrom(inputStream);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MANAGE_CERTS_READ_CERTS_FROM_FILE_DER_NOT_VALID_ASN1.get(
                      f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
                 e);
          }

          if (certElement == null)
          {
            // We've reached the end of the input stream.
            return certList;
          }

          try
          {
            certList.add(new X509Certificate(certElement.encode()));
          }
          catch (final CertException e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_MANAGE_CERTS_READ_CERTS_FROM_FILE_DER_NOT_VALID_CERT.get(
                      f.getAbsolutePath(), e.getMessage()),
                 e);
          }
        }
      }
      else
      {
        try (BufferedReader reader =
                  new BufferedReader(new InputStreamReader(inputStream)))
        {
          boolean inCert = false;
          final StringBuilder buffer = new StringBuilder();
          while (true)
          {
            String line = reader.readLine();
            if (line == null)
            {
              if (inCert)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CERTS_FROM_FILE_EOF_WITHOUT_END.get(
                          f.getAbsolutePath()));
              }

              return certList;
            }

            line = line.trim();
            if (line.isEmpty() || line.startsWith("#"))
            {
              continue;
            }

            if (line.equals("-----BEGIN CERTIFICATE-----"))
            {
              if (inCert)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CERTS_FROM_FILE_MULTIPLE_BEGIN.get(
                          f.getAbsolutePath()));
              }
              else
              {
                inCert = true;
              }
            }
            else if (line.equals("-----END CERTIFICATE-----"))
            {
              if (! inCert)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CERTS_FROM_FILE_END_WITHOUT_BEGIN.
                          get(f.getAbsolutePath()));
              }

              inCert = false;
              final byte[] certBytes;
              try
              {
                certBytes = Base64.decode(buffer.toString());
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CERTS_FROM_FILE_PEM_CERT_NOT_BASE64.
                          get(f.getAbsolutePath(),
                               StaticUtils.getExceptionMessage(e)),
                     e);
              }

              try
              {
                certList.add(new X509Certificate(certBytes));
              }
              catch (final CertException e)
              {
                Debug.debugException(e);
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CERTS_FROM_FILE_PEM_CERT_NOT_CERT.
                          get(f.getAbsolutePath(), e.getMessage()),
                     e);
              }

              buffer.setLength(0);
            }
            else if (inCert)
            {
              buffer.append(line);
            }
            else
            {
              throw new LDAPException(ResultCode.PARAM_ERROR,
                   ERR_MANAGE_CERTS_READ_CERTS_FROM_FILE_DATA_WITHOUT_BEGIN.get(
                        f.getAbsolutePath()));
            }
          }
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
           ERR_MANAGE_CERTS_READ_CERTS_FROM_FILE_READ_ERROR.get(
                f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Reads a private key from the specified file.  The file must exist and must
   * contain exactly one PEM-encoded or DER-encoded PKCS #8 private key.
   *
   * @param  f  The path to the private key file to read.  It must not be
   *            {@code null}.
   *
   * @return  The private key read from the file.
   *
   * @throws  LDAPException  If a problem is encountered while reading the
   *                         private key.
   */
  @NotNull()
  static PKCS8PrivateKey readPrivateKeyFromFile(@NotNull final File f)
         throws LDAPException
  {
    // Read the first byte of the file to see if it contains DER-formatted data,
    // which we can determine by seeing if the first byte is 0x30.
    try (BufferedInputStream inputStream =
              new BufferedInputStream(new FileInputStream(f)))
    {
      inputStream.mark(1);
      final int firstByte = inputStream.read();

      if (firstByte < 0)
      {
        // This means that the file is empty.
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MANAGE_CERTS_READ_PK_FROM_FILE_EMPTY_FILE.get(
                  f.getAbsolutePath()));
      }
      else
      {
        inputStream.reset();
      }

      PKCS8PrivateKey privateKey = null;
      if ((firstByte & 0xFF) == 0x30)
      {
        // It is a DER-encoded file.  Read an ASN.1 element and decode it as a
        // certificate.
        while (true)
        {
          final ASN1Element pkElement;
          try
          {
            pkElement = ASN1Element.readFrom(inputStream);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MANAGE_CERTS_READ_PK_FROM_FILE_DER_NOT_VALID_ASN1.get(
                      f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
                 e);
          }

          if (pkElement == null)
          {
            // We've reached the end of the input stream.
            if (privateKey == null)
            {
              throw new LDAPException(ResultCode.PARAM_ERROR,
                   ERR_MANAGE_CERTS_READ_PK_FROM_FILE_EMPTY_FILE.get(
                        f.getAbsolutePath()));
            }
            else
            {
              return privateKey;
            }
          }
          else if (privateKey == null)
          {
            try
            {
              privateKey = new PKCS8PrivateKey(pkElement.encode());
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              throw new LDAPException(ResultCode.PARAM_ERROR,
                   ERR_MANAGE_CERTS_READ_PK_FROM_FILE_DER_NOT_VALID_PK.get(
                        f.getAbsolutePath(), e.getMessage()),
                   e);
            }
          }
          else
          {
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_MANAGE_CERTS_READ_PK_FROM_FILE_MULTIPLE_KEYS.get(
                      f.getAbsolutePath()));
          }
        }
      }
      else
      {
        try (BufferedReader reader =
                  new BufferedReader(new InputStreamReader(inputStream)))
        {
          boolean inKey = false;
          boolean isRSAKey = false;
          final StringBuilder buffer = new StringBuilder();
          while (true)
          {
            String line = reader.readLine();
            if (line == null)
            {
              if (inKey)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_PK_FROM_FILE_EOF_WITHOUT_END.get(
                          f.getAbsolutePath()));
              }

              if (privateKey == null)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_PK_FROM_FILE_EMPTY_FILE.get(
                          f.getAbsolutePath()));
              }
              else
              {
                return privateKey;
              }
            }

            line = line.trim();
            if (line.isEmpty() || line.startsWith("#"))
            {
              continue;
            }

            if (line.equals("-----BEGIN PRIVATE KEY-----") ||
                 line.equals("-----BEGIN RSA PRIVATE KEY-----"))
            {
              if (inKey)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_PK_FROM_FILE_MULTIPLE_BEGIN.get(
                          f.getAbsolutePath()));
              }
              else if (privateKey != null)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_PK_FROM_FILE_MULTIPLE_KEYS.get(
                          f.getAbsolutePath()));
              }
              else
              {
                inKey = true;
                if (line.equals("-----BEGIN RSA PRIVATE KEY-----"))
                {
                  isRSAKey = true;
                }
              }
            }
            else if (line.equals("-----END PRIVATE KEY-----") ||
                 line.equals("-----END RSA PRIVATE KEY-----"))
            {
              if (! inKey)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_PK_FROM_FILE_END_WITHOUT_BEGIN.get(
                          f.getAbsolutePath()));
              }

              inKey = false;
              byte[] pkBytes;
              try
              {
                pkBytes = Base64.decode(buffer.toString());
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_PK_FROM_FILE_PEM_PK_NOT_BASE64.get(
                          f.getAbsolutePath(),
                          StaticUtils.getExceptionMessage(e)),
                     e);
              }

              if (isRSAKey)
              {
                pkBytes = PKCS8PrivateKey.wrapRSAPrivateKey(pkBytes);
              }

              try
              {
                privateKey = new PKCS8PrivateKey(pkBytes);
              }
              catch (final CertException e)
              {
                Debug.debugException(e);
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_PK_FROM_FILE_PEM_PK_NOT_PK.get(
                          f.getAbsolutePath(), e.getMessage()),
                     e);
              }

              buffer.setLength(0);
            }
            else if (inKey)
            {
              buffer.append(line);
            }
            else
            {
              throw new LDAPException(ResultCode.PARAM_ERROR,
                   ERR_MANAGE_CERTS_READ_PK_FROM_FILE_DATA_WITHOUT_BEGIN.get(
                        f.getAbsolutePath()));
            }
          }
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
           ERR_MANAGE_CERTS_READ_PK_FROM_FILE_READ_ERROR.get(
                f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Reads a certificate signing request from the specified file.  The file must
   * exist and must contain exactly one PEM-encoded or DER-encoded PKCS #10
   * certificate signing request.
   *
   * @param  f  The path to the private key file to read.  It must not be
   *            {@code null}.
   *
   * @return  The certificate signing request read from the file.
   *
   * @throws  LDAPException  If a problem is encountered while reading the
   *                         certificate signing request.
   */
  @NotNull()
  public static PKCS10CertificateSigningRequest
                     readCertificateSigningRequestFromFile(
                          @NotNull final File f)
         throws LDAPException
  {
    // Read the first byte of the file to see if it contains DER-formatted data,
    // which we can determine by seeing if the first byte is 0x30.
    try (BufferedInputStream inputStream =
              new BufferedInputStream(new FileInputStream(f)))
    {
      inputStream.mark(1);
      final int firstByte = inputStream.read();

      if (firstByte < 0)
      {
        // This means that the file is empty.
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_EMPTY_FILE.get(
                  f.getAbsolutePath()));
      }
      else
      {
        inputStream.reset();
      }

      PKCS10CertificateSigningRequest csr = null;
      if ((firstByte & 0xFF) == 0x30)
      {
        // It is a DER-encoded file.  Read an ASN.1 element and decode it as a
        // certificate.
        while (true)
        {
          final ASN1Element csrElement;
          try
          {
            csrElement = ASN1Element.readFrom(inputStream);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_DER_NOT_VALID_ASN1.get(
                      f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
                 e);
          }

          if (csrElement == null)
          {
            // We've reached the end of the input stream.
            if (csr == null)
            {
              throw new LDAPException(ResultCode.PARAM_ERROR,
                   ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_EMPTY_FILE.get(
                        f.getAbsolutePath()));
            }
            else
            {
              return csr;
            }
          }
          else if (csr == null)
          {
            try
            {
              csr = new PKCS10CertificateSigningRequest(csrElement.encode());
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              throw new LDAPException(ResultCode.PARAM_ERROR,
                   ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_DER_NOT_VALID_CSR.get(
                        f.getAbsolutePath(), e.getMessage()),
                   e);
            }
          }
          else
          {
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_MULTIPLE_CSRS.get(
                      f.getAbsolutePath()));
          }
        }
      }
      else
      {
        try (BufferedReader reader =
                  new BufferedReader(new InputStreamReader(inputStream)))
        {
          boolean inCSR = false;
          final StringBuilder buffer = new StringBuilder();
          while (true)
          {
            String line = reader.readLine();
            if (line == null)
            {
              if (inCSR)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_EOF_WITHOUT_END.get(
                          f.getAbsolutePath()));
              }

              if (csr == null)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_EMPTY_FILE.get(
                          f.getAbsolutePath()));
              }
              else
              {
                return csr;
              }
            }

            line = line.trim();
            if (line.isEmpty() || line.startsWith("#"))
            {
              continue;
            }

            if (line.equals("-----BEGIN CERTIFICATE REQUEST-----") ||
                line.equals("-----BEGIN NEW CERTIFICATE REQUEST-----"))
            {
              if (inCSR)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_MULTIPLE_BEGIN.get(
                          f.getAbsolutePath()));
              }
              else if (csr != null)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_MULTIPLE_CSRS.get(
                          f.getAbsolutePath()));
              }
              else
              {
                inCSR = true;
              }
            }
            else if (line.equals("-----END CERTIFICATE REQUEST-----") ||
                 line.equals("-----END NEW CERTIFICATE REQUEST-----"))
            {
              if (! inCSR)
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_END_WITHOUT_BEGIN.get(
                          f.getAbsolutePath()));
              }

              inCSR = false;
              final byte[] csrBytes;
              try
              {
                csrBytes = Base64.decode(buffer.toString());
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_PEM_CSR_NOT_BASE64.get(
                          f.getAbsolutePath(),
                          StaticUtils.getExceptionMessage(e)),
                     e);
              }

              try
              {
                csr = new PKCS10CertificateSigningRequest(csrBytes);
              }
              catch (final CertException e)
              {
                Debug.debugException(e);
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_PEM_CSR_NOT_CSR.get(
                          f.getAbsolutePath(), e.getMessage()),
                     e);
              }

              buffer.setLength(0);
            }
            else if (inCSR)
            {
              buffer.append(line);
            }
            else
            {
              throw new LDAPException(ResultCode.PARAM_ERROR,
                   ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_DATA_WITHOUT_BEGIN.get(
                        f.getAbsolutePath()));
            }
          }
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
           ERR_MANAGE_CERTS_READ_CSR_FROM_FILE_READ_ERROR.get(
                f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves a colon-delimited hexadecimal representation of the contents of
   * the provided byte array.
   *
   * @param  bytes  The byte array for which to get the hexadecimal
   *                representation.  It must not be {@code null}.
   *
   * @return  A colon-delimited hexadecimal representation of the contents of
   *          the provided byte array.
   */
  @NotNull()
  private static String toColonDelimitedHex(@NotNull final byte... bytes)
  {
    final StringBuilder buffer = new StringBuilder(bytes.length * 3);
    StaticUtils.toHex(bytes, ":", buffer);
    return buffer.toString();
  }



  /**
   * Retrieves a formatted representation of the provided date in a
   * human-readable format that includes an offset from the current time.
   *
   * @param  d  The date to format.  It must not be {@code null}.
   *
   * @return  A formatted representation of the provided date.
   */
  @NotNull()
  private static String formatDateAndTime(@NotNull final Date d)
  {
    // Example:  Sunday, January 1, 2017
    final String dateFormatString = "EEEE, MMMM d, yyyy";
    final String formattedDate =
         new SimpleDateFormat(dateFormatString).format(d);

    // Example:  12:34:56 AM CDT
    final String timeFormatString = "hh:mm:ss aa z";
    final String formattedTime =
         new SimpleDateFormat(timeFormatString).format(d);

    final long providedTime = d.getTime();
    final long currentTime = System.currentTimeMillis();
    if (providedTime > currentTime)
    {
      final long secondsInFuture = ((providedTime - currentTime) / 1000L);
      final String durationInFuture =
           StaticUtils.secondsToHumanReadableDuration(secondsInFuture);
      return INFO_MANAGE_CERTS_FORMAT_DATE_AND_TIME_IN_FUTURE.get(formattedDate,
           formattedTime, durationInFuture);
    }
    else
    {
      final long secondsInPast = ((currentTime - providedTime) / 1000L);
      final String durationInPast =
           StaticUtils.secondsToHumanReadableDuration(secondsInPast);
      return INFO_MANAGE_CERTS_FORMAT_DATE_AND_TIME_IN_PAST.get(formattedDate,
           formattedTime, durationInPast);
    }
  }



  /**
   * Retrieves a formatted representation of the provided date in a format
   * suitable for use as the validity start time value provided to the keytool
   * command.
   *
   * @param  d  The date to format.  It must not be {@code null}.
   *
   * @return  A formatted representation of the provided date.
   */
  @NotNull()
  private static String formatValidityStartTime(@NotNull final Date d)
  {
    // Example:  2017/01/01 01:23:45
    final String dateFormatString = "yyyy'/'MM'/'dd HH':'mm':'ss";
    return new SimpleDateFormat(dateFormatString).format(d);
  }



  /**
   * Retrieves the certificate chain for the specified certificate from the
   * given keystore.  If any issuer certificate is not in the provided keystore,
   * then the JVM-default trust store will be checked to see if it can be found
   * there.
   *
   * @param  alias             The alias of the certificate for which to get the
   *                           certificate chain.  This must not be
   *                           {@code null}.
   * @param  keystore          The keystore from which to get the certificate
   *                           chain.  This must not be {@code null}.
   * @param  missingIssuerRef  A reference that will be updated with the DN of a
   *                           missing issuer certificate, if any certificate in
   *                           the chain cannot be located.  This must not be
   *                           {@code null}.
   *
   * @return  The certificate chain for the specified certificate, or an empty
   *          array if no certificate exists with the specified alias.
   *
   * @throws  LDAPException  If a problem is encountered while getting the
   *                         certificate chain.
   */
  @NotNull()
  private static X509Certificate[] getCertificateChain(
                      @NotNull final String alias,
                      @NotNull final KeyStore keystore,
                      @NotNull final AtomicReference<DN> missingIssuerRef)
          throws LDAPException
  {
    try
    {
      // First, see if the keystore will give us the certificate chain.  This
      // will only happen if the alias references an entry that includes the
      // private key, but it will save us a lot of work.
      final Certificate[] chain = keystore.getCertificateChain(alias);
      if ((chain != null) && (chain.length > 0))
      {
        final X509Certificate[] x509Chain = new X509Certificate[chain.length];
        for (int i=0; i < chain.length; i++)
        {
          x509Chain[i] = new X509Certificate(chain[i].getEncoded());
        }
        return x509Chain;
      }


      // We couldn't get the keystore to give us the chain, but see if we can
      // get a certificate with the specified alias.
      final Certificate endCert = keystore.getCertificate(alias);
      if (endCert == null)
      {
        // This means there isn't any certificate with the specified alias.
        // Return an empty chain.
        return new X509Certificate[0];
      }

      final ArrayList<X509Certificate> chainList = new ArrayList<>(5);
      X509Certificate certificate = new X509Certificate(endCert.getEncoded());
      chainList.add(certificate);

      final AtomicReference<KeyStore> jvmDefaultTrustStoreRef =
           new AtomicReference<>();
      while (true)
      {
        final X509Certificate issuerCertificate =
             getIssuerCertificate(certificate, keystore,
                  jvmDefaultTrustStoreRef, missingIssuerRef);
        if (issuerCertificate == null)
        {
          break;
        }

        chainList.add(issuerCertificate);
        certificate = issuerCertificate;
      }

      final X509Certificate[] x509Chain = new X509Certificate[chainList.size()];
      return chainList.toArray(x509Chain);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MANAGE_CERTS_GET_CHAIN_ERROR.get(alias,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Attempts to retrieve the issuer certificate for the provided certificate
   * from the given keystore or the JVM-default trust store.
   *
   * @param  certificate              The certificate for which to retrieve the
   *                                  issuer certificate.
   * @param  keystore                 The keystore in which to look for the
   *                                  issuer certificate.
   * @param  jvmDefaultTrustStoreRef  A reference that will be used to hold the
   *                                  JVM-default trust store if it is obtained
   *                                  in the process of retrieving the issuer
   *                                  certificate.
   * @param  missingIssuerRef         A reference that will be updated with the
   *                                  DN of a missing issuer certificate, if any
   *                                  certificate in the chain cannot be
   *                                  located.  This must not be {@code null}.
   *
   * @return  The issuer certificate for the provided certificate, or
   *          {@code null} if the issuer certificate could not be retrieved.
   *
   * @throws  Exception   If a problem is encountered while trying to retrieve
   *                      the issuer certificate.
   */
  @Nullable()
  private static X509Certificate getIssuerCertificate(
               @NotNull final X509Certificate certificate,
               @NotNull final KeyStore keystore,
               @NotNull final AtomicReference<KeyStore> jvmDefaultTrustStoreRef,
               @NotNull final AtomicReference<DN> missingIssuerRef)
          throws Exception
  {
    final DN subjectDN = certificate.getSubjectDN();
    final DN issuerDN = certificate.getIssuerDN();
    if (subjectDN.equals(issuerDN))
    {
      // This means that the certificate is self-signed, so there is no issuer.
      return null;
    }


    // See if we can find the issuer certificate in the provided keystore.
    X509Certificate issuerCertificate = getIssuerCertificate(certificate,
         keystore);
    if (issuerCertificate != null)
    {
      return issuerCertificate;
    }


    // See if we can get the JVM-default trust store.
    KeyStore jvmDefaultTrustStore = jvmDefaultTrustStoreRef.get();
    if (jvmDefaultTrustStore == null)
    {
      if (JVM_DEFAULT_CACERTS_FILE == null)
      {
        missingIssuerRef.set(issuerDN);
        return null;
      }

      final String[] keystoreTypes =
      {
        CryptoHelper.KEY_STORE_TYPE_JKS,
        CryptoHelper.KEY_STORE_TYPE_PKCS_12,
        BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE
      };

      for (final String keystoreType : keystoreTypes)
      {
        final KeyStore ks = CryptoHelper.getKeyStore(keystoreType);
        try (FileInputStream inputStream =
                  new FileInputStream(JVM_DEFAULT_CACERTS_FILE))
        {
          ks.load(inputStream, null);
          jvmDefaultTrustStore = ks;
          jvmDefaultTrustStoreRef.set(jvmDefaultTrustStore);
          break;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    if (jvmDefaultTrustStore != null)
    {
      issuerCertificate = getIssuerCertificate(certificate,
           jvmDefaultTrustStore);
    }

    if (issuerCertificate == null)
    {
      missingIssuerRef.set(issuerDN);
    }

    return issuerCertificate;
  }



  /**
   * Attempts to retrieve the issuer certificate for the provided certificate
   * from the given keystore.
   *
   * @param  certificate  The certificate for which to retrieve the issuer
   *                      certificate.
   * @param  keystore     The keystore in which to look for the issuer
   *                      certificate.
   *
   * @return  The issuer certificate for the provided certificate, or
   *          {@code null} if the issuer certificate could not be retrieved.
   *
   * @throws  Exception   If a problem is encountered while trying to retrieve
   *                      the issuer certificate.
   */
  @Nullable()
  private static X509Certificate getIssuerCertificate(
                      @NotNull final X509Certificate certificate,
                      @NotNull final KeyStore keystore)
          throws Exception
  {
    final Enumeration<String> aliases = keystore.aliases();
    while (aliases.hasMoreElements())
    {
      final String alias = aliases.nextElement();

      Certificate[] certs = null;
      if (hasCertificateAlias(keystore, alias))
      {
        final Certificate c = keystore.getCertificate(alias);
        if (c == null)
        {
          continue;
        }

        certs = new Certificate[] { c };
      }
      else if (hasKeyAlias(keystore, alias))
      {
        certs = keystore.getCertificateChain(alias);
      }

      if (certs != null)
      {
        for (final Certificate c : certs)
        {
          final X509Certificate xc = new X509Certificate(c.getEncoded());
          if (xc.isIssuerFor(certificate))
          {
            return xc;
          }
        }
      }
    }

    return null;
  }



  /**
   * Retrieves the authority key identifier value for the provided certificate,
   * if present.
   *
   * @param  c  The certificate for which to retrieve the authority key
   *            identifier.
   *
   * @return  The authority key identifier value for the provided certificate,
   *          or {@code null} if the certificate does not have an authority
   *          key identifier.
   */
  @Nullable()
  private static byte[] getAuthorityKeyIdentifier(
                             @NotNull final X509Certificate c)
  {
    for (final X509CertificateExtension extension : c.getExtensions())
    {
      if (extension instanceof AuthorityKeyIdentifierExtension)
      {
        final AuthorityKeyIdentifierExtension e =
             (AuthorityKeyIdentifierExtension) extension;
        if (e.getKeyIdentifier() != null)
        {
          return e.getKeyIdentifier().getValue();
        }
      }
    }

    return null;
  }



  /**
   * Writes the provided keystore to the specified file.  If the keystore file
   * already exists, a new temporary file will be created, the old file renamed
   * out of the way, the new file renamed into place, and the old file deleted.
   * If the keystore file does not exist, then it will simply be created in the
   * correct place.
   *
   * @param  keystore          The keystore to be written.
   * @param  keystorePath      The path to the keystore file to be written.
   * @param  keystorePassword  The password to use for the keystore.
   *
   * @throws  LDAPException  If a problem is encountered while writing the
   *                         keystore.
   */
  static void writeKeystore(@NotNull final KeyStore keystore,
                            @NotNull final File keystorePath,
                            @Nullable final char[] keystorePassword)
          throws LDAPException
  {
    File copyOfExistingKeystore = null;
    final String timestamp =
         StaticUtils.encodeGeneralizedTime(System.currentTimeMillis());
    if (keystorePath.exists())
    {
      copyOfExistingKeystore = new File(keystorePath.getAbsolutePath() +
           ".backup-" + timestamp);
      try
      {
        Files.copy(keystorePath.toPath(), copyOfExistingKeystore.toPath());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MANAGE_CERTS_WRITE_KS_ERROR_COPYING_EXISTING_KS.get(
                  keystorePath.getAbsolutePath(),
                  copyOfExistingKeystore.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    try (FileOutputStream outputStream = new FileOutputStream(keystorePath))
    {
      keystore.store(outputStream, keystorePassword);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      if (copyOfExistingKeystore == null)
      {
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MANAGE_CERTS_WRITE_KS_ERROR_WRITING_NEW_KS.get(
                  keystorePath.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
      else
      {
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MANAGE_CERTS_WRITE_KS_ERROR_OVERWRITING_KS.get(
                  keystorePath.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e),
                  copyOfExistingKeystore.getAbsolutePath()),
             e);
      }
    }

    if (copyOfExistingKeystore != null)
    {
      try
      {
        Files.delete(copyOfExistingKeystore.toPath());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MANAGE_CERTS_WRITE_KS_ERROR_DELETING_KS_BACKUP.get(
                  copyOfExistingKeystore.getAbsolutePath(),
                  keystorePath.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
  }



  /**
   * Indicates whether the provided keystore has a certificate entry with the
   * specified alias.
   *
   * @param  keystore  The keystore to examine.
   * @param  alias     The alias for which to make the determination.
   *
   * @return  {@code true} if the keystore has a certificate entry with the
   *          specified alias, or {@code false} if the alias doesn't exist or
   *          is associated with some other type of entry (like a key).
   */
  private static boolean hasCertificateAlias(@NotNull final KeyStore keystore,
                                             @NotNull final String alias)
  {
    try
    {
      return keystore.isCertificateEntry(alias);
    }
    catch (final Exception e)
    {
      // This should never happen.  If it does, then we'll assume the alias
      // doesn't exist or isn't associated with a certificate.
      Debug.debugException(e);
      return false;
    }
  }



  /**
   * Indicates whether the provided keystore has a key entry with the specified
   * alias.
   *
   * @param  keystore  The keystore to examine.
   * @param  alias     The alias for which to make the determination.
   *
   * @return  {@code true} if the keystore has a key entry with the specified
   *          alias, or {@code false} if the alias doesn't exist or is
   *          associated with some other type of entry (like a certificate).
   */
  private static boolean hasKeyAlias(@NotNull final KeyStore keystore,
                                     @NotNull final String alias)
  {
    try
    {
      return keystore.isKeyEntry(alias);
    }
    catch (final Exception e)
    {
      // This should never happen.  If it does, then we'll assume the alias
      // doesn't exist or isn't associated with a key.
      Debug.debugException(e);
      return false;
    }
  }



  /**
   * Adds arguments for each of the provided extensions to the given list.
   *
   * @param  keytoolArguments   The list to which the extension arguments should
   *                            be added.
   * @param  basicConstraints   The basic constraints extension to include.  It
   *                            may be {@code null} if this extension should not
   *                            be included.
   * @param  keyUsage           The key usage extension to include.  It may be
   *                            {@code null} if this extension should not be
   *                            included.
   * @param  extendedKeyUsage   The extended key usage extension to include.  It
   *                            may be {@code null} if this extension should not
   *                            be included.
   * @param  sanValues          The list of subject alternative name values to
   *                            include.  It must not be {@code null} but may be
   *                            empty.
   * @param  ianValues          The list of issuer alternative name values to
   *                            include.  It must not be {@code null} but may be
   *                            empty.
   * @param  genericExtensions  The list of generic extensions to include.  It
   *                            must not be {@code null} but may be empty.
   */
  private static void addExtensionArguments(
               @NotNull final List<String> keytoolArguments,
               @Nullable final BasicConstraintsExtension basicConstraints,
               @Nullable final KeyUsageExtension keyUsage,
               @Nullable final ExtendedKeyUsageExtension extendedKeyUsage,
               @NotNull final Set<String> sanValues,
               @NotNull final Set<String> ianValues,
               @NotNull final List<X509CertificateExtension> genericExtensions)
  {
    if (basicConstraints != null)
    {
      final StringBuilder basicConstraintsValue = new StringBuilder();
      basicConstraintsValue.append("ca:");
      basicConstraintsValue.append(basicConstraints.isCA());

      if (basicConstraints.getPathLengthConstraint() != null)
      {
        basicConstraintsValue.append(",pathlen:");
        basicConstraintsValue.append(
             basicConstraints.getPathLengthConstraint());
      }

      keytoolArguments.add("-ext");
      keytoolArguments.add("BasicConstraints=" + basicConstraintsValue);
    }

    if (keyUsage != null)
    {
      final StringBuilder keyUsageValue = new StringBuilder();
      if (keyUsage.isDigitalSignatureBitSet())
      {
        commaAppend(keyUsageValue, "digitalSignature");
      }

      if (keyUsage.isNonRepudiationBitSet())
      {
        commaAppend(keyUsageValue, "nonRepudiation");
      }

      if (keyUsage.isKeyEnciphermentBitSet())
      {
        commaAppend(keyUsageValue, "keyEncipherment");
      }

      if (keyUsage.isDataEnciphermentBitSet())
      {
        commaAppend(keyUsageValue, "dataEncipherment");
      }

      if (keyUsage.isKeyAgreementBitSet())
      {
        commaAppend(keyUsageValue, "keyAgreement");
      }

      if (keyUsage.isKeyCertSignBitSet())
      {
        commaAppend(keyUsageValue, "keyCertSign");
      }

      if (keyUsage.isCRLSignBitSet())
      {
        commaAppend(keyUsageValue, "cRLSign");
      }

      if (keyUsage.isEncipherOnlyBitSet())
      {
        commaAppend(keyUsageValue, "encipherOnly");
      }

      if (keyUsage.isEncipherOnlyBitSet())
      {
        commaAppend(keyUsageValue, "decipherOnly");
      }

      keytoolArguments.add("-ext");
      keytoolArguments.add("KeyUsage=" + keyUsageValue);
    }

    if (extendedKeyUsage != null)
    {
      final StringBuilder extendedKeyUsageValue = new StringBuilder();
      for (final OID oid : extendedKeyUsage.getKeyPurposeIDs())
      {
        final ExtendedKeyUsageID id = ExtendedKeyUsageID.forOID(oid);
        if (id == null)
        {
          commaAppend(extendedKeyUsageValue, oid.toString());
        }
        else
        {
          switch (id)
          {
            case TLS_SERVER_AUTHENTICATION:
              commaAppend(extendedKeyUsageValue, "serverAuth");
              break;
            case TLS_CLIENT_AUTHENTICATION:
              commaAppend(extendedKeyUsageValue, "clientAuth");
              break;
            case CODE_SIGNING:
              commaAppend(extendedKeyUsageValue, "codeSigning");
              break;
            case EMAIL_PROTECTION:
              commaAppend(extendedKeyUsageValue, "emailProtection");
              break;
            case TIME_STAMPING:
              commaAppend(extendedKeyUsageValue, "timeStamping");
              break;
            case OCSP_SIGNING:
              commaAppend(extendedKeyUsageValue, "OCSPSigning");
              break;
            default:
              // This should never happen.
              commaAppend(extendedKeyUsageValue, id.getOID().toString());
              break;
          }
        }
      }

      keytoolArguments.add("-ext");
      keytoolArguments.add("ExtendedKeyUsage=" + extendedKeyUsageValue);
    }

    if (! sanValues.isEmpty())
    {
      final StringBuilder subjectAltNameValue = new StringBuilder();
      for (final String sanValue : sanValues)
      {
        commaAppend(subjectAltNameValue, sanValue);
      }

      keytoolArguments.add("-ext");
      keytoolArguments.add("SAN=" + subjectAltNameValue);
    }

    if (! ianValues.isEmpty())
    {
      final StringBuilder issuerAltNameValue = new StringBuilder();
      for (final String ianValue : ianValues)
      {
        commaAppend(issuerAltNameValue, ianValue);
      }

      keytoolArguments.add("-ext");
      keytoolArguments.add("IAN=" + issuerAltNameValue);
    }

    for (final X509CertificateExtension e : genericExtensions)
    {
      keytoolArguments.add("-ext");
      if (e.isCritical())
      {
        keytoolArguments.add(e.getOID().toString() + ":critical=" +
             toColonDelimitedHex(e.getValue()));
      }
      else
      {
        keytoolArguments.add(e.getOID().toString() + '=' +
             toColonDelimitedHex(e.getValue()));
      }
    }
  }



  /**
   * Appends the provided value to the given buffer.  If the buffer is not
   * empty, the new value will be preceded by a comma.  There will not be any
   * spaces on either side of the comma.
   *
   * @param  buffer  The buffer to which the value should be appended.
   * @param  value   The value to append to the buffer.
   */
  private static void commaAppend(@NotNull final StringBuilder buffer,
                                  @NotNull final String value)
  {
    if (buffer.length() > 0)
    {
      buffer.append(',');
    }

    buffer.append(value);
  }



  /**
   * Retrieves a set of information that may be used to generate example usage
   * information.  Each element in the returned map should consist of a map
   * between an example set of arguments and a string that describes the
   * behavior of the tool when invoked with that set of arguments.
   *
   * @return  A set of information that may be used to generate example usage
   *          information.  It may be {@code null} or empty if no example usage
   *          information is available.
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final String keystorePath = getPlatformSpecificPath("config", "keystore");
    final String keystorePWPath =
         getPlatformSpecificPath("config", "keystore.pin");
    final String privateKeyPWPath =
         getPlatformSpecificPath("config", "server-cert-private-key.pin");
    final String exportCertOutputFile =
         getPlatformSpecificPath("server-cert.crt");
    final String exportKeyOutputFile =
         getPlatformSpecificPath("server-cert.private-key");
    final String genCSROutputFile = getPlatformSpecificPath("server-cert.csr");
    final String truststorePath =
         getPlatformSpecificPath("config", "truststore");
    final String truststorePWPath =
         getPlatformSpecificPath("config", "truststore.pin");

    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));

    examples.put(
         new String[]
         {
           "list-certificates",
           "--keystore", keystorePath,
           "--keystore-password-file", keystorePWPath,
           "--verbose",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_LIST_1.get(keystorePath));

    examples.put(
         new String[]
         {
           "export-certificate",
           "--keystore", keystorePath,
           "--keystore-password-file", keystorePWPath,
           "--alias", "server-cert",
           "--output-file", exportCertOutputFile,
           "--output-format", "PEM",
           "--verbose",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_EXPORT_CERT_1.get(keystorePath,
              exportCertOutputFile));

    examples.put(
         new String[]
         {
           "export-private-key",
           "--keystore", keystorePath,
           "--keystore-password-file", keystorePWPath,
           "--private-key-password-file", privateKeyPWPath,
           "--alias", "server-cert",
           "--output-file", exportKeyOutputFile,
           "--output-format", "PEM",
           "--verbose",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_EXPORT_KEY_1.get(keystorePath,
              exportKeyOutputFile));

    examples.put(
         new String[]
         {
           "import-certificate",
           "--keystore", keystorePath,
           "--keystore-type", "JKS",
           "--keystore-password-file", keystorePWPath,
           "--alias", "server-cert",
           "--certificate-file", exportCertOutputFile,
           "--private-key-file", exportKeyOutputFile,
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_IMPORT_1.get(exportCertOutputFile,
              exportKeyOutputFile, keystorePath));

    examples.put(
         new String[]
         {
           "delete-certificate",
           "--keystore", keystorePath,
           "--keystore-password-file", keystorePWPath,
           "--alias", "server-cert"
         },
         INFO_MANAGE_CERTS_EXAMPLE_DELETE_1.get(keystorePath));

    examples.put(
         new String[]
         {
           "generate-self-signed-certificate",
           "--keystore", keystorePath,
           "--keystore-type", "PKCS12",
           "--keystore-password-file", keystorePWPath,
           "--alias", "ca-cert",
           "--subject-dn", "CN=Example Authority,O=Example Corporation,C=US",
           "--days-valid", "7300",
           "--validity-start-time", "20170101000000",
           "--key-algorithm", "RSA",
           "--key-size-bits", "4096",
           "--signature-algorithm", "SHA256withRSA",
           "--basic-constraints-is-ca", "true",
           "--key-usage", "key-cert-sign",
           "--key-usage", "crl-sign",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_GEN_CERT_1.get(keystorePath));

    examples.put(
         new String[]
         {
           "generate-certificate-signing-request",
           "--keystore", keystorePath,
           "--keystore-type", "PKCS12",
           "--keystore-password-file", keystorePWPath,
           "--output-file", genCSROutputFile,
           "--alias", "server-cert",
           "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
           "--key-algorithm", "EC",
           "--key-size-bits", "256",
           "--signature-algorithm", "SHA256withECDSA",
           "--subject-alternative-name-dns", "ldap1.example.com",
           "--subject-alternative-name-dns", "ldap2.example.com",
           "--extended-key-usage", "server-auth",
           "--extended-key-usage", "client-auth",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_GEN_CSR_1.get(keystorePath,
              genCSROutputFile));

    examples.put(
         new String[]
         {
           "generate-certificate-signing-request",
           "--keystore", keystorePath,
           "--keystore-password-file", keystorePWPath,
           "--alias", "server-cert",
           "--use-existing-key-pair",
           "--inherit-extensions",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_GEN_CSR_2.get(keystorePath));

    examples.put(
         new String[]
         {
           "sign-certificate-signing-request",
           "--keystore", keystorePath,
           "--keystore-password-file", keystorePWPath,
           "--request-input-file", genCSROutputFile,
           "--certificate-output-file", exportCertOutputFile,
           "--alias", "ca-cert",
           "--days-valid", "730",
           "--include-requested-extensions",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_SIGN_CERT_1.get(keystorePath,
              genCSROutputFile, exportCertOutputFile));

    examples.put(
         new String[]
         {
           "change-certificate-alias",
           "--keystore", keystorePath,
           "--keystore-password-file", keystorePWPath,
           "--current-alias", "server-cert",
           "--new-alias", "server-certificate",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_CHANGE_ALIAS_1.get(keystorePath,
              genCSROutputFile, exportCertOutputFile));

    examples.put(
         new String[]
         {
           "change-keystore-password",
           "--keystore", getPlatformSpecificPath("config", "keystore"),
           "--current-keystore-password-file",
                getPlatformSpecificPath("config", "current.pin"),
           "--new-keystore-password-file",
                getPlatformSpecificPath("config", "new.pin"),
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_SC_CHANGE_KS_PW_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "keystore"),
              getPlatformSpecificPath("config", "current.pin"),
              getPlatformSpecificPath("config", "new.pin")));

    examples.put(
         new String[]
         {
           "retrieve-server-certificate",
           "--hostname", "ds.example.com",
           "--port", "636"
         },
         INFO_MANAGE_CERTS_SC_RETRIEVE_CERT_EXAMPLE_1.get(
              getPlatformSpecificPath("config", "truststore")));

    examples.put(
         new String[]
         {
           "trust-server-certificate",
           "--hostname", "ldap.example.com",
           "--port", "636",
           "--keystore", truststorePath,
           "--keystore-password-file", truststorePWPath,
           "--alias", "ldap.example.com:636"
         },
         INFO_MANAGE_CERTS_EXAMPLE_TRUST_SERVER_1.get(truststorePath));

    examples.put(
         new String[]
         {
           "check-certificate-usability",
           "--keystore", keystorePath,
           "--keystore-password-file", keystorePWPath,
           "--alias", "server-cert"
         },
         INFO_MANAGE_CERTS_EXAMPLE_CHECK_USABILITY_1.get(keystorePath));

    examples.put(
         new String[]
         {
           "display-certificate-file",
           "--certificate-file", exportCertOutputFile,
           "--verbose",
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_DISPLAY_CERT_1.get(keystorePath));

    examples.put(
         new String[]
         {
           "display-certificate-signing-request-file",
           "--certificate-signing-request-file", genCSROutputFile,
           "--display-keytool-command"
         },
         INFO_MANAGE_CERTS_EXAMPLE_DISPLAY_CSR_1.get(keystorePath));

    examples.put(
         new String[]
         {
           "--help-subcommands"
         },
         INFO_MANAGE_CERTS_EXAMPLE_HELP_SUBCOMMANDS_1.get(keystorePath));

    return examples;
  }
}
