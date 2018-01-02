/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.io.File;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.StreamHandler;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.MinimalLogFormatter;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a command-line tool that can be used to run an instance
 * of the in-memory directory server.  Instances of the server may also be
 * created and controlled programmatically using the
 * {@link InMemoryDirectoryServer} class.
 * <BR><BR>
 * The following command-line arguments may be used with this class:
 * <UL>
 *   <LI>"-b {baseDN}" or "--baseDN {baseDN}" -- specifies a base DN to use for
 *       the server.  At least one base DN must be specified, and multiple
 *       base DNs may be provided as separate arguments.</LI>
 *   <LI>"-p {port}" or "--port {port}" -- specifies the port on which the
 *       server should listen for client connections.  If this is not provided,
 *       then a free port will be automatically chosen for use by the
 *       server.</LI>
 *   <LI>"-l {path}" or "--ldifFile {path}" -- specifies the path to an LDIF
 *       file to use to initially populate the server.  If this is not provided,
 *       then the server will initially be empty.  The LDIF file will not be
 *       updated as operations are processed in the server.</LI>
 *   <LI>"-D {bindDN}" or "--additionalBindDN {bindDN}" -- specifies an
 *       additional DN that can be used to authenticate to the server, even if
 *       there is no account for that user.  If this is provided, then the
 *       --additionalBindPassword argument must also be given.</LI>
 *   <LI>"-w {password}" or "--additionalBindPassword {password}" -- specifies
 *       the password that should be used when attempting to bind as the user
 *       specified with the "-additionalBindDN" argument.  If this is provided,
 *       then the --additionalBindDN argument must also be given.</LI>
 *   <LI>"-c {count}" or "--maxChangeLogEntries {count}" -- Indicates whether an
 *       LDAP changelog should be enabled, and if so how many changelog records
 *       should be maintained.  If this argument is not provided, or if it is
 *       provided with a value of zero, then no changelog will be
 *       maintained.</LI>
 *   <LI>"-A" or "--accessLogToStandardOut" -- indicates that access log
 *       information should be written to standard output.  This cannot be
 *       provided in conjunction with the "--accessLogFile" argument.  If
 *       that should be used as a server access log.  This cannot be provided in
 *       neither argument is provided, then no access logging will be
 *       performed</LI>
 *   <LI>"-a {path}" or "--accessLogFile {path}" -- specifies the path to a file
 *       that should be used as a server access log.  This cannot be provided in
 *       conjunction with the "--accessLogToStandardOut" argument.  If neither
 *       argument is provided, then no access logging will be performed</LI>
 *   <LI>"--ldapDebugLogToStandardOut" -- Indicates that LDAP debug log
 *       information should be written to standard output.  This cannot be
 *       provided in conjunction with the "--ldapDebugLogFile" argument.  If
 *       neither argument is provided, then no debug logging will be
 *       performed.</LI>
 *   <LI>"-d {path}" or "--ldapDebugLogFile {path}" -- specifies the path to a
 *       file that should be used as a server LDAP debug log.  This cannot be
 *       provided in conjunction with the "--ldapDebugLogToStandardOut"
 *       argument.  If neither argument is provided, then no debug logging will
 *       be performed.</LI>
 *   <LI>"-s" or "--useDefaultSchema" -- Indicates that the server should use
 *       the default standard schema provided as part of the LDAP SDK.  If
 *       neither this argument nor the "--useSchemaFile" argument is provided,
 *       then the server will not perform any schema validation.</LI>
 *   <LI>"-S {path}" or "--useSchemaFile {path}" -- specifies the path to a file
 *       or directory containing schema definitions to use for the server.  If
 *       neither this argument nor the "--useDefaultSchema" argument is
 *       provided, then the server will not perform any schema validation.  If
 *       the specified path represents a file, then it must be an LDIF file
 *       containing a valid LDAP subschema subentry.  If the path is a
 *       directory, then its files will be processed in lexicographic order by
 *       name.</LI>
 *   <LI>"-I {attr}" or "--equalityIndex {attr}" -- specifies that an equality
 *       index should be maintained for the specified attribute.  The equality
 *       index may be used to speed up certain kinds of searches, although it
 *       will cause the server to consume more memory.</LI>
 *   <LI>"-Z" or "--useSSL" -- indicates that the server should encrypt all
 *       communication using SSL.  If this is provided, then the
 *       "--keyStorePath" and "--keyStorePassword" arguments must also be
 *       provided, and the "--useStartTLS" argument must not be provided.</LI>
 *   <LI>"-q" or "--useStartTLS" -- indicates that the server should support the
 *       use of the StartTLS extended request.  If this is provided, then the
 *       "--keyStorePath" and "--keyStorePassword" arguments must also be
 *       provided, and the "--useSSL" argument must not be provided.</LI>
 *   <LI>"-K {path}" or "--keyStorePath {path}" -- specifies the path to the JKS
 *       key store file that should be used to obtain the server certificate to
 *       use for SSL communication.  If this argument is provided, then the
 *       "--keyStorePassword" argument must also be provided, along with exactly
 *       one of the "--useSSL" or "--useStartTLS" arguments.</LI>
 *   <LI>"-W {password}" or "--keyStorePassword {password}" -- specifies the
 *       password that should be used to access the contents of the SSL key
 *       store.  If this argument is provided, then the "--keyStorePath"
 *       argument must also be provided, along with exactly one of the
 *       "--useSSL" or "--useStartTLS" arguments.</LI>
 *   <LI>"--keyStoreType {type}" -- specifies the type of keystore represented
 *       by the file specified by the keystore path.  If this argument is
 *       provided, then the "--keyStorePath" argument must also be provided,
 *       along with exactly one of the "--useSSL" or "--useStartTLS" arguments.
 *       If this argument is not provided, then a default key store type of
 *       "JKS" will be assumed.</LI>
 *   <LI>"-P {path}" or "--trustStorePath {path}" -- specifies the path to the
 *       JKS trust store file that should be used to determine whether to trust
 *       any SSL certificates that may be presented by the client.  If this
 *       argument is provided, then exactly one of the "--useSSL" or
 *       "--useStartTLS" arguments must also be provided.  If this argument is
 *       not provided but SSL or StartTLS is to be used, then all client
 *       certificates will be automatically trusted.</LI>
 *   <LI>"-T {password}" or "--trustStorePassword {password}" -- specifies the
 *       password that should be used to access the contents of the SSL trust
 *       store.  If this argument is provided, then the "--trustStorePath"
 *       argument must also be provided, along with exactly one of the
 *       "--useSSL" or "--useStartTLS" arguments.  If an SSL trust store path
 *       was provided without a trust store password, then the server will
 *       attempt to use the trust store without a password.</LI>
 *   <LI>"--trustStoreType {type}" -- specifies the type of trust store
 *       represented by the file specified by the trust store path.  If this
 *       argument is provided, then the "--trustStorePath" argument must also
 *       be provided, along with exactly one of the "--useSSL" or
 *       "--useStartTLS" arguments.  If this argument is not provided, then a
 *       default trust store type of "JKS" will be assumed.</LI>
 *   <LI>"--vendorName {name}" -- specifies the vendor name value to appear in
 *       the server root DSE.</LI>
 *   <LI>"--vendorVersion {version}" -- specifies the vendor version value to
 *       appear in the server root DSE.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class InMemoryDirectoryServerTool
       extends CommandLineTool
       implements Serializable, LDAPListenerExceptionHandler
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6484637038039050412L;



  // The argument used to indicate that access log information should be written
  // to standard output.
  private BooleanArgument accessLogToStandardOutArgument;

  // The argument used to prevent the in-memory server from starting.  This is
  // only intended to be used for internal testing purposes.
  private BooleanArgument dontStartArgument;

  // The argument used to indicate that LDAP debug log information should be
  // written to standard output.
  private BooleanArgument ldapDebugLogToStandardOutArgument;

  // The argument used to indicate that the default standard schema should be
  // used.
  private BooleanArgument useDefaultSchemaArgument;

  // The argument used to indicate that the server should use SSL
  private BooleanArgument useSSLArgument;

  // The argument used to indicate that the server should support the StartTLS
  // extended operation
  private BooleanArgument useStartTLSArgument;

  // The argument used to specify an additional bind DN to use for the server.
  private DNArgument additionalBindDNArgument;

  // The argument used to specify the base DNs to use for the server.
  private DNArgument baseDNArgument;

  // The argument used to specify the path to an access log file to which
  // information should be written about operations processed by the server.
  private FileArgument accessLogFileArgument;

  // The argument used to specify the code log file to use, if any.
  private FileArgument codeLogFile;

  // The argument used to specify the path to the SSL key store file.
  private FileArgument keyStorePathArgument;

  // The argument used to specify the path to an LDAP debug log file to which
  // information should be written about detailed LDAP communication performed
  // by the server.
  private FileArgument ldapDebugLogFileArgument;

  // The argument used to specify the path to an LDIF file with data to use to
  // initially populate the server.
  private FileArgument ldifFileArgument;

  // The argument used to specify the path to the SSL trust store file.
  private FileArgument trustStorePathArgument;

  // The argument used to specify the path to a directory containing schema
  // definitions.
  private FileArgument useSchemaFileArgument;

  // The in-memory directory server instance that has been created by this tool.
  private InMemoryDirectoryServer directoryServer;

  // The argument used to specify the maximum number of changelog entries that
  // the server should maintain.
  private IntegerArgument maxChangeLogEntriesArgument;

  // The argument used to specify the port on which the server should listen.
  private IntegerArgument portArgument;

  // The argument used to specify the password for the additional bind DN.
  private StringArgument additionalBindPasswordArgument;

  // The argument used to specify the attributes for which to maintain equality
  // indexes.
  private StringArgument equalityIndexArgument;

  // The argument used to specify the password to use to access the contents of
  // the SSL key store
  private StringArgument keyStorePasswordArgument;

  // The argument used to specify the key store type.
  private StringArgument keyStoreTypeArgument;

  // The argument used to specify the password to use to access the contents of
  // the SSL trust store
  private StringArgument trustStorePasswordArgument;

  // The argument used to specify the trust store type.
  private StringArgument trustStoreTypeArgument;

  // The argument used to specify the server vendor name.
  private StringArgument vendorNameArgument;

  // The argument used to specify the server vendor veresion.
  private StringArgument vendorVersionArgument;



  /**
   * Parse the provided command line arguments and uses them to start the
   * directory server.
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
   * Parse the provided command line arguments and uses them to start the
   * directory server.
   *
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   * @param  args       The command line arguments provided to this program.
   *
   * @return  A result code indicating whether the processing was successful.
   */
  public static ResultCode main(final String[] args,
                                final OutputStream outStream,
                                final OutputStream errStream)
  {
    final InMemoryDirectoryServerTool tool =
         new InMemoryDirectoryServerTool(outStream, errStream);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool that use the provided output streams
   * for standard output and standard error.
   *
   * @param  outStream  The output stream to use for standard output.  It may be
   *                    {@code System.out} for the JVM's default standard output
   *                    stream, {@code null} if no output should be generated,
   *                    or a custom output stream if the output should be sent
   *                    to an alternate location.
   * @param  errStream  The output stream to use for standard error.  It may be
   *                    {@code System.err} for the JVM's default standard error
   *                    stream, {@code null} if no output should be generated,
   *                    or a custom output stream if the output should be sent
   *                    to an alternate location.
   */
  public InMemoryDirectoryServerTool(final OutputStream outStream,
                                     final OutputStream errStream)
  {
    super(outStream, errStream);

    directoryServer                   = null;
    dontStartArgument                 = null;
    useDefaultSchemaArgument          = null;
    useSSLArgument                    = null;
    useStartTLSArgument               = null;
    additionalBindDNArgument          = null;
    baseDNArgument                    = null;
    accessLogToStandardOutArgument    = null;
    accessLogFileArgument             = null;
    keyStorePathArgument              = null;
    ldapDebugLogToStandardOutArgument = null;
    ldapDebugLogFileArgument          = null;
    ldifFileArgument                  = null;
    trustStorePathArgument            = null;
    useSchemaFileArgument             = null;
    maxChangeLogEntriesArgument       = null;
    portArgument                      = null;
    additionalBindPasswordArgument    = null;
    equalityIndexArgument             = null;
    keyStorePasswordArgument          = null;
    keyStoreTypeArgument              = null;
    trustStorePasswordArgument        = null;
    trustStoreTypeArgument            = null;
    vendorNameArgument                = null;
    vendorVersionArgument             = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolName()
  {
    return "in-memory-directory-server";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolDescription()
  {
    return INFO_MEM_DS_TOOL_DESC.get(InMemoryDirectoryServer.class.getName());
  }



  /**
   * Retrieves the version string for this tool.
   *
   * @return  The version string for this tool.
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
  public void addToolArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    portArgument = new IntegerArgument('p', "port", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PORT.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_PORT.get(), 0, 65535);
    portArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    parser.addArgument(portArgument);

    useSSLArgument = new BooleanArgument('Z', "useSSL",
         INFO_MEM_DS_TOOL_ARG_DESC_USE_SSL.get());
    useSSLArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    useSSLArgument.addLongIdentifier("use-ssl", true);
    parser.addArgument(useSSLArgument);

    useStartTLSArgument = new BooleanArgument('q', "useStartTLS",
         INFO_MEM_DS_TOOL_ARG_DESC_USE_START_TLS.get());
    useStartTLSArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    useStartTLSArgument.addLongIdentifier("use-starttls", true);
    useStartTLSArgument.addLongIdentifier("use-start-tls", true);
    parser.addArgument(useStartTLSArgument);

    keyStorePathArgument = new FileArgument('K', "keyStorePath", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PATH.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_KEY_STORE_PATH.get(), true, true, true,
         false);
    keyStorePathArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    keyStorePathArgument.addLongIdentifier("key-store-path", true);
    parser.addArgument(keyStorePathArgument);

    keyStorePasswordArgument = new StringArgument('W', "keyStorePassword",
         false, 1, INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PASSWORD.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_KEY_STORE_PW.get());
    keyStorePasswordArgument.setSensitive(true);
    keyStorePasswordArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    keyStorePasswordArgument.addLongIdentifier("keyStorePIN", true);
    keyStorePasswordArgument.addLongIdentifier("key-store-password", true);
    keyStorePasswordArgument.addLongIdentifier("key-store-pin", true);
    parser.addArgument(keyStorePasswordArgument);

    keyStoreTypeArgument = new StringArgument(null, "keyStoreType",
         false, 1, "{type}", "The keystore type.", "JKS");
    keyStoreTypeArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    keyStoreTypeArgument.addLongIdentifier("keyStoreFormat", true);
    keyStoreTypeArgument.addLongIdentifier("key-store-type", true);
    keyStoreTypeArgument.addLongIdentifier("key-store-format", true);
    parser.addArgument(keyStoreTypeArgument);

    trustStorePathArgument = new FileArgument('P', "trustStorePath", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PATH.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_TRUST_STORE_PATH.get(), true, true, true,
         false);
    trustStorePathArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    trustStorePathArgument.addLongIdentifier("trust-store-path", true);
    parser.addArgument(trustStorePathArgument);

    trustStorePasswordArgument = new StringArgument('T', "trustStorePassword",
         false, 1, INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PASSWORD.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_TRUST_STORE_PW.get());
    trustStorePasswordArgument.setSensitive(true);
    trustStorePasswordArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    trustStorePasswordArgument.addLongIdentifier("trustStorePIN", true);
    trustStorePasswordArgument.addLongIdentifier("trust-store-password", true);
    trustStorePasswordArgument.addLongIdentifier("trust-store-pin", true);
    parser.addArgument(trustStorePasswordArgument);

    trustStoreTypeArgument = new StringArgument(null, "trustStoreType",
         false, 1, "{type}", "The trust store type.", "JKS");
    trustStoreTypeArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    trustStoreTypeArgument.addLongIdentifier("trustStoreFormat", true);
    trustStoreTypeArgument.addLongIdentifier("trust-store-type", true);
    trustStoreTypeArgument.addLongIdentifier("trust-store-format", true);
    parser.addArgument(trustStoreTypeArgument);

    dontStartArgument = new BooleanArgument(null, "dontStart",
         INFO_MEM_DS_TOOL_ARG_DESC_DONT_START.get());
    dontStartArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_CONNECTIVITY.get());
    dontStartArgument.setHidden(true);
    dontStartArgument.addLongIdentifier("doNotStart", true);
    dontStartArgument.addLongIdentifier("dont-start", true);
    dontStartArgument.addLongIdentifier("do-not-start", true);
    parser.addArgument(dontStartArgument);

    baseDNArgument = new DNArgument('b', "baseDN", true, 0,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_BASE_DN.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_BASE_DN.get());
    baseDNArgument.setArgumentGroupName(INFO_MEM_DS_TOOL_GROUP_DATA.get());
    baseDNArgument.addLongIdentifier("base-dn", true);
    parser.addArgument(baseDNArgument);

    ldifFileArgument = new FileArgument('l', "ldifFile", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PATH.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_LDIF_FILE.get(), true, true, true, false);
    ldifFileArgument.setArgumentGroupName(INFO_MEM_DS_TOOL_GROUP_DATA.get());
    ldifFileArgument.addLongIdentifier("ldif-file", true);
    parser.addArgument(ldifFileArgument);

    additionalBindDNArgument = new DNArgument('D', "additionalBindDN", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_BIND_DN.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_ADDITIONAL_BIND_DN.get());
    additionalBindDNArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_DATA.get());
    additionalBindDNArgument.addLongIdentifier("additional-bind-dn", true);
    parser.addArgument(additionalBindDNArgument);

    additionalBindPasswordArgument = new StringArgument('w',
         "additionalBindPassword", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PASSWORD.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_ADDITIONAL_BIND_PW.get());
    additionalBindPasswordArgument.setSensitive(true);
    additionalBindPasswordArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_DATA.get());
    additionalBindPasswordArgument.addLongIdentifier(
         "additional-bind-password", true);
    parser.addArgument(additionalBindPasswordArgument);

    useDefaultSchemaArgument = new BooleanArgument('s', "useDefaultSchema",
         INFO_MEM_DS_TOOL_ARG_DESC_USE_DEFAULT_SCHEMA.get());
    useDefaultSchemaArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_DATA.get());
    useDefaultSchemaArgument.addLongIdentifier("use-default-schema", true);
    parser.addArgument(useDefaultSchemaArgument);

    useSchemaFileArgument = new FileArgument('S', "useSchemaFile", false, 0,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PATH.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_USE_SCHEMA_FILE.get(), true, true, false,
         false);
    useSchemaFileArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_DATA.get());
    useSchemaFileArgument.addLongIdentifier("use-schema-file", true);
    parser.addArgument(useSchemaFileArgument);

    equalityIndexArgument = new StringArgument('I', "equalityIndex", false, 0,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_ATTR.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_EQ_INDEX.get());
    equalityIndexArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_DATA.get());
    equalityIndexArgument.addLongIdentifier("equality-index", true);
    parser.addArgument(equalityIndexArgument);

    maxChangeLogEntriesArgument = new IntegerArgument('c',
         "maxChangeLogEntries", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_COUNT.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_MAX_CHANGELOG_ENTRIES.get(), 0,
         Integer.MAX_VALUE, 0);
    maxChangeLogEntriesArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_DATA.get());
    maxChangeLogEntriesArgument.addLongIdentifier("max-changelog-entries",
         true);
    maxChangeLogEntriesArgument.addLongIdentifier("max-change-log-entries",
         true);
    parser.addArgument(maxChangeLogEntriesArgument);

    vendorNameArgument = new StringArgument(null, "vendorName", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_VALUE.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_VENDOR_NAME.get());
    vendorNameArgument.setArgumentGroupName(INFO_MEM_DS_TOOL_GROUP_DATA.get());
    vendorNameArgument.addLongIdentifier("vendor-name", true);
    parser.addArgument(vendorNameArgument);

    vendorVersionArgument = new StringArgument(null, "vendorVersion", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_VALUE.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_VENDOR_VERSION.get());
    vendorVersionArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_DATA.get());
    vendorVersionArgument.addLongIdentifier("vendor-version", true);
    parser.addArgument(vendorVersionArgument);

    accessLogToStandardOutArgument = new BooleanArgument('A',
         "accessLogToStandardOut",
         INFO_MEM_DS_TOOL_ARG_DESC_ACCESS_LOG_TO_STDOUT.get());
    accessLogToStandardOutArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_LOGGING.get());
    accessLogToStandardOutArgument.addLongIdentifier(
         "access-log-to-standard-out", true);
    parser.addArgument(accessLogToStandardOutArgument);

    accessLogFileArgument = new FileArgument('a', "accessLogFile", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PATH.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_ACCESS_LOG_FILE.get(), false, true, true,
         false);
    accessLogFileArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_LOGGING.get());
    accessLogFileArgument.addLongIdentifier("access-log-format", true);
    parser.addArgument(accessLogFileArgument);

    ldapDebugLogToStandardOutArgument = new BooleanArgument(null,
         "ldapDebugLogToStandardOut",
         INFO_MEM_DS_TOOL_ARG_DESC_LDAP_DEBUG_LOG_TO_STDOUT.get());
    ldapDebugLogToStandardOutArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_LOGGING.get());
    ldapDebugLogToStandardOutArgument.addLongIdentifier(
         "ldap-debug-log-to-standard-out", true);
    parser.addArgument(ldapDebugLogToStandardOutArgument);

    ldapDebugLogFileArgument = new FileArgument('d', "ldapDebugLogFile", false,
         1, INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PATH.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_LDAP_DEBUG_LOG_FILE.get(), false, true, true,
         false);
    ldapDebugLogFileArgument.setArgumentGroupName(
         INFO_MEM_DS_TOOL_GROUP_LOGGING.get());
    ldapDebugLogFileArgument.addLongIdentifier("ldap-debug-log-file", true);
    parser.addArgument(ldapDebugLogFileArgument);

    codeLogFile = new FileArgument('C', "codeLogFile", false, 1, "{path}",
         INFO_MEM_DS_TOOL_ARG_DESC_CODE_LOG_FILE.get(), false, true, true,
         false);
    codeLogFile.setArgumentGroupName(INFO_MEM_DS_TOOL_GROUP_LOGGING.get());
    codeLogFile.addLongIdentifier("code-log-file", true);
    parser.addArgument(codeLogFile);

    parser.addExclusiveArgumentSet(useDefaultSchemaArgument,
         useSchemaFileArgument);
    parser.addExclusiveArgumentSet(useSSLArgument, useStartTLSArgument);

    parser.addExclusiveArgumentSet(accessLogToStandardOutArgument,
         accessLogFileArgument);
    parser.addExclusiveArgumentSet(ldapDebugLogToStandardOutArgument,
         ldapDebugLogFileArgument);

    parser.addDependentArgumentSet(additionalBindDNArgument,
         additionalBindPasswordArgument);
    parser.addDependentArgumentSet(additionalBindPasswordArgument,
         additionalBindDNArgument);

    parser.addDependentArgumentSet(useSSLArgument, keyStorePathArgument);
    parser.addDependentArgumentSet(useSSLArgument, keyStorePasswordArgument);
    parser.addDependentArgumentSet(useStartTLSArgument, keyStorePathArgument);
    parser.addDependentArgumentSet(useStartTLSArgument,
         keyStorePasswordArgument);
    parser.addDependentArgumentSet(keyStorePathArgument, useSSLArgument,
         useStartTLSArgument);
    parser.addDependentArgumentSet(keyStorePasswordArgument, useSSLArgument,
         useStartTLSArgument);
    parser.addDependentArgumentSet(trustStorePathArgument, useSSLArgument,
         useStartTLSArgument);
    parser.addDependentArgumentSet(trustStorePasswordArgument,
         trustStorePathArgument);
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
   * {@inheritDoc}
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    // Create a base configuration.
    final InMemoryDirectoryServerConfig serverConfig;
    try
    {
      serverConfig = getConfig();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      err(ERR_MEM_DS_TOOL_ERROR_INITIALIZING_CONFIG.get(le.getMessage()));
      return le.getResultCode();
    }


    // Create the server instance using the provided configuration, but don't
    // start it yet.
    try
    {
      directoryServer = new InMemoryDirectoryServer(serverConfig);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      err(ERR_MEM_DS_TOOL_ERROR_CREATING_SERVER_INSTANCE.get(le.getMessage()));
      return le.getResultCode();
    }


    // If an LDIF file was provided, then use it to populate the server.
    if (ldifFileArgument.isPresent())
    {
      final File ldifFile = ldifFileArgument.getValue();
      try
      {
        final int numEntries = directoryServer.importFromLDIF(true,
             ldifFile.getAbsolutePath());
        out(INFO_MEM_DS_TOOL_ADDED_ENTRIES_FROM_LDIF.get(numEntries,
             ldifFile.getAbsolutePath()));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err(ERR_MEM_DS_TOOL_ERROR_POPULATING_SERVER_INSTANCE.get(
             ldifFile.getAbsolutePath(), le.getMessage()));
        return le.getResultCode();
      }
    }


    // Start the server.
    try
    {
      if (! dontStartArgument.isPresent())
      {
        directoryServer.startListening();
        out(INFO_MEM_DS_TOOL_LISTENING.get(directoryServer.getListenPort()));
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      err(ERR_MEM_DS_TOOL_ERROR_STARTING_SERVER.get(
           StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Creates a server configuration based on information provided with
   * command line arguments.
   *
   * @return  The configuration that was created.
   *
   * @throws  LDAPException  If a problem is encountered while creating the
   *                         configuration.
   */
  private InMemoryDirectoryServerConfig getConfig()
          throws LDAPException
  {
    final List<DN> dnList = baseDNArgument.getValues();
    final DN[] baseDNs = new DN[dnList.size()];
    dnList.toArray(baseDNs);

    final InMemoryDirectoryServerConfig serverConfig =
         new InMemoryDirectoryServerConfig(baseDNs);


    // If a listen port was specified, then update the configuration to use it.
    int listenPort = 0;
    if (portArgument.isPresent())
    {
      listenPort = portArgument.getValue();
    }


    // If schema should be used, then get it.
    if (useDefaultSchemaArgument.isPresent())
    {
      serverConfig.setSchema(Schema.getDefaultStandardSchema());
    }
    else if (useSchemaFileArgument.isPresent())
    {
      final ArrayList<File> schemaFiles = new ArrayList<File>(10);
      for (final File f : useSchemaFileArgument.getValues())
      {
        if (f.exists())
        {
          if (f.isFile())
          {
            schemaFiles.add(f);
          }
          else
          {
            for (final File subFile : f.listFiles())
            {
              if (subFile.isFile())
              {
                schemaFiles.add(subFile);
              }
            }
          }
        }
        else
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_MEM_DS_TOOL_NO_SUCH_SCHEMA_FILE.get(f.getAbsolutePath()));
        }
      }

      try
      {
        serverConfig.setSchema(Schema.getSchema(schemaFiles));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        final StringBuilder fileList = new StringBuilder();
        final Iterator<File> fileIterator = schemaFiles.iterator();
        while (fileIterator.hasNext())
        {
          fileList.append(fileIterator.next().getAbsolutePath());
          if (fileIterator.hasNext())
          {
            fileList.append(", ");
          }
        }

        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MEM_DS_TOOL_ERROR_READING_SCHEMA.get(
                  fileList, StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else
    {
      serverConfig.setSchema(null);
    }


    // If an additional bind DN and password are provided, then include them in
    // the configuration.
    if (additionalBindDNArgument.isPresent())
    {
      serverConfig.addAdditionalBindCredentials(
           additionalBindDNArgument.getValue().toString(),
           additionalBindPasswordArgument.getValue());
    }


    // If a maximum number of changelog entries was specified, then update the
    // configuration with that.
    if (maxChangeLogEntriesArgument.isPresent())
    {
      serverConfig.setMaxChangeLogEntries(
           maxChangeLogEntriesArgument.getValue());
    }


    // If an access log file was specified, then create the appropriate log
    // handler.
    if (accessLogToStandardOutArgument.isPresent())
    {
      final StreamHandler handler = new StreamHandler(System.out,
           new MinimalLogFormatter(null, false, false, true));
      handler.setLevel(Level.INFO);
      serverConfig.setAccessLogHandler(handler);
    }
    else if (accessLogFileArgument.isPresent())
    {
      final File logFile = accessLogFileArgument.getValue();
      try
      {
        final FileHandler handler =
             new FileHandler(logFile.getAbsolutePath(), true);
        handler.setLevel(Level.INFO);
        handler.setFormatter(new MinimalLogFormatter(null, false, false,
             true));
        serverConfig.setAccessLogHandler(handler);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MEM_DS_TOOL_ERROR_CREATING_LOG_HANDLER.get(
                  logFile.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    // If an LDAP debug log file was specified, then create the appropriate log
    // handler.
    if (ldapDebugLogToStandardOutArgument.isPresent())
    {
      final StreamHandler handler = new StreamHandler(System.out,
           new MinimalLogFormatter(null, false, false, true));
      handler.setLevel(Level.INFO);
      serverConfig.setLDAPDebugLogHandler(handler);
    }
    else if (ldapDebugLogFileArgument.isPresent())
    {
      final File logFile = ldapDebugLogFileArgument.getValue();
      try
      {
        final FileHandler handler =
             new FileHandler(logFile.getAbsolutePath(), true);
        handler.setLevel(Level.INFO);
        handler.setFormatter(new MinimalLogFormatter(null, false, false,
             true));
        serverConfig.setLDAPDebugLogHandler(handler);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MEM_DS_TOOL_ERROR_CREATING_LOG_HANDLER.get(
                  logFile.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    // If a code log file was specified, then update the configuration
    // accordingly.
    if (codeLogFile.isPresent())
    {
      serverConfig.setCodeLogDetails(codeLogFile.getValue().getAbsolutePath(),
           true);
    }


    // If SSL is to be used, then create the corresponding socket factories.
    if (useSSLArgument.isPresent() || useStartTLSArgument.isPresent())
    {
      try
      {
        final KeyManager keyManager = new KeyStoreKeyManager(
             keyStorePathArgument.getValue(),
             keyStorePasswordArgument.getValue().toCharArray(),
             keyStoreTypeArgument.getValue(), null);

        final TrustManager trustManager;
        if (trustStorePathArgument.isPresent())
        {
          final char[] password;
          if (trustStorePasswordArgument.isPresent())
          {
            password = trustStorePasswordArgument.getValue().toCharArray();
          }
          else
          {
            password = null;
          }

          trustManager = new TrustStoreTrustManager(
               trustStorePathArgument.getValue(), password,
               trustStoreTypeArgument.getValue(), true);
        }
        else
        {
          trustManager = new TrustAllTrustManager();
        }

        final SSLUtil serverSSLUtil = new SSLUtil(keyManager, trustManager);

        if (useSSLArgument.isPresent())
        {
          final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());
          serverConfig.setListenerConfigs(
               InMemoryListenerConfig.createLDAPSConfig("LDAPS", null,
                    listenPort, serverSSLUtil.createSSLServerSocketFactory(),
                    clientSSLUtil.createSSLSocketFactory()));
        }
        else
        {
          serverConfig.setListenerConfigs(
               InMemoryListenerConfig.createLDAPConfig("LDAP+StartTLS", null,
                    listenPort, serverSSLUtil.createSSLSocketFactory()));
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MEM_DS_TOOL_ERROR_INITIALIZING_SSL.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else
    {
      serverConfig.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig(
           "LDAP", listenPort));
    }


    // If vendor name and/or vendor version values were provided, then configure
    // them for use.
    if (vendorNameArgument.isPresent())
    {
      serverConfig.setVendorName(vendorNameArgument.getValue());
    }

    if (vendorVersionArgument.isPresent())
    {
      serverConfig.setVendorVersion(vendorVersionArgument.getValue());
    }


    // If equality indexing is to be performed, then configure it.
    if (equalityIndexArgument.isPresent())
    {
      serverConfig.setEqualityIndexAttributes(
           equalityIndexArgument.getValues());
    }

    return serverConfig;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> exampleUsages =
         new LinkedHashMap<String[],String>(2);

    final String[] example1Args =
    {
      "--baseDN", "dc=example,dc=com"
    };
    exampleUsages.put(example1Args, INFO_MEM_DS_TOOL_EXAMPLE_1.get());

    final String[] example2Args =
    {
      "--baseDN", "dc=example,dc=com",
      "--port", "1389",
      "--ldifFile", "test.ldif",
      "--accessLogFile", "access.log",
      "--useDefaultSchema"
    };
    exampleUsages.put(example2Args, INFO_MEM_DS_TOOL_EXAMPLE_2.get());

    return exampleUsages;
  }



  /**
   * Retrieves the in-memory directory server instance that has been created by
   * this tool.  It will only be valid after the {@link #doToolProcessing()}
   * method has been called.
   *
   * @return  The in-memory directory server instance that has been created by
   *          this tool, or {@code null} if the directory server instance has
   *          not been successfully created.
   */
  public InMemoryDirectoryServer getDirectoryServer()
  {
    return directoryServer;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void connectionCreationFailure(final Socket socket,
                                        final Throwable cause)
  {
    err(ERR_MEM_DS_TOOL_ERROR_ACCEPTING_CONNECTION.get(
         StaticUtils.getExceptionMessage(cause)));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void connectionTerminated(
                   final LDAPListenerClientConnection connection,
                   final LDAPException cause)
  {
    err(ERR_MEM_DS_TOOL_CONNECTION_TERMINATED_BY_EXCEPTION.get(
         StaticUtils.getExceptionMessage(cause)));
  }
}
