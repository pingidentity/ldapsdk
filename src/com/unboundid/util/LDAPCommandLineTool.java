/*
 * Copyright 2008-2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2011 UnboundID Corp.
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



import java.io.OutputStream;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import com.unboundid.ldap.sdk.ANONYMOUSBindRequest;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequestProperties;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.PostConnectProcessor;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RoundRobinServerSet;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.SingleServerSet;
import com.unboundid.ldap.sdk.StartTLSPostConnectProcessor;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.PromptTrustManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a basis for developing command-line tools that
 * communicate with an LDAP directory server.  It provides a common set of
 * options for connecting and authenticating to a directory server, and then
 * provides a mechanism for obtaining connections and connection pools to use
 * when communicating with that server.
 * <BR><BR>
 * The arguments that this class supports include:
 * <UL>
 *   <LI>"-h {address}" or "--hostname {address}" -- Specifies the address of
 *       the directory server.  If this isn't specified, then a default of
 *       "localhost" will be used.</LI>
 *   <LI>"-p {port}" or "--port {port}" -- Specifies the port number of the
 *       directory server.  If this isn't specified, then a default port of 389
 *       will be used.</LI>
 *   <LI>"-D {bindDN}" or "--bindDN {bindDN}" -- Specifies the DN to use to bind
 *       to the directory server using simple authentication.  If this isn't
 *       specified, then simple authentication will not be performed.</LI>
 *   <LI>"-w {password}" or "--bindPassword {password}" -- Specifies the
 *       password to use when binding with simple authentication or a
 *       password-based SASL mechanism.</LI>
 *   <LI>"-j {path}" or "--bindPasswordFile {path}" -- Specifies the path to the
 *       file containing the password to use when binding with simple
 *       authentication or a password-based SASL mechanism.</LI>
 *   <LI>"-Z" or "--useSSL" -- Indicates that the communication with the server
 *       should be secured using SSL.</LI>
 *   <LI>"-q" or "--useStartTLS" -- Indicates that the communication with the
 *       server should be secured using StartTLS.</LI>
 *   <LI>"-X" or "--trustAll" -- Indicates that the client should trust any
 *       certificate that the server presents to it.</LI>
 *   <LI>"-K {path}" or "--keyStorePath {path}" -- Specifies the path to the
 *       key store to use to obtain client certificates.</LI>
 *   <LI>"-W {password}" or "--keyStorePassword {password}" -- Specifies the
 *       password to use to access the contents of the key store.</LI>
 *   <LI>"-u {path}" or "--keyStorePasswordFile {path}" -- Specifies the path to
 *       the file containing the password to use to access the contents of the
 *       key store.</LI>
 *   <LI>"--keyStoreFormat {format}" -- Specifies the format to use for the key
 *       store file.</LI>
 *   <LI>"-P {path}" or "--trustStorePath {path}" -- Specifies the path to the
 *       trust store to use when determining whether to trust server
 *       certificates.</LI>
 *   <LI>"-T {password}" or "--trustStorePassword {password}" -- Specifies the
 *       password to use to access the contents of the trust store.</LI>
 *   <LI>"-U {path}" or "--trustStorePasswordFile {path}" -- Specifies the path
 *       to the file containing the password to use to access the contents of
 *       the trust store.</LI>
 *   <LI>"--trustStoreFormat {format}" -- Specifies the format to use for the
 *       trust store file.</LI>
 *   <LI>"-N {nickname}" or "--certNickname {nickname}" -- Specifies the
 *       nickname of the client certificate to use when performing SSL client
 *       authentication.</LI>
 *   <LI>"-o {name=value}" or "--saslOption {name=value}" -- Specifies a SASL
 *       option to use when performing SASL authentication.</LI>
 * </UL>
 * If SASL authentication is to be used, then a "mech" SASL option must be
 * provided to specify the name of the SASL mechanism to use (e.g.,
 * "--saslOption mech=EXTERNAL" indicates that the EXTERNAL mechanism should be
 * used).  Depending on the SASL mechanism, additional SASL options may be
 * required or optional.  They include:
 * <UL>
 *   <LI>
 *     mech=ANONYMOUS
 *     <UL>
 *       <LI>Required SASL options:  </LI>
 *       <LI>Optional SASL options:  trace</LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=CRAM-MD5
 *     <UL>
 *       <LI>Required SASL options:  authID</LI>
 *       <LI>Optional SASL options:  </LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=DIGEST-MD5
 *     <UL>
 *       <LI>Required SASL options:  authID</LI>
 *       <LI>Optional SASL options:  authzID, realm</LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=EXTERNAL
 *     <UL>
 *       <LI>Required SASL options:  </LI>
 *       <LI>Optional SASL options:  </LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=GSSAPI
 *     <UL>
 *       <LI>Required SASL options:  authID</LI>
 *       <LI>Optional SASL options:  authzID, configFile, debug, protocol,
 *                realm, kdcAddress, useTicketCache, requireCache,
 *                renewTGT, ticketCachePath</LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=PLAIN
 *     <UL>
 *       <LI>Required SASL options:  authID</LI>
 *       <LI>Optional SASL options:  authzID</LI>
 *     </UL>
 *   </LI>
 * </UL>
 * <BR><BR>
 * Note that in general, methods in this class are not threadsafe.  However, the
 * {@link #getConnection()} and {@link #getConnectionPool(int,int)} methods may
 * be invoked concurrently by multiple threads accessing the same instance only
 * while that instance is in the process of invoking the
 * {@link #doToolProcessing()} method.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class LDAPCommandLineTool
       extends CommandLineTool
{
  /**
   * The set of required options for each SASL mechanism.
   */
  private static final Map<String,List<String>> REQUIRED_SASL_OPTIONS;



  /**
   * The set of optional options for each SASL mechanism.
   */
  private static final Map<String,List<String>> OPTIONAL_SASL_OPTIONS;



  /**
   * The name for the ANONYMOUS mechanism.
   */
  private static final String SASL_MECH_ANONYMOUS = "anonymous";



  /**
   * The name for the CRAM-MD5 mechanism.
   */
  private static final String SASL_MECH_CRAM_MD5 = "cram-md5";



  /**
   * The name for the DIGEST-MD5 mechanism.
   */
  private static final String SASL_MECH_DIGEST_MD5 = "digest-md5";



  /**
   * The name for the EXTERNAL mechanism.
   */
  private static final String SASL_MECH_EXTERNAL = "external";



  /**
   * The name for the GSSAPI mechanism.
   */
  private static final String SASL_MECH_GSSAPI = "gssapi";



  /**
   * The name for the PLAIN mechanism.
   */
  private static final String SASL_MECH_PLAIN = "plain";



  /**
   * The name of the SASL option that specifies the authentication ID.
   */
  private static final String SASL_OPTION_AUTH_ID = "authid";



  /**
   * The name of the SASL option that specifies the authorization ID.
   */
  private static final String SASL_OPTION_AUTHZ_ID = "authzid";



  /**
   * The name of the SASL option that specifies the path to the JAAS config
   * file.
   */
  private static final String SASL_OPTION_CONFIG_FILE = "configfile";



  /**
   * The name of the SASL option that indicates whether debugging should be
   * enabled.
   */
  private static final String SASL_OPTION_DEBUG = "debug";



  /**
   * The name of the SASL option that specifies the KDC address.
   */
  private static final String SASL_OPTION_KDC_ADDRESS = "kdcaddress";



  /**
   * The name of the SASL option that specifies the GSSAPI service principal
   * protocol.
   */
  private static final String SASL_OPTION_PROTOCOL = "protocol";



  /**
   * The name of the SASL option that specifies the realm name.
   */
  private static final String SASL_OPTION_REALM = "realm";



  /**
   * The name of the SASL option that indicates whether to require an existing
   * Kerberos session from the ticket cache.
   */
  private static final String SASL_OPTION_REQUIRE_CACHE = "requirecache";



  /**
   * The name of the SASL option that indicates whether to attempt to renew the
   * Kerberos TGT for an existing session.
   */
  private static final String SASL_OPTION_RENEW_TGT = "renewtgt";



  /**
   * The name of the SASL option that specifies the path to the Kerberos ticket
   * cache to use.
   */
  private static final String SASL_OPTION_TICKET_CACHE_PATH = "ticketcache";



  /**
   * The name of the SASL option that specifies the trace string.
   */
  private static final String SASL_OPTION_TRACE = "trace";



  /**
   * The name of the SASL option that specifies whether to use a Kerberos ticket
   * cache.
   */
  private static final String SASL_OPTION_USE_TICKET_CACHE = "useticketcache";



  // Arguments used to communicate with an LDAP directory server.
  private BooleanArgument trustAll;
  private BooleanArgument useSSL;
  private BooleanArgument useStartTLS;
  private DNArgument      bindDN;
  private FileArgument    bindPasswordFile;
  private FileArgument    keyStorePasswordFile;
  private FileArgument    trustStorePasswordFile;
  private IntegerArgument port;
  private StringArgument  bindPassword;
  private StringArgument  certificateNickname;
  private StringArgument  host;
  private StringArgument  keyStoreFormat;
  private StringArgument  keyStorePath;
  private StringArgument  keyStorePassword;
  private StringArgument  saslOption;
  private StringArgument  trustStoreFormat;
  private StringArgument  trustStorePath;
  private StringArgument  trustStorePassword;

  // The set of SASL options provided, if any.
  private Map<String,String> saslOptions;
  private String             saslMechanism;

  // Variables used when creating and authenticating connections.
  private BindRequest bindRequest;
  private ServerSet   serverSet;
  private SSLContext  startTLSContext;

  // The prompt trust manager that will be shared by all connections created
  // for which it is appropriate.  This will allow them to benefit from the
  // common cache.
  private final AtomicReference<PromptTrustManager> promptTrustManager;



  static
  {
    REQUIRED_SASL_OPTIONS = new LinkedHashMap<String,List<String>>(6);
    OPTIONAL_SASL_OPTIONS = new LinkedHashMap<String,List<String>>(6);

    REQUIRED_SASL_OPTIONS.put(SASL_MECH_ANONYMOUS, Arrays.<String>asList());
    OPTIONAL_SASL_OPTIONS.put(SASL_MECH_ANONYMOUS,
         Arrays.asList(SASL_OPTION_TRACE));

    REQUIRED_SASL_OPTIONS.put(SASL_MECH_CRAM_MD5,
         Arrays.asList(SASL_OPTION_AUTH_ID));
    OPTIONAL_SASL_OPTIONS.put(SASL_MECH_CRAM_MD5, Arrays.<String>asList());

    REQUIRED_SASL_OPTIONS.put(SASL_MECH_DIGEST_MD5,
         Arrays.asList(SASL_OPTION_AUTH_ID));
    OPTIONAL_SASL_OPTIONS.put(SASL_MECH_DIGEST_MD5,
         Arrays.asList(SASL_OPTION_AUTHZ_ID, SASL_OPTION_REALM));

    REQUIRED_SASL_OPTIONS.put(SASL_MECH_EXTERNAL, Arrays.<String>asList());
    OPTIONAL_SASL_OPTIONS.put(SASL_MECH_EXTERNAL, Arrays.<String>asList());

    REQUIRED_SASL_OPTIONS.put(SASL_MECH_GSSAPI,
         Arrays.asList(SASL_OPTION_AUTH_ID));
    OPTIONAL_SASL_OPTIONS.put(SASL_MECH_GSSAPI,
         Arrays.asList(SASL_OPTION_AUTHZ_ID,
              SASL_OPTION_CONFIG_FILE,
              SASL_OPTION_DEBUG,
              SASL_OPTION_PROTOCOL,
              SASL_OPTION_REALM,
              SASL_OPTION_KDC_ADDRESS,
              SASL_OPTION_RENEW_TGT,
              SASL_OPTION_REQUIRE_CACHE,
              SASL_OPTION_TICKET_CACHE_PATH,
              SASL_OPTION_USE_TICKET_CACHE));

    REQUIRED_SASL_OPTIONS.put(SASL_MECH_PLAIN,
         Arrays.asList(SASL_OPTION_AUTH_ID));
    OPTIONAL_SASL_OPTIONS.put(SASL_MECH_PLAIN,
         Arrays.asList(SASL_OPTION_AUTHZ_ID));
  }



  /**
   * Creates a new instance of this LDAP-enabled command-line tool with the
   * provided information.
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
  public LDAPCommandLineTool(final OutputStream outStream,
                             final OutputStream errStream)
  {
    super(outStream, errStream);

    promptTrustManager = new AtomicReference<PromptTrustManager>();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void addToolArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    host = new StringArgument('h', "hostname", true,
         (supportsMultipleServers() ? 0 : 1),
         INFO_LDAP_TOOL_PLACEHOLDER_HOST.get(),
         INFO_LDAP_TOOL_DESCRIPTION_HOST.get(), "localhost");
    parser.addArgument(host);

    port = new IntegerArgument('p', "port", true,
         (supportsMultipleServers() ? 0 : 1),
         INFO_LDAP_TOOL_PLACEHOLDER_PORT.get(),
         INFO_LDAP_TOOL_DESCRIPTION_PORT.get(), 1, 65535, 389);
    parser.addArgument(port);

    bindDN = new DNArgument('D', "bindDN", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_DN.get(),
         INFO_LDAP_TOOL_DESCRIPTION_BIND_DN.get());
    parser.addArgument(bindDN);

    bindPassword = new StringArgument('w', "bindPassword", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_PASSWORD.get(),
         INFO_LDAP_TOOL_DESCRIPTION_BIND_PW.get());
    parser.addArgument(bindPassword);

    bindPasswordFile = new FileArgument('j', "bindPasswordFile", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
         INFO_LDAP_TOOL_DESCRIPTION_BIND_PW_FILE.get(), true, true, true,
         false);
    parser.addArgument(bindPasswordFile);

    useSSL = new BooleanArgument('Z', "useSSL", 1,
         INFO_LDAP_TOOL_DESCRIPTION_USE_SSL.get());
    parser.addArgument(useSSL);

    useStartTLS = new BooleanArgument('q', "useStartTLS", 1,
         INFO_LDAP_TOOL_DESCRIPTION_USE_START_TLS.get());
    parser.addArgument(useStartTLS);

    trustAll = new BooleanArgument('X', "trustAll", 1,
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_ALL.get());
    parser.addArgument(trustAll);

    keyStorePath = new StringArgument('K', "keyStorePath", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
         INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PATH.get());
    parser.addArgument(keyStorePath);

    keyStorePassword = new StringArgument('W', "keyStorePassword", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_PASSWORD.get(),
         INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PASSWORD.get());
    parser.addArgument(keyStorePassword);

    keyStorePasswordFile = new FileArgument('u', "keyStorePasswordFile", false,
         1, INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
         INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PASSWORD_FILE.get());
    parser.addArgument(keyStorePasswordFile);

    keyStoreFormat = new StringArgument(null, "keyStoreFormat", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_FORMAT.get(),
         INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_FORMAT.get());
    parser.addArgument(keyStoreFormat);

    trustStorePath = new StringArgument('P', "trustStorePath", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PATH.get());
    parser.addArgument(trustStorePath);

    trustStorePassword = new StringArgument('T', "trustStorePassword", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_PASSWORD.get(),
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PASSWORD.get());
    parser.addArgument(trustStorePassword);

    trustStorePasswordFile = new FileArgument('U', "trustStorePasswordFile",
         false, 1, INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PASSWORD_FILE.get());
    parser.addArgument(trustStorePasswordFile);

    trustStoreFormat = new StringArgument(null, "trustStoreFormat", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_FORMAT.get(),
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_FORMAT.get());
    parser.addArgument(trustStoreFormat);

    certificateNickname = new StringArgument('N', "certNickname", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_CERT_NICKNAME.get(),
         INFO_LDAP_TOOL_DESCRIPTION_CERT_NICKNAME.get());
    parser.addArgument(certificateNickname);

    saslOption = new StringArgument('o', "saslOption", false, 0,
         INFO_LDAP_TOOL_PLACEHOLDER_SASL_OPTION.get(),
         INFO_LDAP_TOOL_DESCRIPTION_SASL_OPTION.get());
    parser.addArgument(saslOption);


    parser.addDependentArgumentSet(bindDN, bindPassword, bindPasswordFile);

    parser.addExclusiveArgumentSet(useSSL, useStartTLS);
    parser.addExclusiveArgumentSet(bindPassword, bindPasswordFile);
    parser.addExclusiveArgumentSet(keyStorePassword, keyStorePasswordFile);
    parser.addExclusiveArgumentSet(trustStorePassword, trustStorePasswordFile);
    parser.addExclusiveArgumentSet(trustAll, trustStorePath);

    addNonLDAPArguments(parser);
  }



  /**
   * Adds the arguments needed by this command-line tool to the provided
   * argument parser which are not related to connecting or authenticating to
   * the directory server.
   *
   * @param  parser  The argument parser to which the arguments should be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding the arguments.
   */
  public abstract void addNonLDAPArguments(final ArgumentParser parser)
         throws ArgumentException;



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // If more than one hostname or port number was provided, then make sure
    // that the same number of values were provided for each.
    if ((host.getValues().size() > 1) || (port.getValues().size() > 1))
    {
      if (host.getValues().size() != port.getValues().size())
      {
        throw new ArgumentException(
             ERR_LDAP_TOOL_HOST_PORT_COUNT_MISMATCH.get(
                  host.getLongIdentifier(), port.getLongIdentifier()));
      }
    }


    // If any SASL options were provided, then make sure they are valid.
    saslMechanism = null;
    saslOptions = new LinkedHashMap<String,String>(10);
    if (saslOption.isPresent())
    {
      for (final String s : saslOption.getValues())
      {
        final int equalPos = s.indexOf('=');
        if (equalPos < 0)
        {
          throw new ArgumentException(
               ERR_LDAP_TOOL_MALFORMED_SASL_OPTION.get(s));
        }

        final String optionName  = toLowerCase(s.substring(0, equalPos));
        final String optionValue = s.substring(equalPos+1);
        saslOptions.put(optionName, optionValue);
      }

      final LinkedHashMap<String,String> optionsCopy =
           new LinkedHashMap<String,String>(saslOptions);
      final String mech = optionsCopy.remove("mech");
      if (mech == null)
      {
        throw new ArgumentException(ERR_LDAP_TOOL_NO_SASL_MECH.get());
      }

      saslMechanism = toLowerCase(mech);
      final List<String> requiredOptions =
           REQUIRED_SASL_OPTIONS.get(saslMechanism);
      final List<String> optionalOptions =
           OPTIONAL_SASL_OPTIONS.get(saslMechanism);
      if (requiredOptions == null)
      {
        throw new ArgumentException(
             ERR_LDAP_TOOL_UNSUPPORTED_SASL_MECH.get(mech));
      }

      for (final String s : requiredOptions)
      {
        if (optionsCopy.remove(s) == null)
        {
          throw new ArgumentException(
               ERR_LDAP_TOOL_MISSING_REQUIRED_SASL_OPTION.get(s, mech));
        }
      }

      for (final String s : optionalOptions)
      {
        optionsCopy.remove(s);
      }

      if (! optionsCopy.isEmpty())
      {
        final String option = optionsCopy.keySet().iterator().next();
        throw new ArgumentException(
             ERR_LDAP_TOOL_INVALID_SASL_OPTION.get(option, mech));
      }
    }


    doExtendedNonLDAPArgumentValidation();
  }



  /**
   * Indicates whether this tool supports creating connections to multiple
   * servers.  If it is to support multiple servers, then the "--hostname" and
   * "--port" arguments will be allowed to be provided multiple times, and
   * will be required to be provided the same number of times.  The same type of
   * communication security and bind credentials will be used for all servers.
   *
   * @return  {@code true} if this tool supports creating connections to
   *          multiple servers, or {@code false} if not.
   */
  protected boolean supportsMultipleServers()
  {
    return false;
  }



  /**
   * Performs any necessary processing that should be done to ensure that the
   * provided set of command-line arguments were valid.  This method will be
   * called after the basic argument parsing has been performed and after all
   * LDAP-specific argument validation has been processed, and immediately
   * before the {@link CommandLineTool#doToolProcessing} method is invoked.
   *
   * @throws  ArgumentException  If there was a problem with the command-line
   *                             arguments provided to this program.
   */
  public void doExtendedNonLDAPArgumentValidation()
         throws ArgumentException
  {
    // No processing will be performed by default.
  }



  /**
   * Retrieves the connection options that should be used for connections that
   * are created with this command line tool.  Subclasses may override this
   * method to use a custom set of connection options.
   *
   * @return  The connection options that should be used for connections that
   *          are created with this command line tool.
   */
  public LDAPConnectionOptions getConnectionOptions()
  {
    return new LDAPConnectionOptions();
  }



  /**
   * Retrieves a connection that may be used to communicate with the target
   * directory server.
   * <BR><BR>
   * Note that this method is threadsafe and may be invoked by multiple threads
   * accessing the same instance only while that instance is in the process of
   * invoking the {@link #doToolProcessing} method.
   *
   * @return  A connection that may be used to communicate with the target
   *          directory server.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  public final LDAPConnection getConnection()
         throws LDAPException
  {
    if (serverSet == null)
    {
      serverSet   = createServerSet();
      bindRequest = createBindRequest();
    }

    final LDAPConnection connection = serverSet.getConnection();

    if (useStartTLS.isPresent())
    {
      try
      {
        final ExtendedResult extendedResult =
             connection.processExtendedOperation(
                  new StartTLSExtendedRequest(startTLSContext));
        if (! extendedResult.getResultCode().equals(ResultCode.SUCCESS))
        {
          throw new LDAPException(extendedResult.getResultCode(),
               ERR_LDAP_TOOL_START_TLS_FAILED.get(
                    extendedResult.getDiagnosticMessage()));
        }
      }
      catch (LDAPException le)
      {
        debugException(le);
        connection.close();
        throw le;
      }
    }

    try
    {
      if (bindRequest != null)
      {
        connection.bind(bindRequest);
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      connection.close();
      throw le;
    }

    return connection;
  }



  /**
   * Retrieves a connection pool that may be used to communicate with the target
   * directory server.
   * <BR><BR>
   * Note that this method is threadsafe and may be invoked by multiple threads
   * accessing the same instance only while that instance is in the process of
   * invoking the {@link #doToolProcessing} method.
   *
   * @param  initialConnections  The number of connections that should be
   *                             initially established in the pool.
   * @param  maxConnections      The maximum number of connections to maintain
   *                             in the pool.
   *
   * @return  A connection that may be used to communicate with the target
   *          directory server.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection
   *                         pool.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  public final LDAPConnectionPool getConnectionPool(
                                       final int initialConnections,
                                       final int maxConnections)
            throws LDAPException
  {
    if (serverSet == null)
    {
      serverSet   = createServerSet();
      bindRequest = createBindRequest();
    }

    PostConnectProcessor postConnectProcessor = null;
    if (useStartTLS.isPresent())
    {
      postConnectProcessor = new StartTLSPostConnectProcessor(startTLSContext);
    }

    return new LDAPConnectionPool(serverSet, bindRequest, initialConnections,
                                  maxConnections, postConnectProcessor);
  }



  /**
   * Creates the server set to use when creating connections or connection
   * pools.
   *
   * @return  The server set to use when creating connections or connection
   *          pools.
   *
   * @throws  LDAPException  If a problem occurs while creating the server set.
   */
  public ServerSet createServerSet()
         throws LDAPException
  {
    final SSLUtil sslUtil = createSSLUtil();

    SocketFactory socketFactory = null;
    if (useSSL.isPresent())
    {
      try
      {
        socketFactory = sslUtil.createSSLSocketFactory();
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDAP_TOOL_CANNOT_CREATE_SSL_SOCKET_FACTORY.get(
                  getExceptionMessage(e)), e);
      }
    }
    else if (useStartTLS.isPresent())
    {
      try
      {
        startTLSContext = sslUtil.createSSLContext();
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDAP_TOOL_CANNOT_CREATE_SSL_CONTEXT.get(
                  getExceptionMessage(e)), e);
      }
    }

    if (host.getValues().size() == 1)
    {
      return new SingleServerSet(host.getValue(), port.getValue(),
                                 socketFactory, getConnectionOptions());
    }
    else
    {
      final List<String>  hostList = host.getValues();
      final List<Integer> portList = port.getValues();

      final String[] hosts = new String[hostList.size()];
      final int[]    ports = new int[hosts.length];

      for (int i=0; i < hosts.length; i++)
      {
        hosts[i] = hostList.get(i);
        ports[i] = portList.get(i);
      }

      return new RoundRobinServerSet(hosts, ports, socketFactory,
                                     getConnectionOptions());
    }
  }



  /**
   * Creates the SSLUtil instance to use for secure communication.
   *
   * @return  The SSLUtil instance to use for secure communication, or
   *          {@code null} if secure communication is not needed.
   *
   * @throws  LDAPException  If a problem occurs while creating the SSLUtil
   *                         instance.
   */
  private SSLUtil createSSLUtil()
          throws LDAPException
  {
    if (useSSL.isPresent() || useStartTLS.isPresent())
    {
      KeyManager keyManager = null;
      if (keyStorePath.isPresent())
      {
        char[] pw = null;
        if (keyStorePassword.isPresent())
        {
          pw = keyStorePassword.getValue().toCharArray();
        }
        else if (keyStorePasswordFile.isPresent())
        {
          try
          {
            pw = keyStorePasswordFile.getNonBlankFileLines().get(0).
                      toCharArray();
          }
          catch (Exception e)
          {
            debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_LDAP_TOOL_CANNOT_READ_KEY_STORE_PASSWORD.get(
                      getExceptionMessage(e)), e);
          }
        }

        try
        {
          keyManager = new KeyStoreKeyManager(keyStorePath.getValue(), pw,
               keyStoreFormat.getValue(), certificateNickname.getValue());
        }
        catch (Exception e)
        {
          debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_LDAP_TOOL_CANNOT_CREATE_KEY_MANAGER.get(
                    getExceptionMessage(e)), e);
        }
      }

      TrustManager trustManager;
      if (trustAll.isPresent())
      {
        trustManager = new TrustAllTrustManager(false);
      }
      else if (trustStorePath.isPresent())
      {
        char[] pw = null;
        if (trustStorePassword.isPresent())
        {
          pw = trustStorePassword.getValue().toCharArray();
        }
        else if (trustStorePasswordFile.isPresent())
        {
          try
          {
            pw = trustStorePasswordFile.getNonBlankFileLines().get(0).
                      toCharArray();
          }
          catch (Exception e)
          {
            debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_LDAP_TOOL_CANNOT_READ_TRUST_STORE_PASSWORD.get(
                      getExceptionMessage(e)), e);
          }
        }

        trustManager = new TrustStoreTrustManager(trustStorePath.getValue(), pw,
             trustStoreFormat.getValue(), true);
      }
      else
      {
        trustManager = promptTrustManager.get();
        if (trustManager == null)
        {
          final PromptTrustManager m = new PromptTrustManager();
          promptTrustManager.compareAndSet(null, m);
          trustManager = promptTrustManager.get();
        }
      }

      return new SSLUtil(keyManager, trustManager);
    }
    else
    {
      return null;
    }
  }



  /**
   * Creates the bind request to use to authenticate to the server.
   *
   * @return  The bind request to use to authenticate to the server, or
   *          {@code null} if no bind should be performed.
   *
   * @throws  LDAPException  If a problem occurs while creating the bind
   *                         request.
   */
  private BindRequest createBindRequest()
          throws LDAPException
  {
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
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDAP_TOOL_CANNOT_READ_BIND_PASSWORD.get(
                  getExceptionMessage(e)), e);
      }
    }
    else
    {
      pw = null;
    }

    if (bindDN.isPresent())
    {
      return new SimpleBindRequest(bindDN.getValue(), pw);
    }
    else if (saslMechanism != null)
    {
      if (saslMechanism.equals(SASL_MECH_ANONYMOUS))
      {
        return new ANONYMOUSBindRequest(saslOptions.get(SASL_OPTION_TRACE));
      }
      else if (saslMechanism.equals(SASL_MECH_CRAM_MD5))
      {
        return new CRAMMD5BindRequest(saslOptions.get(SASL_OPTION_AUTH_ID), pw);
      }
      else if (saslMechanism.equals(SASL_MECH_DIGEST_MD5))
      {
        return new DIGESTMD5BindRequest(saslOptions.get(SASL_OPTION_AUTH_ID),
             saslOptions.get(SASL_OPTION_AUTHZ_ID), pw,
             saslOptions.get(SASL_OPTION_REALM));
      }
      else if (saslMechanism.equals(SASL_MECH_EXTERNAL))
      {
        return new EXTERNALBindRequest();
      }
      else if (saslMechanism.equals(SASL_MECH_GSSAPI))
      {
        final GSSAPIBindRequestProperties gssapiProperties =
             new GSSAPIBindRequestProperties(
                  saslOptions.get(SASL_OPTION_AUTH_ID), pw);
        gssapiProperties.setAuthorizationID(
             saslOptions.get(SASL_OPTION_AUTHZ_ID));
        gssapiProperties.setRealm(saslOptions.get(SASL_OPTION_REALM));
        gssapiProperties.setKDCAddress(
             saslOptions.get(SASL_OPTION_KDC_ADDRESS));
        gssapiProperties.setConfigFilePath(
             saslOptions.get(SASL_OPTION_CONFIG_FILE));
        gssapiProperties.setTicketCachePath(
             saslOptions.get(SASL_OPTION_TICKET_CACHE_PATH));

        final String protocol = saslOptions.get(SASL_OPTION_PROTOCOL);
        if (protocol != null)
        {
          gssapiProperties.setServicePrincipalProtocol(protocol);
        }

        final String useTicketCacheStr =
             saslOptions.get(SASL_OPTION_USE_TICKET_CACHE);
        if (useTicketCacheStr != null)
        {
          gssapiProperties.setUseTicketCache(
               useTicketCacheStr.equalsIgnoreCase("true"));
        }

        final String requireCacheStr =
             saslOptions.get(SASL_OPTION_REQUIRE_CACHE);
        if (requireCacheStr != null)
        {
          gssapiProperties.setRequireCachedCredentials(
               requireCacheStr.equalsIgnoreCase("true"));
        }

        final String renewTGTStr =
             saslOptions.get(SASL_OPTION_RENEW_TGT);
        if (renewTGTStr != null)
        {
          gssapiProperties.setRenewTGT(
               renewTGTStr.equalsIgnoreCase("true"));
        }

        final String debugStr = saslOptions.get(SASL_OPTION_DEBUG);
        if ((debugStr != null) && debugStr.equalsIgnoreCase("true"))
        {
          gssapiProperties.setEnableGSSAPIDebugging(true);
        }

        return new GSSAPIBindRequest(gssapiProperties);
      }
      else if (saslMechanism.equals(SASL_MECH_PLAIN))
      {
        return new PLAINBindRequest(saslOptions.get(SASL_OPTION_AUTH_ID),
             saslOptions.get(SASL_OPTION_AUTHZ_ID), pw);
      }
      else
      {
        throw new LDAPException(ResultCode.NOT_SUPPORTED,
             ERR_LDAP_TOOL_UNSUPPORTED_SASL_MECH.get(saslMechanism));
      }
    }
    else
    {
      return null;
    }
  }
}
