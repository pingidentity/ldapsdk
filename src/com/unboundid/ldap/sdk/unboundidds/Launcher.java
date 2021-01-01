/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.List;

import com.unboundid.ldap.listener.InMemoryDirectoryServerTool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.examples.AuthRate;
import com.unboundid.ldap.sdk.examples.Base64Tool;
import com.unboundid.ldap.sdk.examples.IdentifyReferencesToMissingEntries;
import com.unboundid.ldap.sdk.examples.IdentifyUniqueAttributeConflicts;
import com.unboundid.ldap.sdk.examples.IndentLDAPFilter;
import com.unboundid.ldap.sdk.examples.LDAPDebugger;
import com.unboundid.ldap.sdk.examples.ModRate;
import com.unboundid.ldap.sdk.examples.SearchRate;
import com.unboundid.ldap.sdk.examples.SearchAndModRate;
import com.unboundid.ldap.sdk.examples.TestLDAPSDKPerformance;
import com.unboundid.ldap.sdk.examples.ValidateLDIF;
import com.unboundid.ldap.sdk.persist.GenerateSchemaFromSource;
import com.unboundid.ldap.sdk.persist.GenerateSourceFromSchema;
import com.unboundid.ldap.sdk.schema.ValidateLDAPSchema;
import com.unboundid.ldap.sdk.transformations.TransformLDIF;
import com.unboundid.ldap.sdk.unboundidds.examples.DumpDNs;
import com.unboundid.ldap.sdk.unboundidds.examples.SubtreeAccessibility;
import com.unboundid.ldap.sdk.unboundidds.examples.SummarizeAccessLog;
import com.unboundid.ldap.sdk.unboundidds.tools.CollectSupportData;
import com.unboundid.ldap.sdk.unboundidds.tools.GenerateTOTPSharedSecret;
import com.unboundid.ldap.sdk.unboundidds.tools.LDAPCompare;
import com.unboundid.ldap.sdk.unboundidds.tools.LDAPDelete;
import com.unboundid.ldap.sdk.unboundidds.tools.LDAPModify;
import com.unboundid.ldap.sdk.unboundidds.tools.LDAPPasswordModify;
import com.unboundid.ldap.sdk.unboundidds.tools.LDAPResultCode;
import com.unboundid.ldap.sdk.unboundidds.tools.LDAPSearch;
import com.unboundid.ldap.sdk.unboundidds.tools.ManageAccount;
import com.unboundid.ldap.sdk.unboundidds.tools.OIDLookup;
import com.unboundid.ldap.sdk.unboundidds.tools.ParallelUpdate;
import com.unboundid.ldap.sdk.unboundidds.tools.SplitLDIF;
import com.unboundid.ldif.LDIFDiff;
import com.unboundid.ldif.LDIFModify;
import com.unboundid.ldif.LDIFSearch;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.TLSCipherSuiteSelector;
import com.unboundid.util.ssl.cert.ManageCertificates;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides an entry point that may be used to launch other tools
 * provided as part of the LDAP SDK.  This is primarily a convenience for
 * someone who just has the jar file and none of the scripts, since you can run
 * "<CODE>java -jar unboundid-ldapsdk.jar {tool-name} {tool-args}</CODE>"
 * in order to invoke any of the example tools.  Running just
 * "<CODE>java -jar unboundid-ldapsdk.jar</CODE>" will display version
 * information about the LDAP SDK.
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
 * The tool names are case-insensitive.  Supported tool names include:
 * <UL>
 *   <LI>authrate -- Launch the {@link AuthRate} tool.</LI>
 *   <LI>base64 -- Launch the {@link Base64Tool} tool.</LI>
 *   <LI>collect-support-data -- Launch the
 *       {@link CollectSupportData} tool.</LI>
 *   <LI>deliver-one-time-password -- Launch the
 *       {@link DeliverOneTimePassword} tool.</LI>
 *   <LI>deliver-password-reset-token -- Launch the
 *       {@link DeliverPasswordResetToken} tool.</LI>
 *   <LI>dump-dns -- Launch the {@link DumpDNs} tool.</LI>
 *   <LI>generate-schema-from-source -- Launch the
 *       {@link GenerateSchemaFromSource} tool.</LI>
 *   <LI>generate-source-from-schema -- Launch the
 *       {@link GenerateSourceFromSchema} tool.</LI>
 *   <LI>generate-totp-shared-secret -- Launch the
 *       {@link GenerateTOTPSharedSecret} tool.</LI>
 *   <LI>identify-references-to-missing-entries -- Launch the
 *       {@link IdentifyReferencesToMissingEntries} tool.</LI>
 *   <LI>identify-unique-attribute-conflicts -- Launch the
 *       {@link IdentifyUniqueAttributeConflicts} tool.</LI>
 *   <LI>indent-ldap-filter -- Launch the {@link IndentLDAPFilter} tool.</LI>
 *   <LI>in-memory-directory-server -- Launch the
 *       {@link InMemoryDirectoryServerTool} tool.</LI>
 *   <LI>ldapcompare -- Launch the {@link LDAPCompare} tool.</LI>
 *   <LI>ldapdelete -- Launch the {@link LDAPDelete} tool.</LI>
 *   <LI>ldapmodify -- Launch the {@link LDAPModify} tool.</LI>
 *   <LI>ldappasswordmodify -- Launch the {@link LDAPPasswordModify} tool.</LI>
 *   <LI>ldapsearch -- Launch the {@link LDAPSearch} tool.</LI>
 *   <LI>ldap-debugger -- Launch the {@link LDAPDebugger} tool.</LI>
 *   <LI>ldap-result-code -- Launch the {@link LDAPResultCode} tool.</LI>
 *   <LI>ldifmodify -- Launch the {@link LDIFModify} tool.</LI>
 *   <LI>ldifsearch -- Launch the {@link LDIFSearch} tool.</LI>
 *   <LI>ldif-diff -- Launch the {@link LDIFDiff} tool.</LI>
 *   <LI>manage-account -- Launch the {@link ManageAccount} tool.</LI>
 *   <LI>manage-certificates -- Launch the {@link ManageCertificates} tool.</LI>
 *   <LI>modrate -- Launch the {@link ModRate} tool.</LI>
 *   <LI>move-subtree -- Launch the {@link MoveSubtree} tool.</LI>
 *   <LI>oid-lookup -- Launch the {@link OIDLookup} tool.</LI>
 *   <LI>parallel-update -- Launch the {@link ParallelUpdate} tool.</LI>
 *   <LI>register-yubikey-otp-device -- Launch the
 *       {@link RegisterYubiKeyOTPDevice} tool.</LI>
 *   <LI>searchrate -- Launch the {@link SearchRate} tool.</LI>
 *   <LI>search-and-mod-rate -- Launch the {@link SearchAndModRate} tool.</LI>
 *   <LI>split-ldif -- Launch the {@link SplitLDIF} tool.</LI>
 *   <LI>subtree-accessibility -- Launch the {@link SubtreeAccessibility}
 *       tool.</LI>
 *   <LI>summarize-access-log -- Launch the {@link SummarizeAccessLog}
 *       tool.</LI>
 *   <LI>test-ldap-sdk-performance -- Launch the {@link TLSCipherSuiteSelector}
 *       tool.</LI>
 *   <LI>tls-cipher-suite-selector -- Launch the {@link TLSCipherSuiteSelector}
 *       tool.</LI>
 *   <LI>transform-ldif -- Launch the {@link TransformLDIF} tool.</LI>
 *   <LI>validate-ldap-schema -- Launch the {@link ValidateLDAPSchema}
 *       tool.</LI>
 *   <LI>validate-ldif -- Launch the {@link ValidateLDIF} tool.</LI>
 *   <LI>version -- Display version information for the LDAP SDK.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Launcher
{
  /**
   * Prevent this utility class from being instantiated.
   */
  private Launcher()
  {
    // No implementation required.
  }



  /**
   * Parses the command-line arguments and performs any appropriate processing
   * for this program.
   *
   * @param  args  The command-line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    main(System.out, System.err, args);
  }



  /**
   * Parses the command-line arguments and performs any appropriate processing
   * for this program.
   *
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   * @param  args       The command-line arguments provided to this program.
   *
   * @return  A result code with information about the status of processing.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream outStream,
                                @Nullable final OutputStream errStream,
                                @NotNull final String... args)
  {
    if ((args == null) || (args.length == 0) ||
        args[0].equalsIgnoreCase("version"))
    {
      if (outStream != null)
      {
        final PrintStream out = new PrintStream(outStream);
        for (final String line : Version.getVersionLines())
        {
          out.println(line);
        }
      }

      return ResultCode.SUCCESS;
    }

    final String firstArg = StaticUtils.toLowerCase(args[0]);
    final String[] remainingArgs = new String[args.length - 1];
    System.arraycopy(args, 1, remainingArgs, 0, remainingArgs.length);

    if (firstArg.equals("authrate"))
    {
      return AuthRate.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("base64"))
    {
      return Base64Tool.main(System.in, outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("collect-support-data"))
    {
      return CollectSupportData.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("deliver-one-time-password"))
    {
      return DeliverOneTimePassword.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("deliver-password-reset-token"))
    {
      return DeliverPasswordResetToken.main(remainingArgs, outStream,
           errStream);
    }
    else if (firstArg.equals("dump-dns"))
    {
      return DumpDNs.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("identify-references-to-missing-entries"))
    {
      return IdentifyReferencesToMissingEntries.main(remainingArgs, outStream,
           errStream);
    }
    else if (firstArg.equals("identify-unique-attribute-conflicts"))
    {
      return IdentifyUniqueAttributeConflicts.main(remainingArgs, outStream,
           errStream);
    }
    else if (firstArg.equals("in-memory-directory-server"))
    {
      return InMemoryDirectoryServerTool.main(remainingArgs, outStream,
           errStream);
    }
    else if (firstArg.equals("indent-ldap-filter"))
    {
      return IndentLDAPFilter.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("generate-schema-from-source"))
    {
      return GenerateSchemaFromSource.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("generate-source-from-schema"))
    {
      return GenerateSourceFromSchema.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("generate-totp-shared-secret"))
    {
      return GenerateTOTPSharedSecret.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("ldapcompare"))
    {
      return LDAPCompare.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("ldapdelete"))
    {
      return LDAPDelete.main(System.in, outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("ldapmodify"))
    {
      return LDAPModify.main(System.in, outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("ldappasswordmodify"))
    {
      return LDAPPasswordModify.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("ldapsearch"))
    {
      return LDAPSearch.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("ldap-debugger"))
    {
      return LDAPDebugger.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("ldap-result-code"))
    {
      return LDAPResultCode.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("ldifmodify"))
    {
      return LDIFModify.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("ldifsearch"))
    {
      return LDIFSearch.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("ldif-diff"))
    {
      return LDIFDiff.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("manage-account"))
    {
      return ManageAccount.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("manage-certificates"))
    {
      return ManageCertificates.main(System.in, outStream, errStream,
           remainingArgs);
    }
    else if (firstArg.equals("modrate"))
    {
      return ModRate.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("move-subtree"))
    {
      return MoveSubtree.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("oid-lookup"))
    {
      return OIDLookup.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("parallel-update"))
    {
      return ParallelUpdate.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("register-yubikey-otp-device"))
    {
      return RegisterYubiKeyOTPDevice.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("searchrate"))
    {
      return SearchRate.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("search-and-mod-rate"))
    {
      return SearchAndModRate.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("split-ldif"))
    {
      return SplitLDIF.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("subtree-accessibility"))
    {
      return SubtreeAccessibility.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("summarize-access-log"))
    {
      return SummarizeAccessLog.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("test-ldap-sdk-performance"))
    {
      return TestLDAPSDKPerformance.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("tls-cipher-suite-selector"))
    {
      return TLSCipherSuiteSelector.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("transform-ldif"))
    {
      return TransformLDIF.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("validate-ldap-schema"))
    {
      return ValidateLDAPSchema.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("validate-ldif"))
    {
      return ValidateLDIF.main(remainingArgs, outStream, errStream);
    }
    else
    {
      if (errStream != null)
      {
        final PrintStream err = new PrintStream(errStream);
        err.println("Unrecognized tool name '" + args[0] + '\'');
        err.println("Supported tool names include:");
        err.println("     authrate");
        err.println("     base64");
        err.println("     collect-support-data");
        err.println("     deliver-one-time-password");
        err.println("     deliver-password-reset-token");
        err.println("     dump-dns");
        err.println("     generate-schema-from-source");
        err.println("     generate-source-from-schema");
        err.println("     generate-totp-shared-secret");
        err.println("     identify-references-to-missing-entries");
        err.println("     identify-unique-attribute-conflicts");
        err.println("     indent-ldap-filter");
        err.println("     in-memory-directory-server");
        err.println("     ldapcompare");
        err.println("     ldapdelete");
        err.println("     ldapmodify");
        err.println("     ldappasswordmodify");
        err.println("     ldapsearch");
        err.println("     ldap-debugger");
        err.println("     ldap-result-code");
        err.println("     ldifmodify");
        err.println("     ldifsearch");
        err.println("     ldif-diff");
        err.println("     manage-account");
        err.println("     manage-certificates");
        err.println("     modrate");
        err.println("     move-subtree");
        err.println("     oid-lookup");
        err.println("     parallel-update");
        err.println("     register-yubikey-otp-device");
        err.println("     searchrate");
        err.println("     search-and-mod-rate");
        err.println("     split-ldif");
        err.println("     subtree-accessibility");
        err.println("     summarize-access-log");
        err.println("     test-ldap-sdk-performance");
        err.println("     tls-cipher-suite-selector");
        err.println("     transform-ldif");
        err.println("     validate-ldap-schema");
        err.println("     validate-ldif");
        err.println("     version");
      }

      return ResultCode.PARAM_ERROR;
    }
  }



  /**
   * Retrieves a list of all of the classes that provide the implementations for
   * all of the command-line tools included with the LDAP SDK.
   *
   * @return  A list of all of the classes that provide  the implementations for
   *          all of the command-line tools included with the LDAP SDK.
   */
  @NotNull()
  public static List<Class<? extends CommandLineTool>> getToolClasses()
  {
    return Arrays.asList(
         AuthRate.class,
         Base64Tool.class,
         CollectSupportData.class,
         DeliverOneTimePassword.class,
         DeliverPasswordResetToken.class,
         DumpDNs.class,
         GenerateSchemaFromSource.class,
         GenerateSourceFromSchema.class,
         GenerateTOTPSharedSecret.class,
         IdentifyReferencesToMissingEntries.class,
         IdentifyUniqueAttributeConflicts.class,
         IndentLDAPFilter.class,
         InMemoryDirectoryServerTool.class,
         LDAPCompare.class,
         LDAPDebugger.class,
         LDAPDelete.class,
         LDAPModify.class,
         LDAPPasswordModify.class,
         LDAPResultCode.class,
         LDAPSearch.class,
         LDIFDiff.class,
         LDIFModify.class,
         LDIFSearch.class,
         ManageAccount.class,
         ManageCertificates.class,
         ModRate.class,
         MoveSubtree.class,
         OIDLookup.class,
         ParallelUpdate.class,
         RegisterYubiKeyOTPDevice.class,
         SearchAndModRate.class,
         SearchRate.class,
         SplitLDIF.class,
         SubtreeAccessibility.class,
         SummarizeAccessLog.class,
         TestLDAPSDKPerformance.class,
         TLSCipherSuiteSelector.class,
         TransformLDIF.class,
         ValidateLDAPSchema.class,
         ValidateLDIF.class);
  }



  /**
   * Retrieves an instance of the specified type of command-line tool with the
   * given output and error streams.  The tool class must provide a two-argument
   * constructor in which the first argument is a possibly-{@code null}
   * {@code OutputStream} to use for standard output, and the second argument is
   * a possibly-{@code null} {@code OutputStream} to use for standard error.
   *
   * @param  toolClass  The class that provides the implementation for the
   *                    desired command-line tool.
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   *
   * @return  An instance of the specified command-line tool.
   *
   * @throws  LDAPException  If a problem occurs while attempting to create an
   *                         instance of the requested tool.
   */
  @NotNull()
  public static CommandLineTool getToolInstance(
                     @NotNull final Class<?> toolClass,
                     @Nullable final OutputStream outStream,
                     @Nullable final OutputStream errStream)
         throws LDAPException
  {
    if (! CommandLineTool.class.isAssignableFrom(toolClass))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LAUNCHER_CLASS_NOT_COMMAND_LINE_TOOL.get(toolClass.getName(),
                CommandLineTool.class.getName()));
    }

    final Constructor<?> constructor;
    try
    {
      constructor = toolClass.getConstructor(OutputStream.class,
           OutputStream.class);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LAUNCHER_TOOL_CLASS_MISSING_EXPECTED_CONSTRUCTOR.get(
                toolClass.getName()),
           e);
    }


    try
    {
      return (CommandLineTool) constructor.newInstance(outStream, errStream);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LAUNCHER_ERROR_INVOKING_CONSTRUCTOR.get(toolClass.getName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }
}
