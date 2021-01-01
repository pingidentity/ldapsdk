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
package com.unboundid.util;



import java.io.OutputStream;
import java.io.PrintStream;

import com.unboundid.ldap.listener.InMemoryDirectoryServerTool;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.examples.AuthRate;
import com.unboundid.ldap.sdk.examples.Base64Tool;
import com.unboundid.ldap.sdk.examples.IdentifyReferencesToMissingEntries;
import com.unboundid.ldap.sdk.examples.IdentifyUniqueAttributeConflicts;
import com.unboundid.ldap.sdk.examples.IndentLDAPFilter;
import com.unboundid.ldap.sdk.examples.LDAPCompare;
import com.unboundid.ldap.sdk.examples.LDAPDebugger;
import com.unboundid.ldap.sdk.examples.LDAPModify;
import com.unboundid.ldap.sdk.examples.LDAPSearch;
import com.unboundid.ldap.sdk.examples.ModRate;
import com.unboundid.ldap.sdk.examples.SearchRate;
import com.unboundid.ldap.sdk.examples.SearchAndModRate;
import com.unboundid.ldap.sdk.examples.TestLDAPSDKPerformance;
import com.unboundid.ldap.sdk.examples.ValidateLDIF;
import com.unboundid.ldap.sdk.persist.GenerateSchemaFromSource;
import com.unboundid.ldap.sdk.persist.GenerateSourceFromSchema;
import com.unboundid.ldap.sdk.schema.ValidateLDAPSchema;
import com.unboundid.ldap.sdk.transformations.TransformLDIF;
import com.unboundid.ldif.LDIFDiff;
import com.unboundid.ldif.LDIFModify;
import com.unboundid.ldif.LDIFSearch;
import com.unboundid.util.ssl.TLSCipherSuiteSelector;
import com.unboundid.util.ssl.cert.ManageCertificates;



/**
 * This class provides an entry point that may be used to launch other tools
 * provided as part of the LDAP SDK.  This is primarily a convenience for
 * someone who just has the jar file and none of the scripts, since you can run
 * "<CODE>java -jar unboundid-ldapsdk.jar {tool-name} {tool-args}</CODE>"
 * in order to invoke any of the example tools.  Running just
 * "<CODE>java -jar unboundid-ldapsdk.jar</CODE>" will display version
 * information about the LDAP SDK.
 * <BR><BR>
 * The tool names are case-insensitive.  Supported tool names include:
 * <UL>
 *   <LI>authrate -- Launch the {@link AuthRate} tool.</LI>
 *   <LI>base64 -- Launch the {@link Base64Tool} tool.</LI>
 *   <LI>generate-schema-from-source -- Launch the
 *       {@link GenerateSchemaFromSource} tool.</LI>
 *   <LI>generate-source-from-schema -- Launch the
 *       {@link GenerateSourceFromSchema} tool.</LI>
 *   <LI>identify-references-to-missing-entries -- Launch the
 *       {@link IdentifyReferencesToMissingEntries} tool.</LI>
 *   <LI>identify-unique-attribute-conflicts -- Launch the
 *       {@link IdentifyUniqueAttributeConflicts} tool.</LI>
 *   <LI>indent-ldap-filter -- Launch the {@link IndentLDAPFilter} tool.</LI>
 *   <LI>in-memory-directory-server -- Launch the
 *       {@link InMemoryDirectoryServerTool} tool.</LI>
 *   <LI>ldapcompare -- Launch the {@link LDAPCompare} tool.</LI>
 *   <LI>ldapmodify -- Launch the {@link LDAPModify} tool.</LI>
 *   <LI>ldapsearch -- Launch the {@link LDAPSearch} tool.</LI>
 *   <LI>ldap-debugger -- Launch the {@link LDAPDebugger} tool.</LI>
 *   <LI>ldifmodify -- Launch the {@link LDIFModify} tool.</LI>
 *   <LI>ldifsearch -- Launch the {@link LDIFSearch} tool.</LI>
 *   <LI>ldif-diff -- Launch the {@link LDIFDiff} tool.</LI>
 *   <LI>manage-certificates -- Launch the {@link ManageCertificates} tool.</LI>
 *   <LI>modrate -- Launch the {@link ModRate} tool.</LI>
 *   <LI>searchrate -- Launch the {@link SearchRate} tool.</LI>
 *   <LI>search-and-mod-rate -- Launch the {@link SearchAndModRate} tool.</LI>
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
   * Prevent this utility class from being externally instantiated.
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
                                @Nullable final String... args)
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
    else if (firstArg.equals("indent-ldap-filter"))
    {
      return IndentLDAPFilter.main(outStream, errStream, remainingArgs);
    }
    else if (firstArg.equals("in-memory-directory-server"))
    {
      return InMemoryDirectoryServerTool.main(remainingArgs, outStream,
           errStream);
    }
    else if (firstArg.equals("generate-schema-from-source"))
    {
      return GenerateSchemaFromSource.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("generate-source-from-schema"))
    {
      return GenerateSourceFromSchema.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("ldapcompare"))
    {
      return LDAPCompare.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("ldapmodify"))
    {
      return LDAPModify.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("ldapsearch"))
    {
      return LDAPSearch.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("ldap-debugger"))
    {
      return LDAPDebugger.main(remainingArgs, outStream, errStream);
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
    else if (firstArg.equals("manage-certificates"))
    {
      return ManageCertificates.main(System.in, outStream, errStream,
           remainingArgs);
    }
    else if (firstArg.equals("modrate"))
    {
      return ModRate.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("searchrate"))
    {
      return SearchRate.main(remainingArgs, outStream, errStream);
    }
    else if (firstArg.equals("search-and-mod-rate"))
    {
      return SearchAndModRate.main(remainingArgs, outStream, errStream);
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
        err.println("     generate-schema-from-source");
        err.println("     generate-source-from-schema");
        err.println("     identify-references-to-missing-entries");
        err.println("     identify-unique-attribute-conflicts");
        err.println("     indent-ldap-filter");
        err.println("     in-memory-directory-server");
        err.println("     ldapcompare");
        err.println("     ldapmodify");
        err.println("     ldapsearch");
        err.println("     ldap-debugger");
        err.println("     ldifmodify");
        err.println("     ldifsearch");
        err.println("     ldif-diff");
        err.println("     manage-certificates");
        err.println("     modrate");
        err.println("     searchrate");
        err.println("     search-and-mod-rate");
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
}
