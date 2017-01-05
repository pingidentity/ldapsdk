/*
 * Copyright 2011-2017 UnboundID Corp.
 * All Rights Reserved.
 */
package com.unboundid.buildtools.minimalsource;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

import com.unboundid.util.StaticUtils;



/**
 * This class provides an Ant task that can be used to create a minimized
 * version of the LDAP SDK source code in an attempt to make the jar file as
 * small as possible, but one that is still fully functional for basic LDAP
 * operations.
 */
public final class GenerateMinimalSource
       extends Task
{
  /**
   * The set of classes that should be retained in the minimal version of the
   * source code.
   */
  private static final String[] CLASSES_TO_RETAIN =
  {
    "com.unboundid.asn1.ASN1Boolean",
    "com.unboundid.asn1.ASN1Buffer",
    "com.unboundid.asn1.ASN1BufferSequence",
    "com.unboundid.asn1.ASN1BufferSet",
    "com.unboundid.asn1.ASN1Constants",
    "com.unboundid.asn1.ASN1Element",
    "com.unboundid.asn1.ASN1Enumerated",
    "com.unboundid.asn1.ASN1Exception",
    "com.unboundid.asn1.ASN1Integer",
    "com.unboundid.asn1.ASN1Long",
    "com.unboundid.asn1.ASN1Null",
    "com.unboundid.asn1.ASN1OctetString",
    "com.unboundid.asn1.ASN1Sequence",
    "com.unboundid.asn1.ASN1Set",
    "com.unboundid.asn1.ASN1StreamReader",
    "com.unboundid.asn1.ASN1StreamReaderSequence",
    "com.unboundid.asn1.ASN1StreamReaderSet",
    "com.unboundid.asn1.ASN1Writer",
    "com.unboundid.asn1.InternalASN1Helper",
    "com.unboundid.asn1.package-info",

    "com.unboundid.ldap.matchingrules.AcceptAllSimpleMatchingRule",
    "com.unboundid.ldap.matchingrules.BooleanMatchingRule",
    "com.unboundid.ldap.matchingrules.CaseExactStringMatchingRule",
    "com.unboundid.ldap.matchingrules.CaseIgnoreListMatchingRule",
    "com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule",
    "com.unboundid.ldap.matchingrules.DistinguishedNameMatchingRule",
    "com.unboundid.ldap.matchingrules.GeneralizedTimeMatchingRule",
    "com.unboundid.ldap.matchingrules.IntegerMatchingRule",
    "com.unboundid.ldap.matchingrules.MatchingRule",
    "com.unboundid.ldap.matchingrules.NumericStringMatchingRule",
    "com.unboundid.ldap.matchingrules.OctetStringMatchingRule",
    "com.unboundid.ldap.matchingrules.SimpleMatchingRule",
    "com.unboundid.ldap.matchingrules.TelephoneNumberMatchingRule",
    "com.unboundid.ldap.matchingrules.package-info",

    "com.unboundid.ldap.protocol.AbandonRequestProtocolOp",
    "com.unboundid.ldap.protocol.AddRequestProtocolOp",
    "com.unboundid.ldap.protocol.AddResponseProtocolOp",
    "com.unboundid.ldap.protocol.BindRequestProtocolOp",
    "com.unboundid.ldap.protocol.BindResponseProtocolOp",
    "com.unboundid.ldap.protocol.CompareRequestProtocolOp",
    "com.unboundid.ldap.protocol.CompareResponseProtocolOp",
    "com.unboundid.ldap.protocol.DeleteRequestProtocolOp",
    "com.unboundid.ldap.protocol.DeleteResponseProtocolOp",
    "com.unboundid.ldap.protocol.ExtendedRequestProtocolOp",
    "com.unboundid.ldap.protocol.ExtendedResponseProtocolOp",
    "com.unboundid.ldap.protocol.GenericResponseProtocolOp",
    "com.unboundid.ldap.protocol.IntermediateResponseProtocolOp",
    "com.unboundid.ldap.protocol.LDAPMessage",
    "com.unboundid.ldap.protocol.LDAPResponse",
    "com.unboundid.ldap.protocol.ModifyRequestProtocolOp",
    "com.unboundid.ldap.protocol.ModifyResponseProtocolOp",
    "com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp",
    "com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp",
    "com.unboundid.ldap.protocol.ProtocolOp",
    "com.unboundid.ldap.protocol.SearchRequestProtocolOp",
    "com.unboundid.ldap.protocol.SearchResultDoneProtocolOp",
    "com.unboundid.ldap.protocol.SearchResultEntryProtocolOp",
    "com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp",
    "com.unboundid.ldap.protocol.UnbindRequestProtocolOp",

    "com.unboundid.ldap.sdk.AbstractConnectionPool",
    "com.unboundid.ldap.sdk.AddRequest",
    "com.unboundid.ldap.sdk.AsyncCompareHelper",
    "com.unboundid.ldap.sdk.AsyncCompareResultListener",
    "com.unboundid.ldap.sdk.AsyncHelper",
    "com.unboundid.ldap.sdk.AsyncRequestID",
    "com.unboundid.ldap.sdk.AsyncResultListener",
    "com.unboundid.ldap.sdk.AsyncSearchHelper",
    "com.unboundid.ldap.sdk.AsyncSearchResultListener",
    "com.unboundid.ldap.sdk.AsyncTimeoutTimerTask",
    "com.unboundid.ldap.sdk.Attribute",
    "com.unboundid.ldap.sdk.BindRequest",
    "com.unboundid.ldap.sdk.BindResult",
    "com.unboundid.ldap.sdk.ChangeType",
    "com.unboundid.ldap.sdk.CommonAsyncHelper",
    "com.unboundid.ldap.sdk.CompactAttribute",
    "com.unboundid.ldap.sdk.CompactEntry",
    "com.unboundid.ldap.sdk.CompareRequest",
    "com.unboundid.ldap.sdk.CompareResult",
    "com.unboundid.ldap.sdk.ConnectionClosedResponse",
    "com.unboundid.ldap.sdk.ConnectThread",
    "com.unboundid.ldap.sdk.Control",
    "com.unboundid.ldap.sdk.DecodeableControl",
    "com.unboundid.ldap.sdk.DeleteRequest",
    "com.unboundid.ldap.sdk.DereferencePolicy",
    "com.unboundid.ldap.sdk.DiscardAsyncListener",
    "com.unboundid.ldap.sdk.DisconnectHandler",
    "com.unboundid.ldap.sdk.DisconnectInfo",
    "com.unboundid.ldap.sdk.DisconnectType",
    "com.unboundid.ldap.sdk.DN",
    "com.unboundid.ldap.sdk.Entry",
    "com.unboundid.ldap.sdk.ExtendedRequest",
    "com.unboundid.ldap.sdk.ExtendedResult",
    "com.unboundid.ldap.sdk.FailoverServerSet",
    "com.unboundid.ldap.sdk.Filter",
    "com.unboundid.ldap.sdk.GenericSASLBindRequest",
    "com.unboundid.ldap.sdk.IntermediateResponse",
    "com.unboundid.ldap.sdk.IntermediateResponseListener",
    "com.unboundid.ldap.sdk.InternalSDKHelper",
    "com.unboundid.ldap.sdk.LDAPBindException",
    "com.unboundid.ldap.sdk.LDAPConnection",
    "com.unboundid.ldap.sdk.LDAPConnectionInternals",
    "com.unboundid.ldap.sdk.LDAPConnectionOptions",
    "com.unboundid.ldap.sdk.LDAPConnectionPool",
    "com.unboundid.ldap.sdk.LDAPConnectionPoolHealthCheck",
    "com.unboundid.ldap.sdk.LDAPConnectionPoolHealthCheckResult",
    "com.unboundid.ldap.sdk.LDAPConnectionPoolHealthCheckThread",
    "com.unboundid.ldap.sdk.LDAPConnectionPoolStatistics",
    "com.unboundid.ldap.sdk.LDAPConnectionReader",
    "com.unboundid.ldap.sdk.LDAPConnectionStatistics",
    "com.unboundid.ldap.sdk.LDAPException",
    "com.unboundid.ldap.sdk.LDAPExtendedOperationException",
    "com.unboundid.ldap.sdk.LDAPInterface",
    "com.unboundid.ldap.sdk.LDAPRequest",
    "com.unboundid.ldap.sdk.LDAPResult",
    "com.unboundid.ldap.sdk.LDAPRuntimeException",
    "com.unboundid.ldap.sdk.LDAPSearchException",
    "com.unboundid.ldap.sdk.LDAPURL",
    "com.unboundid.ldap.sdk.Modification",
    "com.unboundid.ldap.sdk.ModificationType",
    "com.unboundid.ldap.sdk.ModifyRequest",
    "com.unboundid.ldap.sdk.ModifyDNRequest",
    "com.unboundid.ldap.sdk.OperationType",
    "com.unboundid.ldap.sdk.ParallelPoolCloser",
    "com.unboundid.ldap.sdk.ParallelPoolCloserTask",
    "com.unboundid.ldap.sdk.ParallelPoolConnector",
    "com.unboundid.ldap.sdk.ParallelPoolConnectorTask",
    "com.unboundid.ldap.sdk.PasswordProvider",
    "com.unboundid.ldap.sdk.PostConnectProcessor",
    "com.unboundid.ldap.sdk.RDN",
    "com.unboundid.ldap.sdk.ReadOnlyAddRequest",
    "com.unboundid.ldap.sdk.ReadOnlyCompareRequest",
    "com.unboundid.ldap.sdk.ReadOnlyDeleteRequest",
    "com.unboundid.ldap.sdk.ReadOnlyEntry",
    "com.unboundid.ldap.sdk.ReadOnlyLDAPRequest",
    "com.unboundid.ldap.sdk.ReadOnlyModifyRequest",
    "com.unboundid.ldap.sdk.ReadOnlyModifyDNRequest",
    "com.unboundid.ldap.sdk.ReadOnlySearchRequest",
    "com.unboundid.ldap.sdk.ReferralConnector",
    "com.unboundid.ldap.sdk.ResponseAcceptor",
    "com.unboundid.ldap.sdk.ResultCode",
    "com.unboundid.ldap.sdk.RootDSE",
    "com.unboundid.ldap.sdk.RoundRobinServerSet",
    "com.unboundid.ldap.sdk.SASLBindInProgressException",
    "com.unboundid.ldap.sdk.SASLBindRequest",
    "com.unboundid.ldap.sdk.SearchRequest",
    "com.unboundid.ldap.sdk.SearchResult",
    "com.unboundid.ldap.sdk.SearchResultEntry",
    "com.unboundid.ldap.sdk.SearchResultListener",
    "com.unboundid.ldap.sdk.SearchResultReference",
    "com.unboundid.ldap.sdk.SearchScope",
    "com.unboundid.ldap.sdk.ServerSet",
    "com.unboundid.ldap.sdk.SimpleBindRequest",
    "com.unboundid.ldap.sdk.SingleServerSet",
    "com.unboundid.ldap.sdk.StartTLSPostConnectProcessor",
    "com.unboundid.ldap.sdk.ToCodeArgHelper",
    "com.unboundid.ldap.sdk.ToCodeHelper",
    "com.unboundid.ldap.sdk.UnsolicitedNotificationHandler",
    "com.unboundid.ldap.sdk.UpdatableLDAPRequest",
    "com.unboundid.ldap.sdk.Version",
    "com.unboundid.ldap.sdk.package-info",

    "com.unboundid.ldap.sdk.extensions.CancelExtendedRequest",
    "com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult",
    "com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest",
    "com.unboundid.ldap.sdk.extensions.package-info",

    "com.unboundid.ldap.sdk.schema.AttributeSyntaxDefinition",
    "com.unboundid.ldap.sdk.schema.AttributeTypeDefinition",
    "com.unboundid.ldap.sdk.schema.AttributeUsage",
    "com.unboundid.ldap.sdk.schema.DITContentRuleDefinition",
    "com.unboundid.ldap.sdk.schema.DITStructureRuleDefinition",
    "com.unboundid.ldap.sdk.schema.MatchingRuleDefinition",
    "com.unboundid.ldap.sdk.schema.MatchingRuleUseDefinition",
    "com.unboundid.ldap.sdk.schema.NameFormDefinition",
    "com.unboundid.ldap.sdk.schema.ObjectClassDefinition",
    "com.unboundid.ldap.sdk.schema.ObjectClassType",
    "com.unboundid.ldap.sdk.schema.SchemaElement",
    "com.unboundid.ldap.sdk.schema.Schema",
    "com.unboundid.ldap.sdk.schema.package-info",

    "com.unboundid.ldif.DuplicateValueBehavior",
    "com.unboundid.ldif.LDIFAddChangeRecord",
    "com.unboundid.ldif.LDIFAttribute",
    "com.unboundid.ldif.LDIFChangeRecord",
    "com.unboundid.ldif.LDIFDeleteChangeRecord",
    "com.unboundid.ldif.LDIFException",
    "com.unboundid.ldif.LDIFModifyChangeRecord",
    "com.unboundid.ldif.LDIFModifyDNChangeRecord",
    "com.unboundid.ldif.LDIFReader",
    "com.unboundid.ldif.LDIFReaderChangeRecordTranslator",
    "com.unboundid.ldif.LDIFReaderEntryTranslator",
    "com.unboundid.ldif.LDIFRecord",
    "com.unboundid.ldif.LDIFWriter",
    "com.unboundid.ldif.LDIFWriterChangeRecordTranslator",
    "com.unboundid.ldif.LDIFWriterEntryTranslator",
    "com.unboundid.ldif.package-info",
    "com.unboundid.ldif.TrailingSpaceBehavior",

    "com.unboundid.util.AggregateInputStream",
    "com.unboundid.util.Base64",
    "com.unboundid.util.ByteString",
    "com.unboundid.util.ByteStringBuffer",
    "com.unboundid.util.ByteStringFactory",
    "com.unboundid.util.Debug",
    "com.unboundid.util.DebugType",
    "com.unboundid.util.InternalUseOnly",
    "com.unboundid.util.LDAPSDKException",
    "com.unboundid.util.LDAPSDKRuntimeException",
    "com.unboundid.util.LDAPSDKThreadFactory",
    "com.unboundid.util.LDAPSDKUsageException",
    "com.unboundid.util.ObjectPair",
    "com.unboundid.util.SynchronizedSocketFactory",
    "com.unboundid.util.SynchronizedSSLSocketFactory",
    "com.unboundid.util.StaticUtils",
    "com.unboundid.util.Validator",
    "com.unboundid.util.WakeableSleeper",
    "com.unboundid.util.WeakHashSet",
    "com.unboundid.util.package-info",

    "com.unboundid.util.parallel.AsynchronousParallelProcessor",
    "com.unboundid.util.parallel.ParallelProcessor",
    "com.unboundid.util.parallel.Processor",
    "com.unboundid.util.parallel.Result",
    "com.unboundid.util.parallel.ResultProcessor",

    "com.unboundid.util.ssl.KeyStoreKeyManager",
    "com.unboundid.util.ssl.PKCS11KeyManager",
    "com.unboundid.util.ssl.PromptTrustManager",
    "com.unboundid.util.ssl.SetEnabledProtocolsSocket",
    "com.unboundid.util.ssl.SetEnabledProtocolsSSLServerSocketFactory",
    "com.unboundid.util.ssl.SetEnabledProtocolsSSLSocketFactory",
    "com.unboundid.util.ssl.SSLSocketVerifier",
    "com.unboundid.util.ssl.SSLUtil",
    "com.unboundid.util.ssl.TrustAllSSLSocketVerifier",
    "com.unboundid.util.ssl.TrustAllTrustManager",
    "com.unboundid.util.ssl.TrustStoreTrustManager",
    "com.unboundid.util.ssl.WrapperKeyManager",
    "com.unboundid.util.ssl.package-info"
  };



  /**
   * The message files to be retained in the minimized version of the source.
   * These messages will be
   */
  private static final String[] MESSAGE_FILES_TO_RETAIN =
  {
    "unboundid-ldapsdk-asn1.properties",
    "unboundid-ldapsdk-extop.properties",
    "unboundid-ldapsdk-ldap.properties",
    "unboundid-ldapsdk-ldif.properties",
    "unboundid-ldapsdk-matchingrules.properties",
    "unboundid-ldapsdk-protocol.properties",
    "unboundid-ldapsdk-schema.properties",
    "unboundid-ldapsdk-ssl.properties",
    "unboundid-ldapsdk-util.properties"
  };



  /**
   * The fully-qualified class names for annotation types to strip out of source
   * files.  Note that even though ThreadSafetyLevel isn't an annotation type,
   * we can lump it in with the rest of them since we want the import stripped.
   */
  private static final String[] ANNOTATIONS_TO_STRIP =
  {
    "com.unboundid.util.Extensible",
    "com.unboundid.util.Extensible",
    "com.unboundid.util.Mutable",
    "com.unboundid.util.NotExtensible",
    "com.unboundid.util.NotMutable",
    "com.unboundid.util.ThreadSafety",
    "com.unboundid.util.ThreadSafetyLevel"
  };



  /**
   * A map with information about methods to strip out of source files.  The
   * map keys should be the fully-qualified names of classes containing the
   * methods, and the values should be a list of the method signatures of the
   * methods to remove.
   */
  private static final Map<String,List<String>> METHODS_TO_STRIP =
       new LinkedHashMap<String,List<String>>(2);
  static
  {
    METHODS_TO_STRIP.put("com.unboundid.ldap.sdk.schema.Schema",
         Arrays.asList("public static Schema getDefaultStandardSchema"));

    METHODS_TO_STRIP.put("com.unboundid.util.StaticUtils",
         Arrays.asList("public static String cleanExampleCommandLineArgument"));
  }



  // The path to the directory containing the message properties files to
  // process.
  private File messagesSourceDirectory;

  // The path to the directory in which to write updated message properties
  // files.
  private File messagesTargetDirectory;

  // The path to the directory containing the original source files.
  private File sourceDirectory;

  // The path to the directory in which to write the pared-down set of source
  // files.
  private File targetDirectory;



  /**
   * Creates a new instance of this Ant task.
   */
  public GenerateMinimalSource()
  {
    messagesSourceDirectory = null;
    messagesTargetDirectory = null;
    sourceDirectory         = null;
    targetDirectory         = null;
  }



  /**
   * Specifies the path to the directory containing the source files that will
   * be processed to create the minimized version of the LDAP SDK.
   *
   * @param  sourceDirectory  The path to the directory containing the source
   *                          files that will be processed to create the
   *                          minimized version of the LDAP SDK.
   */
  public void setSourceDirectory(final File sourceDirectory)
  {
    this.sourceDirectory = sourceDirectory;
  }



  /**
   * Specifies the path to the directory in which the minimized version of the
   * source files should be written.
   *
   * @param  targetDirectory  The path to the directory in which the minimized
   *                          version of the source files should be written.
   */
  public void setTargetDirectory(final File targetDirectory)
  {
    this.targetDirectory = targetDirectory;
  }



  /**
   * Specifies the path to the directory containing the message files that will
   * be processed to create the minimized version of the LDAP SDK.
   *
   * @param  messagesSourceDirectory  The path to the directory containing the
   *                                  source files that will be processed to
   *                                  create the minimized version of the LDAP
   *                                  SDK.
   */
  public void setMessagesSourceDirectory(final File messagesSourceDirectory)
  {
    this.messagesSourceDirectory = messagesSourceDirectory;
  }



  /**
   * Specifies the path to the directory in which the minimized version of the
   * messages files should be written.
   *
   * @param  messagesTargetDirectory  The path to the directory in which the
   *                                  minimized version of the message files
   *                                  should be written.
   */
  public void setMessagesTargetDirectory(final File messagesTargetDirectory)
  {
    this.messagesTargetDirectory = messagesTargetDirectory;
  }



  /**
   * Performs all necessary processing for this task.
   *
   * @throws  BuildException  If a problem is encountered.
   */
  @Override()
  public void execute()
         throws BuildException
  {
    if (sourceDirectory == null)
    {
      throw new BuildException("ERROR:  sourceDirectory not specified.");
    }

    if (! sourceDirectory.exists())
    {
      throw new BuildException("ERROR:  sourceDirectory does not exist.");
    }

    if (! sourceDirectory.isDirectory())
    {
      throw new BuildException("ERROR:  sourceDirectory is not a directory.");
    }


    if (targetDirectory == null)
    {
      throw new BuildException("ERROR:  targetDirectory not specified.");
    }

    if (targetDirectory.exists())
    {
      if (! targetDirectory.isDirectory())
      {
        throw new BuildException("ERROR:  targetDirectory is not a directory.");
      }
    }
    else
    {
      if (! targetDirectory.mkdirs())
      {
        throw new BuildException("ERROR:  Could not create targetDirectory '" +
             targetDirectory.getAbsolutePath() + "'.");
      }
    }


    if (messagesSourceDirectory == null)
    {
      throw new BuildException(
           "ERROR:  messagesSourceDirectory not specified.");
    }

    if (! messagesSourceDirectory.exists())
    {
      throw new BuildException(
           "ERROR:  messagesSourceDirectory does not exist.");
    }

    if (! messagesSourceDirectory.isDirectory())
    {
      throw new BuildException(
           "ERROR: messageSourceDirectory is not a directory.");
    }


    if (messagesTargetDirectory == null)
    {
      throw new BuildException(
           "ERROR:  messagesTargetDirectory not specified.");
    }

    if (messagesTargetDirectory.exists())
    {
      if (! messagesTargetDirectory.isDirectory())
      {
        throw new BuildException(
             "ERROR:  messagesTargetDirectory is not a directory.");
      }
    }
    else
    {
      if (! messagesTargetDirectory.mkdirs())
      {
        throw new BuildException(
             "ERROR:  Could not create messagesTargetDirectory '" +
                  messagesTargetDirectory.getAbsolutePath() + "'.");
      }
    }


    final HashSet<String> messageIDs = new HashSet<String>(1000);
    messageIDs.add("class.name");

    for (final String className : CLASSES_TO_RETAIN)
    {
      try
      {
        processClass(className, messageIDs);
      }
      catch (final BuildException be)
      {
        throw be;
      }
      catch (final Exception e)
      {
        throw new BuildException(
             "An error occurred while processing class " + className + ":  " +
                  StaticUtils.getExceptionMessage(e),
             e);
      }
    }


    for (final String messageFile : MESSAGE_FILES_TO_RETAIN)
    {
      try
      {
        processMessageFile(messageFile, messageIDs);
      }
      catch (final BuildException be)
      {
        throw be;
      }
      catch (final Exception e)
      {
        throw new BuildException(
             "An error occurred while processing message file '" + messageFile +
                  ":  " + StaticUtils.getExceptionMessage(e),
             e);
      }
    }
  }



  /**
   * Performs all appropriate processing for a single class.
   *
   * @param  className   The fully-qualified name of the class to process.
   * @param  messageIDs  A set to which the message IDs for any messages that
   *                     are used in the retained source should be added.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private void processClass(final String className,
                            final Set<String> messageIDs)
          throws Exception
  {
    // Get the source and target paths for the file.
    final String classPath =
         className.replace('.', File.separatorChar) + ".java";
    final File sourceFile = new File(sourceDirectory, classPath);
    final File targetFile = new File(targetDirectory, classPath);

    final File targetFileDir = targetFile.getParentFile();
    if (! targetFileDir.exists())
    {
      if (! targetFileDir.mkdirs())
      {
        throw new BuildException("ERROR:  Could not create directory '" +
             targetFileDir.getAbsolutePath() + "' for class " + className);
      }
    }


    // Define variables that will be used to determine whether a method should
    // be stripped from the file.
    final List<String> stripMethods = METHODS_TO_STRIP.get(className);
    final ArrayList<String> methodLines = new ArrayList<String>(100);
    boolean suppressMethod = false;


    // Read and process data from the file.
    final BufferedReader reader =
         new BufferedReader(new FileReader(sourceFile));
    final PrintWriter writer = new PrintWriter(targetFile);

lineLoop:
    while (true)
    {
      String line = reader.readLine();
      if (line == null)
      {
        for (final String s : methodLines)
        {
          writer.println(s);
        }
        break;
      }

      // We don't want to the @link element in javadoc because it may reference
      // something that isn't in the minimal edition.
      line = line.replace("{@link #", "{@code ");
      line = line.replace("{@link ", "{@code ");

      // While we're reading, we can strip out import and annotation lines that
      // should be excluded.
      final String trimmedLine = line.trim();
      extractMessageIDs(trimmedLine, messageIDs);
      for (final String annotationType : ANNOTATIONS_TO_STRIP)
      {
        if (trimmedLine.startsWith("import "))
        {
          if (trimmedLine.endsWith(annotationType + ';'))
          {
            continue lineLoop;
          }
        }
        else
        {
          final int lastPeriodPos = annotationType.lastIndexOf('.');
          final String annotation =
               '@' + annotationType.substring(lastPeriodPos+1);
          if (trimmedLine.startsWith(annotation))
          {
            continue lineLoop;
          }
        }
      }

      // See if the line indicates the beginning of a method.  This
      // determination will be made by assuming each method starts with "/**".
      if (trimmedLine.equals("/**"))
      {
        suppressMethod = false;
        for (final String s : methodLines)
        {
          writer.println(s);
        }
        methodLines.clear();
        methodLines.add(line);
      }
      else if (suppressMethod)
      {
        continue;
      }
      else
      {
        if (stripMethods != null)
        {
          for (final String s : stripMethods)
          {
            if (trimmedLine.contains(s))
            {
              suppressMethod = true;
              methodLines.clear();
              continue lineLoop;
            }
          }
        }

        methodLines.add(line);
      }
    }

    reader.close();
    writer.close();
  }



  /**
   * Parses the provided line to extract any message IDs contained in it.
   *
   * @param  line   The line to be examined.
   * @param  idSet  The set to which extracted message IDs should be added.
   */
  private static void extractMessageIDs(final String line,
                                        final Set<String> idSet)
  {
    final StringTokenizer tokenizer = new StringTokenizer(line, " (.,");
    while (tokenizer.hasMoreTokens())
    {
      final String token = tokenizer.nextToken();
      if (token.startsWith("INFO_") || token.startsWith("ERR_") ||
          token.startsWith("WARN_"))
      {
        idSet.add(token);
      }
    }
  }



  /**
   * Performs processing for the contents of the provided message file to strip
   * out any messages that aren't used in the minimal version of the source.
   *
   * @param  messageFile  The name of the message file to process.
   * @param  messageIDs   The set of message IDs to retain.
   *
   *
   */
  private void processMessageFile(final String messageFile,
                                  final Set<String> messageIDs)
          throws Exception
  {
    final File       sf = new File(messagesSourceDirectory, messageFile);
    final Properties sp = new Properties();

    final FileInputStream is = new FileInputStream(sf);
    sp.load(is);
    is.close();

    final Properties tp = new Properties();
    final Enumeration<?> nameEnum = sp.propertyNames();
    while (nameEnum.hasMoreElements())
    {
      final String propertyName = String.valueOf(nameEnum.nextElement());
      if (messageIDs.contains(propertyName))
      {
        tp.setProperty(propertyName, sp.getProperty(propertyName));
      }
    }

    final File tf = new File(messagesTargetDirectory, messageFile);
    final FileOutputStream os = new FileOutputStream(tf);
    tp.store(os, null);
    os.close();
  }
}
