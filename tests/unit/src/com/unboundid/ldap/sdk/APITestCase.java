/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.TreeSet;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.unboundidds.MoveSubtree;
import com.unboundid.util.Extensible;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a set of test cases that test various components of the
 * API presented by the LDAP SDK.
 */
public class APITestCase
       extends LDAPSDKTestCase
{
  // The file that will be written with information about the current version of
  // the public API.
  private File publicAPIDefinitionFile;

  // The set of definitions from the current public API.
  private TreeSet<String> publicAPIDefinitions;



  /**
   * Determines the path that should be used for the file with information about
   * the public API.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void determinePublicAPIFile()
         throws Exception
  {
    File baseDir = new File(System.getProperty("basedir"));
    File buildDir = new File(baseDir, "build");
    File testDir = new File(buildDir, "test");
    publicAPIDefinitionFile = new File(testDir, "public-api.txt");
  }



  /**
   * Ensures that all public interfaces and public non-final classes included in
   * the API are marked with either the @Extensible or @NotExtensible annotation
   * type.  Classes must not be marked with both annotations.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testClassesAndInterfacesMarkedExtensible(final Class<?> c)
         throws Exception
  {
    boolean isExtensible    = false;
    boolean isNotExtensible = false;
    for (Annotation a : c.getAnnotations())
    {
      if (a.annotationType().equals(Extensible.class))
      {
        if (isExtensible)
        {
          fail("Multiple @Extensible annotations for class " + c.getName());
        }

        isExtensible = true;
      }
      else if (a.annotationType().equals(NotExtensible.class))
      {
        if (isNotExtensible)
        {
          fail("Multiple @NotExtensible annotations for class " + c.getName());
        }

        isNotExtensible = true;
      }
    }

    if (isExtensible && isNotExtensible)
    {
      fail("Class " + c.getName() + " is marked with both @Extensible and " +
           "@NotExtensible");
    }

    int modifiers = c.getModifiers();
    if (isExtensible || isNotExtensible)
    {
      if (Modifier.isFinal(modifiers))
      {
        if (isExtensible)
        {
          fail("Final class " + c.getName() +
               " has the @Extensible annotation");
        }
        else
        {
          fail("Final class " + c.getName() +
               " has the @NotExtensible annotation");
        }
      }

      return;
    }


    if (c.isEnum() || c.isAnnotation())
    {
      return;
    }

    if (! Modifier.isPublic(modifiers))
    {
      return;
    }

    if (c.isInterface())
    {
      fail("Public interface " + c.getName() +
           " does not have either the @Extensible or @NotExtensible " +
           "annotation");
    }

    if (! Modifier.isFinal(modifiers))
    {
      fail("Non-final public class " + c.getName() +
           " does not have either the @Extensible or @NotExtensible " +
           "annotation");
    }
  }



  /**
   * Tests to ensure that there are no cases in which an @Extensible class or
   * interface has a superclass that is marked @NotExtensible.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testExtensibleSubclassOfNotExtensible(final Class<?> c)
         throws Exception
  {
    boolean isExtensible = false;
    for (Annotation a : c.getAnnotations())
    {
      if (a.annotationType().equals(Extensible.class))
      {
        isExtensible = true;
        break;
      }
    }

    if (! isExtensible)
    {
      return;
    }

    Class<?> superclass = c.getSuperclass();
    while (superclass != null)
    {
      for (Annotation a : superclass.getAnnotations())
      {
        if (a.annotationType().equals(NotExtensible.class))
        {
          fail("@Extensible class " + c.getName() + " is a subclass of " +
               "@NotExtensible class " + superclass.getName());
        }
      }
      superclass = superclass.getSuperclass();
    }
  }



  /**
   * Ensures that all public classes and interfaces have exactly one instance of
   * the @ThreadSafety annotation.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testIncludesThreadSafety(final Class<?> c)
         throws Exception
  {
    boolean hasThreadSafety = false;
    for (Annotation a : c.getAnnotations())
    {
      if (a.annotationType().equals(ThreadSafety.class))
      {
        if (hasThreadSafety)
        {
          fail("Multiple @ThreadSafety annotations for class " + c.getName());
        }

        hasThreadSafety = true;
      }
    }

    if (hasThreadSafety)
    {
      return;
    }

    if (c.isEnum() || c.isAnnotation())
    {
      return;
    }

    int modifiers = c.getModifiers();
    if (! Modifier.isPublic(modifiers))
    {
      return;
    }

    fail("Public class or interface " + c.getName() +
         " does not include a @ThreadSafety annotation.");
  }



  /**
   * Ensures that all usages of @Mutable and @NotMutable meet certain
   * constraints.  They must not be applied to interfaces, enums, or annotation
   * types.  The @NotMutable annotation must not be used in abstract classes.
   * Both annotation types must not be used in the same class, and multiple
   * instances of either type must not be used in the same class.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testMutability(final Class<?> c)
         throws Exception
  {
    boolean isMutable    = false;
    boolean isNotMutable = false;
    for (Annotation a : c.getAnnotations())
    {
      if (a.annotationType().equals(Mutable.class))
      {
        if (isMutable)
        {
          fail("Multiple @Mutable annotations for class " + c.getName());
        }

        isMutable = true;
      }
      else if (a.annotationType().equals(NotMutable.class))
      {
        if (isNotMutable)
        {
          fail("Multiple @NotMutable annotations for class " + c.getName());
        }

        isNotMutable = true;
      }
    }

    if (isMutable && isNotMutable)
    {
      fail("Class " + c.getName() + " is marked with both @Mutable and " +
           "@NotMutable");
    }

    String annotation;
    if (isMutable)
    {
      annotation = "@Mutable";
    }
    else if (isNotMutable)
    {
      annotation = "@NotMutable";
    }
    else
    {
      return;
    }

    if (c.isInterface())
    {
      fail("Interface " + c.getName() + " is marked with the " + annotation +
           " annotation.");
    }

    if (c.isEnum())
    {
      fail("Enum " + c.getName() + " is marked with the " + annotation +
           " annotation.");
    }

    if (c.isAnnotation())
    {
      fail("Annotation type " + c.getName() + " is marked with the " +
           annotation + " annotation.");
    }

    int modifiers = c.getModifiers();
    if (isNotMutable && Modifier.isAbstract(modifiers))
    {
      fail("Abstract class " + c.getName() + " is marked with the " +
           "@NotMutable annotation.");
    }
  }



  /**
   * Ensures that all non-primitive fields, constructor and method parameters,
   * and method return values are marked with either the {@code NotNull} or
   * {@code Nullable} annotation types.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testNullability(final Class<?> c)
         throws Exception
  {
    // If the class is dynamically generated by something outside the LDAP SDK
    // codebase, then it won't be annotated.
    if (c.isSynthetic())
    {
      return;
    }

    // If the class is a dynamically generated messages file, then it won't be
    // annotated.
    if (c.isEnum() && c.getName().endsWith("Messages"))
    {
      try
      {
        c.getDeclaredField("defaultText");
        return;
      }
      catch (final Exception e)
      {
        // Ignore this.
      }
    }


    // If the class is the dynamically generated Version file, then ignore it.
    if (c.equals(Version.class))
    {
      return;
    }


    final List<String> errors = new ArrayList<>();


    // Make sure that all fields are annotated properly.
    for (final Field field : c.getDeclaredFields())
    {
      // If the field is dynamically generated, then it won't be annotated.
      if (field.isSynthetic())
      {
        continue;
      }

      // Ignore enum constants.
      if (field.isEnumConstant())
      {
        continue;
      }

      final Annotation notNullAnnotation = field.getAnnotation(NotNull.class);
      final Annotation nullableAnnotation = field.getAnnotation(Nullable.class);
      if (field.getType().isPrimitive())
      {
        if (notNullAnnotation != null)
        {
          errors.add("Primitive field '" + field.getName() +
               "' is marked @NotNull.");
        }

        if (nullableAnnotation != null)
        {
          errors.add("Primitive field '" + field.getName() +
               "' is marked @Nullable.");
        }
      }
      else
      {
        if (notNullAnnotation != null)
        {
          if (nullableAnnotation != null)
          {
            errors.add("Field '" + field.getName() +
                 "' is marked with both @NotNull and @Nullable.");
          }
        }
        else if (nullableAnnotation == null)
        {
          errors.add("Non-primitive field '" + field.getName() +
               "' is not marked with either @NotNull or @Nullable.");
        }
      }
    }


    // Make sure that all constructor parameters are annotated properly.
    // Note that enums can have dynamically generated constructors and there
    // deosn't seem to be a good way to detect them, so we'll just skip this
    // validation entirely for enums.
    if (! c.isEnum())
    {
      for (final Constructor<?> constructor : c.getDeclaredConstructors())
      {
        // If the constructor is dynamically generated, then it won't be
        // annotated.
        if (constructor.isSynthetic())
        {
          continue;
        }

        final Class<?>[] parameterTypes = constructor.getParameterTypes();
        final Annotation[][] parameterAnnotations =
             constructor.getParameterAnnotations();
        if (parameterTypes.length != parameterAnnotations.length)
        {
          // This can happen in some cases with enums, anonymous classes, and
          // local classes.  In that case, we can't check it.
          continue;
        }

        for (int i=0; i < parameterTypes.length; i++)
        {
          boolean isNotNull = false;
          boolean isNullable = false;
          for (final Annotation a : parameterAnnotations[i])
          {
            if (a.annotationType().equals(NotNull.class))
            {
              isNotNull = true;
            }
            else if (a.annotationType().equals(Nullable.class))
            {
              isNullable = true;
            }
          }

          if (parameterTypes[i].isPrimitive())
          {
            if (isNotNull)
            {
              errors.add("Constructor " + constructor + " parameter " + i +
                   " is primitive but is marked @NotNull.");
            }

            if (isNullable)
            {
              errors.add("Constructor " + constructor + " parameter " + i +
                   " is primitive but is marked @Nullable.");
            }
          }
          else
          {
            if (isNotNull)
            {
              if (isNullable)
              {
                errors.add("Constructor " + constructor + " parameter " + i +
                     " is marked both @NotNull and @Nullable.");
              }
            }
            else if (! isNullable)
            {
              // Enums can have a default constructor that takes two
              // parameters (String and int).  Since those constructors don't
              // exist in the codebase, they won't be annotated.
              if (c.isEnum() && (parameterTypes.length == 2) &&
                   (parameterTypes[0].equals(String.class) &&
                        parameterTypes[1].equals(Integer.TYPE)))
              {
                continue;
              }

              errors.add("Constructor " + constructor + " parameter " + i +
                   " is not primitive but is not marked @NotNull or " +
                   "@Nullable.");
            }
          }
        }
      }
    }


    // Make sure that all method return values and parameters are annotated
    // properly.
    for (final Method method : c.getDeclaredMethods())
    {
      // If the class is an enum, then we'll skip the valueOf(String) and
      // values() methods that are generated by the compiler.
      if (c.isEnum())
      {
        if (method.getName().equals("valueOf") &&
             (method.getParameterTypes().length == 1) &&
             (method.getParameterTypes()[0].equals(String.class)))
        {
          continue;
        }

        if (method.getName().equals("values") &&
             (method.getParameterTypes().length == 0))
        {
          continue;
        }
      }


      // If the method is dynamically generated, then it won't be
      // annotated.
      if (method.isSynthetic())
      {
        continue;
      }


      // Check the method return type.
      final Class<?> returnType = method.getReturnType();
      final Annotation notNullReturnTypeAnnotation =
           method.getAnnotation(NotNull.class);
      final Annotation nullableReturnTypeAnnotation =
           method.getAnnotation(Nullable.class);
      if (returnType.equals(Void.TYPE))
      {
        if (notNullReturnTypeAnnotation != null)
        {
          errors.add("Method " + method + " has a void return type but is " +
               "marked @NotNull.");
        }

        if (nullableReturnTypeAnnotation != null)
        {
          errors.add("Method " + method + " has a void return type but is " +
               "marked @Nullable.");
        }
      }
      else if (returnType.isPrimitive())
      {
        if (notNullReturnTypeAnnotation != null)
        {
          errors.add("Method " + method + " has a primitive return type but " +
               "is marked @NotNull.");
        }

        if (nullableReturnTypeAnnotation != null)
        {
          errors.add("Method " + method + " has a primitive return type but " +
               "is marked @Nullable.");
        }
      }
      else if (notNullReturnTypeAnnotation == null)
      {
        if (nullableReturnTypeAnnotation == null)
        {
          errors.add("Method " + method + " has a non-primitive return " +
               "type but is not marked @NotNull or @Nullable.");
        }
      }
      else if (nullableReturnTypeAnnotation != null)
      {
        errors.add("Method " + method + " is declared both @NotNull and " +
             "@Nullable.");
      }



      // Check the method parameters.
      final Class<?>[] parameterTypes = method.getParameterTypes();
      final Annotation[][] parameterAnnotations =
           method.getParameterAnnotations();
      if (parameterTypes.length != parameterAnnotations.length)
      {
        // This can happen in some cases with enums, anonymous classes, and
        // local classes.  In that case, we can't check it.
        continue;
      }

      for (int i=0; i < parameterTypes.length; i++)
      {
        boolean isNotNull = false;
        boolean isNullable = false;
        for (final Annotation a : parameterAnnotations[i])
        {
          if (a.annotationType().equals(NotNull.class))
          {
            isNotNull = true;
          }
          else if (a.annotationType().equals(Nullable.class))
          {
            isNullable = true;
          }
        }

        if (parameterTypes[i].isPrimitive())
        {
          if (isNotNull)
          {
            errors.add("Method " + method + " parameter " + i +
                 " is primitive but is marked @NotNull.");
          }

          if (isNullable)
          {
            errors.add("Method " + method + " parameter " + i +
                 " is primitive but is marked @Nullable.");
          }
        }
        else
        {
          if (isNotNull)
          {
            if (isNullable)
            {
              errors.add("Method " + method + " parameter " + i +
                   " is marked both @NotNull and @Nullable.");
            }
          }
          else if (! isNullable)
          {
            // Enums can have a default constructor that takes two
            // parameters (String and int).  Since those constructors don't
            // exist in the codebase, they won't be annotated.
            if (c.isEnum() && (parameterTypes.length == 2) &&
                 (parameterTypes[0].equals(String.class) &&
                      parameterTypes[1].equals(Integer.TYPE)))
            {
              continue;
            }

            errors.add("Method " + method + " parameter " + i +
                 " is not primitive but is not marked @NotNull or " +
                 "@Nullable.");
          }
        }
      }
    }


    if (! errors.isEmpty())
    {
      fail("Found nullability errors in class " + c.getName() + ":  " +
           StaticUtils.concatenateStrings(null, StaticUtils.EOL, null, null,
                null, errors));
    }
  }



  /**
   * Ensures that there are no non-final public or protected fields declared
   * anywhere in the LDAP SDK.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testEnsureNoNonFinalPublicOrProtectedFields(final Class<?> c)
         throws Exception
  {
    int classModifiers = c.getModifiers();
    if (! Modifier.isPublic(classModifiers))
    {
      return;
    }

    for (Field f : c.getFields())
    {
      int fieldModifiers = f.getModifiers();
      if (! Modifier.isFinal(fieldModifiers))
      {
        if (Modifier.isPublic(fieldModifiers))
        {
          fail("Non-final public field " + f.getName() + " found in class " +
               c.getName());
        }
        else if (Modifier.isProtected(fieldModifiers))
        {
          fail("Non-final protected field " + f.getName() + " found in class " +
               c.getName());
        }
      }
    }
  }



  /**
   * Ensures that all serializable classes include a private static final
   * serialVersionUID attribute.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testEnsureSerializableClassesHaveSerialVersionUID(
                   final Class<?> c)
         throws Exception
  {
    if (Serializable.class.isAssignableFrom(c))
    {
      if (c.isInterface() || c.isEnum())
      {
        return;
      }

      Field f = c.getDeclaredField("serialVersionUID");
      if (f == null)
      {
        fail("Serializable class " + c.getName() +
             " does not have a serialVersionUID field");
      }

      int modifiers = f.getModifiers();
      if (! Modifier.isPrivate(modifiers))
      {
        fail("serialVersionUID in class " + c.getName() + " is not private");
      }
      if (! Modifier.isStatic(modifiers))
      {
        fail("serialVersionUID in class " + c.getName() + " is not static");
      }
      if (! Modifier.isFinal(modifiers))
      {
        fail("serialVersionUID in class " + c.getName() + " is not final");
      }
    }
  }



  /**
   * Ensures that all classes which only contain primitive or serializable
   * fields are themselves declared serializable.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testEnsureClassesSerializableIfAppropriate(final Class<?> c)
         throws Exception
  {
    if (c.isAnnotation() || c.isInterface())
    {
      return;
    }

    if (Modifier.isAbstract(c.getModifiers()))
    {
      return;
    }

    if (Serializable.class.isAssignableFrom(c))
    {
      return;
    }

    final Class<?> superclass = c.getSuperclass();
    if (! superclass.equals(Object.class))
    {
      return;
    }

    boolean hasField = false;
    for (Field f : c.getDeclaredFields())
    {
      if (f.isSynthetic())
      {
        continue;
      }

      int fieldModifiers = f.getModifiers();
      if (Modifier.isStatic(fieldModifiers) && Modifier.isFinal(fieldModifiers))
      {
        continue;
      }

      hasField = true;

      Class<?> fieldClass = f.getType();
      while (fieldClass.isArray())
      {
        fieldClass = fieldClass.getComponentType();
      }

      if (! (fieldClass.isPrimitive() ||
             Serializable.class.isAssignableFrom(fieldClass)))
      {
        return;
      }
    }

    if (hasField)
    {
      // Check known exemptions that are acceptable to not be serializable.
      final Class<?>[] exemptions =
      {
        MoveSubtree.class
      };

      for (final Class<?> e : exemptions)
      {
        if (c.equals(e))
        {
          return;
        }
      }

      fail("Class " + c.getName() +
           " contains only serializable fields but is not serializable");
    }
  }



  /**
   * Ensures that all non-extensible, non-abstract classes which have only
   * static fields and/or methods do not contain public constructors.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testEnsureUtilityClassesNotInstantiable(final Class<?> c)
         throws Exception
  {
    if (c.isAnnotation() || c.isInterface() || c.isEnum())
    {
      return;
    }

    if (Throwable.class.isAssignableFrom(c))
    {
      return;
    }

    int classModifiers = c.getModifiers();
    if (Modifier.isAbstract(classModifiers) ||
        (! Modifier.isPublic(classModifiers)))
    {
      return;
    }

    for (Annotation a : c.getAnnotations())
    {
      if (a.annotationType().equals(Extensible.class))
      {
        return;
      }
    }

    if (hasNonStaticFieldOrMethod(c))
    {
      return;
    }

    for (final Constructor<?> ctor : c.getDeclaredConstructors())
    {
      int ctorModifiers = ctor.getModifiers();
      if (Modifier.isPublic(ctorModifiers))
      {
        fail("Class " + c.getName() + " does not have any non-static fields " +
             "or methods but has a public constructor.");
      }
    }
  }



  /**
   * Indicates whether the provided class has any non-static fields or methods.
   *
   * @param  c  The class for which to make the determination.
   *
   * @return  {@code true} if the class has one or more non-static fields, or
   *          {@code false} if not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static boolean hasNonStaticFieldOrMethod(final Class<?> c)
          throws Exception
  {
    for (Field f : c.getDeclaredFields())
    {
      if (f.isSynthetic())
      {
        continue;
      }

      int fieldModifiers = f.getModifiers();
      if (Modifier.isStatic(fieldModifiers))
      {
        continue;
      }

      return true;
    }

    for (Method m : c.getDeclaredMethods())
    {
      if (m.isSynthetic())
      {
        continue;
      }

      int methodModifiers = m.getModifiers();
      if (Modifier.isStatic(methodModifiers))
      {
        continue;
      }

      return true;
    }

    Class<?> superClass = c.getSuperclass();
    return (superClass.getName().startsWith("com.unboundid") &&
            hasNonStaticFieldOrMethod(superClass));
  }



  /**
   * Ensures that all public classes that include a "public void close()" method
   * that either throws no exception or throws IOException implements the
   * {@link Closeable} interface.
   *
   * @param  c  The class to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testEnsureCloseIsCloseable(final Class<?> c)
         throws Exception
  {
    if (c.isAnnotation() || c.isInterface() || c.isEnum())
    {
      return;
    }

    if (! Modifier.isPublic(c.getModifiers()))
    {
      return;
    }

    final Method closeMethod;
    try
    {
      closeMethod = c.getMethod("close");
    }
    catch (final Exception e)
    {
      return;
    }

    if (closeMethod == null)
    {
      return;
    }

    if (! Modifier.isPublic(closeMethod.getModifiers()))
    {
      return;
    }

    if (Closeable.class.isAssignableFrom(c))
    {
      return;
    }

    final Class<?>[] exceptionClasses =  closeMethod.getExceptionTypes();
    if ((exceptionClasses == null) || (exceptionClasses.length == 0))
    {
      fail("Class " + c.getName() + " has a close method but does not " +
           "implement " + Closeable.class.getName());
    }
    else if ((exceptionClasses.length == 1) &&
             IOException.class.isAssignableFrom(exceptionClasses[0]))
    {
      fail("Class " + c.getName() + " has a close method but does not " +
           "implement " + Closeable.class.getName());
    }
  }



  /**
   * Tests to ensure that the current API for the LDAP SDK is compatible with
   * previous versions.
   *
   * @param  f  The file containing the definition for the previous public API
   *            definition.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="publicAPIFiles",
        dependsOnMethods = { "writePublicAPIFile" })
  public void testAPICompatibility(final File f)
         throws Exception
  {
    TreeSet<String> defs = new TreeSet<String>();
    BufferedReader r = new BufferedReader(new FileReader(f));
    while (true)
    {
      String line = r.readLine();
      if (line == null)
      {
        break;
      }
      defs.add(line);
    }
    r.close();


    // Ensure that there are no lines in the old public API that are no longer
    // present in the new API.
    ArrayList<String> errors = new ArrayList<String>();
    for (String s : defs)
    {
      if (! publicAPIDefinitions.contains(s))
      {
        errors.add("Missing previous public API component:  " + s);
      }
    }


    // Ensure that there are no new abstract methods in any extensible class or
    // interface.
    for (String s : publicAPIDefinitions)
    {
      if ((! defs.contains(s)) && s.startsWith("@Extensible class ") &&
          s.contains(" abstract method "))
      {
        // This is only a problem if the class was present in the earlier API.
        StringTokenizer tokenizer = new StringTokenizer(s, " ");
        tokenizer.nextToken(); // @Extensible
        tokenizer.nextToken(); // class
        String interfaceName = tokenizer.nextToken();

        for (String def : defs)
        {
          if (def.startsWith("@Extensible interface " + interfaceName))
          {
            errors.add("New abstract method added to extensible class:  " + s);
            break;
          }
        }
      }
      else if ((! defs.contains(s)) && s.startsWith("@Extensible interface ") &&
               s.contains(" method "))
      {
        if (! defs.contains(s))
        {
          // This is only a problem if the interface was present in the earlier
          // API.
          StringTokenizer tokenizer = new StringTokenizer(s, " ");
          tokenizer.nextToken(); // @Extensible
          tokenizer.nextToken(); // interface
          String interfaceName = tokenizer.nextToken();

          for (String def : defs)
          {
            if (def.startsWith("@Extensible interface " + interfaceName))
            {
              errors.add("New method added to extensible interface:  " + s);
              break;
            }
          }
        }
      }
    }


    if (! errors.isEmpty())
    {
      StringBuilder buffer = new StringBuilder();
      for (String s : errors)
      {
        buffer.append(s);
        buffer.append(EOL);
      }

      fail("Incompatibilities with public API defined in file " +
           f.getAbsolutePath() + ":  " + buffer.toString());
    }
  }



  /**
   * Generates a text file representing the current public API exposed by the
   * LDAP SDK.  For each public class, interface, enum, or annotation type that
   * is not marked with the @InternalUseOnly annotation, it
   * will generate a string representation of each public or protected member
   * variable, constructor, and method not including the @InternalUseOnly
   * annotation type.  The contents of this file may then be compared with the
   * contents of stored files from specific releases to ensure that
   * compatibility has been preserved.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void writePublicAPIFile()
         throws Exception
  {
    TreeSet<String> defs = new TreeSet<String>();

    Object[][] sdkClasses = getSDKClasses();
    for (Object[] o : sdkClasses)
    {
      Class<?> c = (Class<?>) o[0];

      int classModifiers = c.getModifiers();
      if (!  Modifier.isPublic(classModifiers))
      {
        continue;
      }

      boolean isInternalUseOnly = false;
      boolean isExtensible      = false;
      boolean isNotExtensible   = false;
      for (Annotation a : c.getAnnotations())
      {
        if (a.annotationType().equals(InternalUseOnly.class))
        {
          isInternalUseOnly = true;
        }
        else if (a.annotationType().equals(Extensible.class))
        {
          isExtensible = true;
        }
        else if (a.annotationType().equals(NotExtensible.class))
        {
          isNotExtensible = true;
        }
      }

      if (isInternalUseOnly)
      {
        continue;
      }

      for (Constructor<?> ctor : c.getDeclaredConstructors())
      {
        String s = getDefinition(c, ctor, isExtensible, isNotExtensible);
        if (s != null)
        {
          defs.add(s);
        }
      }

      for (Field f : c.getDeclaredFields())
      {
        String s = getDefinition(c, f, isExtensible, isNotExtensible);
        if (s != null)
        {
          defs.add(s);
        }
      }

      for (Method m : c.getDeclaredMethods())
      {
        String s = getDefinition(c, m, isExtensible, isNotExtensible);
        if (s != null)
        {
          defs.add(s);
        }
      }
    }

    PrintWriter w = new PrintWriter(new FileWriter(publicAPIDefinitionFile));
    for (String s : defs)
    {
      w.println(s);
    }
    w.close();
    publicAPIDefinitions = defs;
  }



  /**
   * Retrieves a string representation of the provided constructor.
   *
   * @param  c                The class containing the constructor.
   * @param  ctor             The constructor to process.
   * @param  isExtensible     Indicates whether the class is marked with
   *                          the @Extensible annotation.
   * @param  isNotExtensible  Indicates whether the class is marked with
   *                          the @NotExtensible annotation.
   *
   * @return  A string representation of the provided constructor, or
   *          {@code null} if it should not be included in the output.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static String getDefinition(final Class<?> c,
                                      final Constructor<?> ctor,
                                      final boolean isExtensible,
                                      final boolean isNotExtensible)
          throws Exception
  {
    boolean inPublicAPI = false;
    String visibility = null;
    int ctorModifiers = ctor.getModifiers();
    if (Modifier.isPublic(ctorModifiers))
    {
      inPublicAPI = true;
      visibility  = "public ";
    }
    else if ((! Modifier.isFinal(c.getModifiers())) &&
             Modifier.isProtected(ctorModifiers))
    {
      inPublicAPI = true;
      visibility  = "protected ";
    }

    if (! inPublicAPI)
    {
      return null;
    }

    StringBuilder line = new StringBuilder();
    if (isExtensible)
    {
      line.append("@Extensible ");
    }
    else if (isNotExtensible)
    {
      line.append("@NotExtensible ");
    }

    if (c.isAnnotation())
    {
      line.append("annotation ");
    }
    else if (c.isEnum())
    {
      line.append("enum ");
    }
    else if (c.isInterface())
    {
      line.append("interface ");
    }
    else
    {
      line.append("class ");
    }

    line.append(c.getName());
    line.append(" constructor ");
    line.append(visibility);
    line.append(ctor.getName());
    line.append('(');

    Type[] paramTypes = ctor.getGenericParameterTypes();
    for (int i=0; i < paramTypes.length; i++)
    {
      if (i > 0)
      {
        line.append(',');
      }

      boolean varargs = (ctor.isVarArgs() && (i == (paramTypes.length - 1)));
      line.append(getUserFriendlyName(paramTypes[i], varargs));
    }
    line.append(')');

    Type[] exceptionTypes = ctor.getGenericExceptionTypes();
    if (exceptionTypes.length > 0)
    {
      line.append(" throws ");
      for (int i=0; i < exceptionTypes.length; i++)
      {
        if (i > 0)
        {
          line.append(',');
        }
        line.append(getUserFriendlyName(exceptionTypes[i], false));
      }
    }

    return line.toString();
  }



  /**
   * Retrieves a string representation of the provided field.
   *
   * @param  c                The class containing the constructor.
   * @param  f                The field to process.
   * @param  isExtensible     Indicates whether the class is marked with
   *                          the @Extensible annotation.
   * @param  isNotExtensible  Indicates whether the class is marked with
   *                          the @NotExtensible annotation.
   *
   * @return  A string representation of the provided constructor, or
   *          {@code null} if it should not be included in the output.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static String getDefinition(final Class<?> c, final Field f,
                                      final boolean isExtensible,
                                      final boolean isNotExtensible)
          throws Exception
  {
    if (! f.getDeclaringClass().equals(c))
    {
      return null;
    }

    boolean inPublicAPI = false;
    String visibility = null;
    int fieldModifiers = f.getModifiers();
    if (Modifier.isPublic(fieldModifiers))
    {
      inPublicAPI = true;
      visibility  = "public ";
    }
    else if ((! Modifier.isFinal(c.getModifiers())) &&
             Modifier.isProtected(fieldModifiers))
    {
      inPublicAPI = true;
      visibility  = "protected ";
    }

    if (! inPublicAPI)
    {
      return null;
    }

    StringBuilder line = new StringBuilder();
    if (isExtensible)
    {
      line.append("@Extensible ");
    }
    else if (isNotExtensible)
    {
      line.append("@NotExtensible ");
    }

    if (c.isAnnotation())
    {
      line.append("annotation ");
    }
    else if (c.isEnum())
    {
      line.append("enum ");
    }
    else if (c.isInterface())
    {
      line.append("interface ");
    }
    else
    {
      line.append("class ");
    }

    line.append(c.getName());
    line.append(" field ");
    line.append(visibility);
    if (Modifier.isStatic(fieldModifiers))
    {
      line.append("static ");
    }
    if (Modifier.isFinal(fieldModifiers))
    {
      line.append("final ");
    }
    line.append(getUserFriendlyName(f.getGenericType(), false));
    line.append(' ');
    line.append(f.getName());

    return line.toString();
  }



  /**
   * Retrieves a string representation of the provided method.
   *
   * @param  c                The class containing the constructor.
   * @param  m                The method to process.
   * @param  isExtensible     Indicates whether the class is marked with
   *                          the @Extensible annotation.
   * @param  isNotExtensible  Indicates whether the class is marked with
   *                          the @NotExtensible annotation.
   *
   * @return  A string representation of the provided constructor, or
   *          {@code null} if it should not be included in the output.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static String getDefinition(final Class<?> c, final Method m,
                                      final boolean isExtensible,
                                      final boolean isNotExtensible)
          throws Exception
  {
    if (! m.getDeclaringClass().equals(c))
    {
      return null;
    }

    boolean inPublicAPI = false;
    String visibility = null;
    int methodModifiers = m.getModifiers();
    if (Modifier.isPublic(methodModifiers))
    {
      inPublicAPI = true;
      visibility  = "public";
    }
    else if ((! Modifier.isFinal(c.getModifiers())) &&
             Modifier.isProtected(methodModifiers))
    {
      inPublicAPI = true;
      visibility  = "protected";
    }

    if (! inPublicAPI)
    {
      return null;
    }

    boolean isInternalUseOnlyMethod = false;
    for (Annotation a : m.getAnnotations())
    {
      if (a.annotationType().equals(InternalUseOnly.class))
      {
        isInternalUseOnlyMethod = true;
      }
    }

    if (isInternalUseOnlyMethod)
    {
      return null;
    }

    StringBuilder line = new StringBuilder();
    if (isExtensible)
    {
      line.append("@Extensible ");
    }
    else if (isNotExtensible)
    {
      line.append("@NotExtensible ");
    }

    if (c.isAnnotation())
    {
      line.append("annotation ");
    }
    else if (c.isEnum())
    {
      line.append("enum ");
    }
    else if (c.isInterface())
    {
      line.append("interface ");
    }
    else
    {
      line.append("class ");
    }

    line.append(c.getName());
    line.append(" method ");
    line.append(visibility);
    if (Modifier.isStatic(methodModifiers))
    {
      line.append(" static");
    }
    if (isExtensible)
    {
      if (Modifier.isAbstract(methodModifiers))
      {
        line.append(" abstract");
      }
      else if (Modifier.isFinal(methodModifiers))
      {
        line.append(" final");
      }
    }
    line.append(' ');
    line.append(getUserFriendlyName(m.getGenericReturnType(), false));
    line.append(' ');
    line.append(m.getName());
    line.append('(');

    Type[] paramTypes = m.getGenericParameterTypes();
    for (int i=0; i < paramTypes.length; i++)
    {
      if (i > 0)
      {
        line.append(',');
      }

      boolean varargs = (m.isVarArgs() && (i == (paramTypes.length - 1)));
      line.append(getUserFriendlyName(paramTypes[i], varargs));
    }
    line.append(')');

    Type[] exceptionTypes = m.getGenericExceptionTypes();
    if (exceptionTypes.length > 0)
    {
      line.append(" throws ");
      for (int i=0; i < exceptionTypes.length; i++)
      {
        if (i > 0)
        {
          line.append(',');
        }
        line.append(getUserFriendlyName(exceptionTypes[i], false));
      }
    }

    return line.toString();
  }



  /**
   * Retrieves a user-friendly name for the provided type.
   *
   * @param  t        The type for which to retrieve the user-friendly name.
   * @param  varargs  Indicates whether to use "..." instead of "[]" if it is an
   *                  array class.
   *
   * @return  The user-friendly name for the provided type.
   */
  private static String getUserFriendlyName(final Type t, final boolean varargs)
  {
    if (t instanceof ParameterizedType)
    {
      ParameterizedType pt = (ParameterizedType) t;
      StringBuilder buffer = new StringBuilder();
      buffer.append(getUserFriendlyName(pt.getRawType(), false));
      buffer.append('<');
      Type[] types = pt.getActualTypeArguments();
      for (int i=0; i < types.length; i++)
      {
        if (i > 0)
        {
          buffer.append(',');
        }
        buffer.append(getUserFriendlyName(types[i], false));
      }
      buffer.append('>');
      return buffer.toString();
    }
    else if (t instanceof GenericArrayType)
    {
      GenericArrayType gat = (GenericArrayType) t;
      if (varargs)
      {
        return getUserFriendlyName(gat.getGenericComponentType(), false) +
               "...";
      }
      else
      {
        return getUserFriendlyName(gat.getGenericComponentType(), false) + "[]";
      }
    }
    else if (t instanceof WildcardType)
    {
      WildcardType wt = (WildcardType) t;

      StringBuilder buffer = new StringBuilder();
      buffer.append('?');

      Type[] bounds = wt.getUpperBounds();
      if ((bounds != null) && (bounds.length > 0))
      {
        buffer.append(" extends ");
      }
      else
      {
        bounds = wt.getLowerBounds();
        if ((bounds != null) && (bounds.length > 0))
        {
          buffer.append(" super ");
        }
      }

      if (bounds != null)
      {
        for (int i=0; i < bounds.length; i++)
        {
          if (i > 0)
          {
            buffer.append(',');
          }
          buffer.append(getUserFriendlyName(bounds[i], false));
        }
      }

      return buffer.toString();
    }
    else if (t instanceof TypeVariable<?>)
    {
      TypeVariable<?> tv = (TypeVariable<?>) t;
      return tv.getName();
    }
    else if (t instanceof Class<?>)
    {
      return getUserFriendlyName((Class<?>) t, varargs);
    }
    else
    {
      return t.toString();
    }
  }



  /**
   * Retrieves a user-friendly name for the provided class.
   *
   * @param  c        The class for which to retrieve the user-friendly name.
   * @param  varargs  Indicates whether to use "..." instead of "[]" if it is an
   *                  array class.
   *
   * @return  The user-friendly name for the provided class.
   */
  private static String getUserFriendlyName(final Class<?> c,
                                            final boolean varargs)
  {
    if (c.isArray())
    {
      if (varargs)
      {
        return getUserFriendlyName(c.getComponentType(), false) + "...";
      }
      else
      {
        return getUserFriendlyName(c.getComponentType(), false) + "[]";
      }
    }
    else
    {
      return c.getName();
    }
  }



  /**
   * Retrieves a set of files with previous public API definitions.
   *
   * @return  A set of files with previous public API definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="publicAPIFiles")
  public Object[][] getPublicAPIFiles()
         throws Exception
  {
    File baseDir     = new File(System.getProperty("basedir"));
    File resourceDir = new File(baseDir, "resource");

    return new Object[][]
    {
      new Object[] { new File(resourceDir, "public-api-0.9.5.txt")  },
      new Object[] { new File(resourceDir, "public-api-0.9.6.txt")  },
      new Object[] { new File(resourceDir, "public-api-0.9.7.txt")  },
      new Object[] { new File(resourceDir, "public-api-0.9.8.txt")  },
      new Object[] { new File(resourceDir, "public-api-0.9.9.txt")  },
      new Object[] { new File(resourceDir, "public-api-0.9.10.txt")  },
      new Object[] { new File(resourceDir, "public-api-1.0.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-1.1.1.txt")  },
      new Object[] { new File(resourceDir, "public-api-1.1.2.txt")  },
      new Object[] { new File(resourceDir, "public-api-1.1.3.txt")  },
      new Object[] { new File(resourceDir, "public-api-1.1.4.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.0.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.0.1.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.1.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.2.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.3.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.3.1.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.3.2.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.3.3.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.3.4.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.3.5.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.3.6.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.3.7.txt")  },
      new Object[] { new File(resourceDir, "public-api-2.3.8.txt")  },
      new Object[] { new File(resourceDir, "public-api-3.0.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-3.1.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-3.1.1.txt")  },
      new Object[] { new File(resourceDir, "public-api-3.2.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-3.2.1.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.1.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.2.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.3.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.4.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.5.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.6.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.7.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.8.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.9.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.10.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.11.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.12.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.13.txt")  },
      new Object[] { new File(resourceDir, "public-api-4.0.14.txt")  },
      new Object[] { new File(resourceDir, "public-api-5.0.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-5.0.1.txt")  },
      new Object[] { new File(resourceDir, "public-api-5.1.0.txt")  },
      new Object[] { new File(resourceDir, "public-api-5.1.1.txt")  },
      new Object[] { new File(resourceDir, "public-api-5.1.2.txt")  },
      new Object[] { new File(resourceDir, "public-api-5.1.3.txt")  },
      new Object[] { new File(resourceDir, "public-api-5.1.4.txt")  }
    };
  }



  /**
   * Retrieves the fully-qualified names of all classes included in the SDK.
   *
   * @return  The fully-qualified names of all classes included in the SDK.
   *
   * @throws  Exception  If a problem occurs during processing.
   */
  @DataProvider(name="sdkClasses")
  public Object[][] getSDKClasses()
         throws Exception
  {
    File baseDir = new File(System.getProperty("basedir"));
    File buildDir = new File(baseDir, "build");
    File classesDir = new File(buildDir, "classes");

    ArrayList<Class<?>> classList = new ArrayList<Class<?>>();
    findClasses("", classesDir,  classList);

    Object[][] classes = new Object[classList.size()][1];
    for (int i=0; i < classes.length; i++)
    {
      classes[i][0] = classList.get(i);
    }

    return classes;
  }



  /**
   * Recursively identifies all classes in the provided directory.
   *
   * @param  p  The package name associated with the provided directory.
   * @param  d  The directory to be processed.
   * @param  l  The to which the classes should be added.
   *
   * @throws  Exception  If a problem occurs during processing.
   */
  private static void findClasses(final String p, final File d,
                                  final ArrayList<Class<?>> l)
          throws Exception
  {
    for (File f : d. listFiles())
    {
      if (f.isDirectory())
      {
        if (p.length() == 0)
        {
          findClasses(f.getName(), f, l);
        }
        else
        {
          findClasses(p + '.' + f.getName(), f, l);
        }
      }
      else if (f.getName().endsWith(".class") &&
               (! f.getName().contains("$")))
      {
        int dotPos = f.getName().lastIndexOf('.');
        String baseName = f.getName().substring(0, dotPos);
        String className = p + '.' + baseName;
        l.add(Class.forName(className));
      }
    }
  }
}
