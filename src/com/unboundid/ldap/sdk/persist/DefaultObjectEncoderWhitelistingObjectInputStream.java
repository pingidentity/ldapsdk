/*
 * Copyright 2026 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2026 Ping Identity Corporation
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
 * Copyright (C) 2026 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.persist;



import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.util.NotNull;
import com.unboundid.util.PropertyManager;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;



/**
 * This class provides an implementation of an {@link ObjectInputStream} that
 * can only be used to deserialize a specified class (or its subclasses or
 * implementers of its interface).  Note that it should only be used to read a
 * single object.
 */
final class DefaultObjectEncoderWhitelistingObjectInputStream
      extends ObjectInputStream
{
  /**
   * The name of a Java system property that can be used to indicate whether to
   * disable the filter used when attempting to deserialize a serialized object
   * stored in the server.
   */
  @NotNull static final String PROPERTY_DISABLE_DESERIALIZATION_FILTER =
       DefaultObjectEncoderWhitelistingObjectInputStream.class.getName() +
            ".disableDeserializationFilter";



  // A flag used to indicate whether we have started to read the top-level
  // obejct in the stream.
  @NotNull private final AtomicBoolean startedReadingTopLevelObject;

  // The class that is allowed to be deserialized.
  @NotNull private final Class<?> allowedClass;



  /**
   * Creates a new whitelisting object input stream that will wrap the provided
   * stream and only allow reading objects of the specified type.
   *
   * @param  wrappedStream  The input stream from which the target object
   *                        should be read.
   * @param  allowedClass   The only class that is allowed to be read (although
   *                        subclasses or implementers will also be allowed).
   *
   * @throws  IOException  If a problem occurs while attempting to wrap the
   *                       provided input stream.
   */
  DefaultObjectEncoderWhitelistingObjectInputStream(
       @NotNull final InputStream wrappedStream,
       @NotNull final Class<?> allowedClass)
       throws IOException
  {
    super(wrappedStream);

    this.allowedClass = allowedClass;

    startedReadingTopLevelObject = new AtomicBoolean(false);
  }



  /**
   * Loads the class indicated in the provided description.
   *
   * @param  desc  The descriptor for the class of an object to be loaded.
   *
   * @return  The resolved class.
   *
   * @throws  IOException  If a problem occurs while attempting to read the
   *                       specified class.
   *
   * @throws  ClassNotFoundException  If the specified class cannot be found by
   *                                  the class loader.
   *
   * @throws  SecurityException  If the class is not allwoed to be read by this
   *                             stream.
   */
  @Override()
  @NotNull()
  protected Class<?> resolveClass(@NotNull final ObjectStreamClass desc)
            throws IOException, ClassNotFoundException
  {

    final Class<?> resolvedClass = super.resolveClass(desc);

    if (startedReadingTopLevelObject.compareAndSet(false, true) &&
         (! PropertyManager.getBoolean(PROPERTY_DISABLE_DESERIALIZATION_FILTER,
              false)))
    {
      if (! allowedClass.isAssignableFrom(resolvedClass))
      {
        throw new SecurityException(
             ERR_WHITELISTING_OBJECT_STREAM_DISALLOWED_CLASS.get(
                  allowedClass.getName(), resolvedClass.getName()));
      }
    }

    return resolvedClass;
  }
}
