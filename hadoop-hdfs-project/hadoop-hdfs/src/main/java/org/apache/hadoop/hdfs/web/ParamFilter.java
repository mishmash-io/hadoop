/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hdfs.web;

import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.URI;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.NameBinding;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;

import org.apache.hadoop.util.StringUtils;

/**
 * A filter to change parameter names to lower cases
 * so that parameter names are considered as case insensitive.
 */
@Provider
@ParamFilter.LowerCaseParams
public class ParamFilter implements ContainerRequestFilter {
  @NameBinding
  @Target({ElementType.TYPE, ElementType.METHOD})
  @Retention(value=RetentionPolicy.RUNTIME)
  public @interface LowerCaseParams {
      
  }

  /** Do the strings contain upper case letters? */
  static boolean containsUpperCase(final Iterable<String> strings) {
    for(String s : strings) {
      for(int i = 0; i < s.length(); i++) {
        if (Character.isUpperCase(s.charAt(i))) {
          return true;
        }
      }
    }
    return false;
  }

  /** Rebuild the URI query with lower case parameter names. */
  private static URI rebuildQuery(final URI uri,
      final MultivaluedMap<String, String> parameters) {
    UriBuilder b = UriBuilder.fromUri(uri).replaceQuery("");
    for(Map.Entry<String, List<String>> e : parameters.entrySet()) {
      final String key = StringUtils.toLowerCase(e.getKey());
      for(String v : e.getValue()) {
        b = b.queryParam(key, v);
      }
    }
    return b.build();
  }

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    final UriInfo uriInfo = requestContext.getUriInfo();
    final MultivaluedMap<String, String> parameters = uriInfo.getQueryParameters();
    if (containsUpperCase(parameters.keySet())) {
      //rebuild URI
      final URI lower = rebuildQuery(uriInfo.getRequestUri(), parameters);
      requestContext.setRequestUri(uriInfo.getBaseUri(), lower);
    }
  }
}