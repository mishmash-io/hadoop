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
package org.apache.hadoop.http;

import java.io.IOException;
import java.io.PrintWriter;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.util.GenericsUtil;
import org.apache.hadoop.util.http.ServletUtil;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * A servlet implementation
 */
@InterfaceAudience.LimitedPrivate({"HDFS", "MapReduce"})
@InterfaceStability.Unstable
public class LogLevelServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    static final String MARKER = "<!-- OUTPUT -->";

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response
        ) throws ServletException, IOException {

      // Do the authorization
      if (!HttpServer2.hasAdministratorAccess(getServletContext(), request,
          response)) {
        return;
      }

      PrintWriter out = ServletUtil.initHTML(response, "Log Level");
      String logName = ServletUtil.getParameter(request, "log");
      String level = ServletUtil.getParameter(request, "level");

      if (logName != null) {
        out.println("<br /><hr /><h3>Results</h3>");
        out.println(MARKER
            + "Submitted Class Name: <b>" + logName + "</b><br />");

        org.slf4j.Logger log = LoggerFactory.getLogger(logName);
        out.println(MARKER
            + "Log Class: <b>" + log.getClass().getName() +"</b><br />");
        if (level != null) {
          out.println(MARKER + "Submitted Level: <b>" + level + "</b><br />");
        }

        if (GenericsUtil.isLog4jLogger(logName)) {
          process(Logger.getLogger(logName), level, out);
        } else {
          out.println("Sorry, setting log level is only supported for log4j loggers.<br />");
        }
      }

      out.println(FORMS);
      out.println(ServletUtil.HTML_TAIL);
    }

    static final String FORMS = "\n<br /><hr /><h3>Get / Set</h3>"
        + "\n<form>Class Name: <input type='text' size='50' name='log' /> "
        + "<input type='submit' value='Get Log Level' />"
        + "</form>"
        + "\n<form>Class Name: <input type='text' size='50' name='log' /> "
        + "Level: <input type='text' name='level' /> "
        + "<input type='submit' value='Set Log Level' />"
        + "</form>";

    private static void process(Logger log, String level,
        PrintWriter out) throws IOException {
      if (level != null) {
        if (!level.equalsIgnoreCase(Level.toLevel(level)
            .toString())) {
          out.println(MARKER + "Bad Level : <b>" + level + "</b><br />");
        } else {
          log.setLevel(Level.toLevel(level));
          out.println(MARKER + "Setting Level to " + level + " ...<br />");
        }
      }
      out.println(MARKER
          + "Effective Level: <b>" + log.getEffectiveLevel() + "</b><br />");
    }
}
