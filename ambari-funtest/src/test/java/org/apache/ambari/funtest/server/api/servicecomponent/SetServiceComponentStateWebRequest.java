/*
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

package org.apache.ambari.funtest.server.api.servicecomponent;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.ambari.funtest.server.AmbariHttpWebRequest;
import org.apache.ambari.funtest.server.ConnectionParams;
import org.apache.ambari.server.state.State;

public class SetServiceComponentStateWebRequest extends AmbariHttpWebRequest {
    private String clusterName;
    private String serviceName;
    private String componentName;
    private State componentState;
    private String requestContext;
    private static String pathFormat = "/api/v1/clusters/%s/services/%s";

    public SetServiceComponentStateWebRequest(ConnectionParams params, String clusterName, String serviceName,
                                              String componentName, State componentState, String requestContext) {
        super(params);
        this.clusterName = clusterName;
        this.serviceName = serviceName;
        this.componentName = componentName;
        this.componentState = componentState;
        this.requestContext = requestContext;
    }

    public String getClusterName() { return this.clusterName; }

    public String getServiceName() { return this.serviceName; }

    public State getComponentState() { return this.componentState; }

    public String getRequestContext() { return this.requestContext; }

    @Override
    public String getHttpMethod() {
        return "PUT";
    }

    /**
     * Get REST API path fragment for construction full URI.
     *
     * @return - REST API path
     */
    @Override
    protected String getApiPath() {
        return String.format(pathFormat, clusterName, serviceName, componentName);
    }

    /**
     * Constructs the request data.
     *
     * @return - Request data.
     */
    @Override
    protected String getRequestData() {
        /**
         * {
         * "RequestInfo" : {"context" : requestContext},
         * "Body" : {"ServiceComponentInfo" : {"state" : componentState}}
         * }
         */
        JsonObject jsonObject = new JsonObject();
        jsonObject.add("RequestInfo", createJsonObject("context", requestContext));
        jsonObject.add("Body", createJsonObject("ServiceComponentInfo", createJsonObject("state", componentState.toString())));
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }
}
