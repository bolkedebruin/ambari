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
package org.apache.ambari.server.checks;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.persist.PersistService;
import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.api.services.AmbariMetaInfo;
import org.apache.ambari.server.controller.ControllerModule;
import org.apache.ambari.server.orm.DBAccessor;
import org.apache.ambari.server.state.ServiceInfo;
import org.apache.ambari.server.utils.EventBusSynchronizer;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/*
* Class for database validation.
* Here we will check configs, services, components and etc.
*/
public class CheckDatabaseHelper {
  private static final Logger LOG = LoggerFactory.getLogger
          (CheckDatabaseHelper.class);

  private static final String AUTHENTICATED_USER_NAME = "ambari-check-database";

  private PersistService persistService;
  private DBAccessor dbAccessor;
  private Connection connection;
  private AmbariMetaInfo ambariMetaInfo;
  private Injector injector;

  @Inject
  public CheckDatabaseHelper(DBAccessor dbAccessor,
                             Injector injector,
                             PersistService persistService) {
    this.dbAccessor = dbAccessor;
    this.injector = injector;
    this.persistService = persistService;
  }

  /**
   * Extension of main controller module
   */
  public static class CheckHelperModule extends ControllerModule {

    public CheckHelperModule() throws Exception {
    }

    @Override
    protected void configure() {
      super.configure();
      EventBusSynchronizer.synchronizeAmbariEventPublisher(binder());
    }
  }

  /*
  * init method to create connection
  * */
  protected void init() {
    connection = dbAccessor.getConnection();
    ambariMetaInfo = injector.getInstance(AmbariMetaInfo.class);
  }

  /*
  * method to close connection
  * */
  private void closeConnection() {
    try {
      connection.close();
    } catch (SQLException e) {
      LOG.error("Exception occurred during connection close procedure: ", e);
    }
  }

  public void startPersistenceService() {
    persistService.start();
  }

  public void stopPersistenceService() {
    persistService.stop();
  }

  /*
  * This method checks if all configurations that we have in clusterconfig table
  * have at least one mapping in clusterconfigmapping table. If we found not mapped config
  * then we are showing warning message for user.
  * */
  protected void checkForNotMappedConfigsToCluster() {
    String GET_NOT_MAPPED_CONFIGS_QUERY = "select type_name from clusterconfig where type_name not in (select type_name from clusterconfigmapping)";
    Set<String> nonSelectedConfigs = new HashSet<>();
    ResultSet rs = null;
    try {
      Statement statement = connection.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE);
      rs = statement.executeQuery(GET_NOT_MAPPED_CONFIGS_QUERY);
      if (rs != null) {
        while (rs.next()) {
          nonSelectedConfigs.add(rs.getString("type_name"));
        }
      }
      if (!nonSelectedConfigs.isEmpty()) {
        LOG.warn("You have config(s) that is(are) not mapped to any cluster: " + StringUtils.join(nonSelectedConfigs, ","));
      }
    } catch (SQLException e) {
      LOG.error("Exception occurred during check for not mapped configs to cluster procedure: ", e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException e) {
          LOG.error("Exception occurred during result set closing procedure: ", e);
        }
      }
    }
  }

  /*
  * This method checks if any config type in clusterconfigmapping table, has
  * more than one versions selected. If config version is selected(in selected column = 1),
  * it means that this version of config is actual. So, if any config type has more
  * than one selected version it's a bug and we are showing error message for user.
  * */
  protected void checkForConfigsSelectedMoreThanOnce() {
    String GET_CONFIGS_SELECTED_MORE_THAN_ONCE_QUERY = "select c.cluster_name,type_name from clusterconfigmapping ccm " +
            "join clusters c on ccm.cluster_id=c.cluster_id " +
            "group by c.cluster_name,type_name " +
            "having sum(selected) > 1";
    Multimap<String, String> configsSelectedMoreThanOnce = HashMultimap.create();
    ResultSet rs = null;
    try {
      Statement statement = connection.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE);
      rs = statement.executeQuery(GET_CONFIGS_SELECTED_MORE_THAN_ONCE_QUERY);
      if (rs != null) {
        while (rs.next()) {
          configsSelectedMoreThanOnce.put(rs.getString("cluster_name"), rs.getString("type_name"));
        }
      }
      for (String clusterName : configsSelectedMoreThanOnce.keySet()) {
        LOG.error(String.format("You have config(s), in cluster %s, that is(are) selected more than once in clusterconfigmapping: %s",
                clusterName ,StringUtils.join(configsSelectedMoreThanOnce.get(clusterName), ",")));
      }
    } catch (SQLException e) {
      LOG.error("Exception occurred during check for config selected more than ones procedure: ", e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException e) {
          LOG.error("Exception occurred during result set closing procedure: ", e);
        }
      }
    }
  }

  /*
  * This method checks if all hosts from hosts table
  * has related host state info in hoststate table.
  * If not then we are showing error.
  * */
  protected void checkForHostsWithoutState() {
    String GET_HOSTS_WITHOUT_STATUS_QUERY = "select host_name from hosts where host_id not in (select host_id from hoststate)";
    Set<String> hostsWithoutStatus = new HashSet<>();
    ResultSet rs = null;
    try {
      Statement statement = connection.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE);
      rs = statement.executeQuery(GET_HOSTS_WITHOUT_STATUS_QUERY);
      if (rs != null) {
        while (rs.next()) {
          hostsWithoutStatus.add(rs.getString("host_name"));
        }
      }

      if (!hostsWithoutStatus.isEmpty()) {
        LOG.error("You have host(s) without status: " + StringUtils.join(hostsWithoutStatus, ","));
      }
    } catch (SQLException e) {
      LOG.error("Exception occurred during check for host without state procedure: ", e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException e) {
          LOG.error("Exception occurred during result set closing procedure: ", e);
        }
      }
    }
  }

  /*
  * This method checks if count of host component states equals count
  * of desired host component states. According to ambari logic these
  * two tables should have the same count of rows. If not then we are
  * showing error for user.
  * */
  protected void checkHostComponentStatesCountEqualsHostComponentsDesiredStates() {
    String GET_HOST_COMPONENT_STATE_COUNT_QUERY = "select count(*) from hostcomponentstate";
    String GET_HOST_COMPONENT_DESIRED_STATE_COUNT_QUERY = "select count(*) from hostcomponentdesiredstate";
    String GET_MERGED_TABLE_ROW_COUNT_QUERY = "select count(*) FROM hostcomponentstate hcs " +
            "JOIN hostcomponentdesiredstate hcds ON hcs.service_name = hcds.service_name AND hcs.component_name = hcds.component_name AND hcs.host_id = hcds.host_id";
    int hostComponentStateCount = 0;
    int hostComponentDesiredStateCount = 0;
    int mergedCount = 0;
    ResultSet rs = null;
    try {
      Statement statement = connection.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE);

      rs = statement.executeQuery(GET_HOST_COMPONENT_STATE_COUNT_QUERY);
      if (rs != null) {
        while (rs.next()) {
          hostComponentStateCount = rs.getInt(1);
        }
      }

      rs = statement.executeQuery(GET_HOST_COMPONENT_DESIRED_STATE_COUNT_QUERY);
      if (rs != null) {
        while (rs.next()) {
          hostComponentDesiredStateCount = rs.getInt(1);
        }
      }

      rs = statement.executeQuery(GET_MERGED_TABLE_ROW_COUNT_QUERY);
      if (rs != null) {
        while (rs.next()) {
          mergedCount = rs.getInt(1);
        }
      }

      if (hostComponentStateCount != hostComponentDesiredStateCount || hostComponentStateCount != mergedCount) {
        LOG.error("Your host component state count not equals host component desired state count!");
      }

    } catch (SQLException e) {
      LOG.error("Exception occurred during check for same count of host component states and host component desired states: ", e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException e) {
          LOG.error("Exception occurred during result set closing procedure: ", e);
        }
      }
    }

  }


  /*
  * This method checks several potential problems for services:
  * 1) Check if we have services in cluster which doesn't have service config id(not available in serviceconfig table).
  * 2) Check if service has no mapped configs to it's service config id.
  * 3) Check if service has all required configs mapped to it.
  * 4) Check if service has config which is not selected(has no actual config version) in clusterconfigmapping table.
  * If any issue was discovered, we are showing error message for user.
  * */
  protected void checkServiceConfigs()  {
    String GET_SERVICES_WITHOUT_CONFIGS_QUERY = "select service_name from clusterservices where service_name not in (select service_name from serviceconfig where group_id is null)";
    String GET_SERVICE_CONFIG_WITHOUT_MAPPING_QUERY = "select service_name from serviceconfig where service_config_id not in (select service_config_id from serviceconfigmapping) and group_id is null";
    String GET_STACK_NAME_VERSION_QUERY = "select s.stack_name, s.stack_version from clusters c join stack s on c.desired_stack_id = s.stack_id";
    String GET_SERVICES_WITH_CONFIGS_QUERY = "select cs.service_name, type_name, sc.version from clusterservices cs " +
            "join serviceconfig sc on cs.service_name=sc.service_name " +
            "join serviceconfigmapping scm on sc.service_config_id=scm.service_config_id " +
            "join clusterconfig cc on scm.config_id=cc.config_id " +
            "where sc.group_id is null " +
            "group by cs.service_name, type_name, sc.version";
    String GET_NOT_SELECTED_SERVICE_CONFIGS_QUERY = "select cs.service_name,cc.type_name from clusterservices cs " +
            "join serviceconfig sc on cs.service_name=sc.service_name " +
            "join serviceconfigmapping scm on sc.service_config_id=scm.service_config_id " +
            "join clusterconfig cc on scm.config_id=cc.config_id " +
            "join clusterconfigmapping ccm on cc.type_name=ccm.type_name and cc.version_tag=ccm.version_tag " +
            "where sc.group_id is null and sc.service_config_id = (select max(service_config_id) from serviceconfig sc2 where sc2.service_name=sc.service_name) " +
            "group by cs.service_name,cc.type_name " +
            "having sum(ccm.selected) < 1";
    String stackName = null, stackVersion = null;
    Set<String> servicesWithoutConfigs = new HashSet<>();
    Set<String> servicesWithoutMappedConfigs = new HashSet<>();
    Map<String, List<String>> notSelectedServiceConfigs = new HashMap<>();
    ResultSet rs = null;

    try {
      Statement statement = connection.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE);

      rs = statement.executeQuery(GET_SERVICES_WITHOUT_CONFIGS_QUERY);
      if (rs != null) {
        while (rs.next()) {
          servicesWithoutConfigs.add(rs.getString("service_name"));
        }
      }

      if (!servicesWithoutConfigs.isEmpty()) {
        LOG.error("You have services without configs at all: " + StringUtils.join(servicesWithoutConfigs, ","));
      }

      rs = statement.executeQuery(GET_SERVICE_CONFIG_WITHOUT_MAPPING_QUERY);
      if (rs != null) {
        while (rs.next()) {
          servicesWithoutMappedConfigs.add(rs.getString("service_name"));
        }
      }

      if (!servicesWithoutMappedConfigs.isEmpty()) {
        LOG.error("You have services without mapped configs: " + StringUtils.join(servicesWithoutMappedConfigs, ","));
      }

      rs = statement.executeQuery(GET_STACK_NAME_VERSION_QUERY);
      if (rs != null) {
        while (rs.next()) {
          stackName = rs.getString("stack_name");
          stackVersion = rs.getString("stack_version");
        }
      }

      if (stackName != null && stackVersion != null) {
        Set<String> serviceNames = new HashSet<>();
        Map<Integer, Multimap<String, String>> dbServiceVersionConfigs = new HashMap<>();
        Multimap<String, String> stackServiceConfigs = HashMultimap.create();

        rs = statement.executeQuery(GET_SERVICES_WITH_CONFIGS_QUERY);
        if (rs != null) {
          String serviceName = null, configType = null;
          Integer serviceVersion = null;
          while (rs.next()) {
            serviceName = rs.getString("service_name");
            configType = rs.getString("type_name");
            serviceVersion = rs.getInt("version");

            serviceNames.add(serviceName);

            if (dbServiceVersionConfigs.get(serviceVersion) == null) {
              Multimap<String, String> dbServiceConfigs = HashMultimap.create();
              dbServiceConfigs.put(serviceName, configType);
              dbServiceVersionConfigs.put(serviceVersion, dbServiceConfigs);
            } else {
              dbServiceVersionConfigs.get(serviceVersion).put(serviceName, configType);
            }
          }
        }


        Map<String, ServiceInfo> serviceInfoMap = ambariMetaInfo.getServices(stackName, stackVersion);
        for (String serviceName : serviceNames) {
          ServiceInfo serviceInfo = serviceInfoMap.get(serviceName);
          Set<String> configTypes = serviceInfo.getConfigTypeAttributes().keySet();
          for (String configType : configTypes) {
            stackServiceConfigs.put(serviceName, configType);
          }
        }

        for (Integer serviceVersion : dbServiceVersionConfigs.keySet()) {
          Multimap<String, String> dbServiceConfigs = dbServiceVersionConfigs.get(serviceVersion);
          for (String serviceName : dbServiceConfigs.keySet()) {
            Collection<String> serviceConfigsFromStack = stackServiceConfigs.get(serviceName);
            Collection<String> serviceConfigsFromDB = dbServiceConfigs.get(serviceName);
            if (serviceConfigsFromDB != null && serviceConfigsFromStack != null) {
              serviceConfigsFromStack.removeAll(serviceConfigsFromDB);
              if (!serviceConfigsFromStack.isEmpty()) {
                LOG.error(String.format("Required config(s): %s is(are) not available for service %s with service config version %s",
                        StringUtils.join(serviceConfigsFromStack, ","), serviceName, Integer.toString(serviceVersion)));
              }
            }
          }
        }
      }

      rs = statement.executeQuery(GET_NOT_SELECTED_SERVICE_CONFIGS_QUERY);
      if (rs != null) {
        String serviceName = null, configType = null;
        while (rs.next()) {
          serviceName = rs.getString("service_name");
          configType = rs.getString("type_name");

          if (notSelectedServiceConfigs.get(serviceName) != null) {
            notSelectedServiceConfigs.get(serviceName).add(configType);
          } else {
            List<String> configTypes = new ArrayList<>();
            configTypes.add(configType);
            notSelectedServiceConfigs.put(serviceName, configTypes);
          }
        }
      }

      for (String serviceName : notSelectedServiceConfigs.keySet()) {
        LOG.error(String.format("You have non selected configs: %s for service %s.", StringUtils.join(notSelectedServiceConfigs.get(serviceName), ","), serviceName));
      }
    } catch (SQLException e) {
      LOG.error("Exception occurred during complex service check procedure: ", e);
    } catch (AmbariException e) {
      LOG.error("Exception occurred during complex service check procedure: ", e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException e) {
          LOG.error("Exception occurred during result set closing procedure: ", e);
        }
      }
    }

  }

  /*
  * Main method from which we are calling all checks
  * */
  public static void main(String[] args) throws Exception {
    CheckDatabaseHelper checkDatabaseHelper = null;
    try {
      LOG.info("******************************* Check database started *******************************");

      Injector injector = Guice.createInjector(new CheckHelperModule());
      checkDatabaseHelper = injector.getInstance(CheckDatabaseHelper.class);

      checkDatabaseHelper.startPersistenceService();

      checkDatabaseHelper.init();

      checkDatabaseHelper.checkForNotMappedConfigsToCluster();

      checkDatabaseHelper.checkForConfigsSelectedMoreThanOnce();

      checkDatabaseHelper.checkForHostsWithoutState();

      checkDatabaseHelper.checkHostComponentStatesCountEqualsHostComponentsDesiredStates();

      checkDatabaseHelper.checkServiceConfigs();

      checkDatabaseHelper.stopPersistenceService();

      LOG.info("******************************* Check database completed *******************************");
    } catch (Throwable e) {
      if (e instanceof AmbariException) {
        LOG.error("Exception occurred during database check:", e);
        throw (AmbariException)e;
      }else{
        LOG.error("Unexpected error, database check failed", e);
        throw new Exception("Unexpected error, database check failed", e);
      }
    } finally {
      if (checkDatabaseHelper != null) {
        checkDatabaseHelper.closeConnection();
      }
    }
  }
}
