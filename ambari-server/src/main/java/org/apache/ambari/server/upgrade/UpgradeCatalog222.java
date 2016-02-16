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

package org.apache.ambari.server.upgrade;

import com.google.inject.Inject;
import com.google.inject.Injector;
import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.orm.dao.AlertDefinitionDAO;
import org.apache.ambari.server.orm.dao.DaoUtils;
import org.apache.ambari.server.orm.entities.AlertDefinitionEntity;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.Clusters;
import org.apache.ambari.server.state.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Upgrade catalog for version 2.2.2.
 */
public class UpgradeCatalog222 extends AbstractUpgradeCatalog {

  @Inject
  DaoUtils daoUtils;

  /**
   * Logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(UpgradeCatalog222.class);
  private static final String AMS_SITE = "ams-site";
  private static final String HOST_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER =
    "timeline.metrics.host.aggregator.daily.checkpointCutOffMultiplier";
  private static final String CLUSTER_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER =
    "timeline.metrics.cluster.aggregator.daily.checkpointCutOffMultiplier";
  private static final String TIMELINE_METRICS_SERVICE_WATCHER_DISBALED = "timeline.metrics.service.watcher.disabled";
  private static final String AMS_MODE = "timeline.metrics.service.operation.mode";
  public static final String PRECISION_TABLE_TTL = "timeline.metrics.host.aggregator.ttl";
  public static final String HOST_MINUTE_TABLE_TTL = "timeline.metrics.host.aggregator.minute.ttl";
  public static final String HOST_HOUR_TABLE_TTL = "timeline.metrics.host.aggregator.hourly.ttl";
  public static final String HOST_DAILY_TABLE_TTL = "timeline.metrics.host.aggregator.daily.ttl";
  public static final String CLUSTER_SECOND_TABLE_TTL = "timeline.metrics.cluster.aggregator.second.ttl";
  public static final String CLUSTER_MINUTE_TABLE_TTL = "timeline.metrics.cluster.aggregator.minute.ttl";
  public static final String CLUSTER_HOUR_TABLE_TTL = "timeline.metrics.cluster.aggregator.hourly.ttl";
  public static final String CLUSTER_DAILY_TABLE_TTL = "timeline.metrics.cluster.aggregator.daily.ttl";


  // ----- Constructors ------------------------------------------------------

  /**
   * Don't forget to register new UpgradeCatalogs in {@link org.apache.ambari.server.upgrade.SchemaUpgradeHelper.UpgradeHelperModule#configure()}
   *
   * @param injector Guice injector to track dependencies and uses bindings to inject them.
   */
  @Inject
  public UpgradeCatalog222(Injector injector) {
    super(injector);
    this.injector = injector;
  }

  // ----- UpgradeCatalog ----------------------------------------------------

  /**
   * {@inheritDoc}
   */
  @Override
  public String getTargetVersion() {
    return "2.2.2";
  }

  // ----- AbstractUpgradeCatalog --------------------------------------------

  /**
   * {@inheritDoc}
   */
  @Override
  public String getSourceVersion() {
    return "2.2.1";
  }


  @Override
  protected void executeDDLUpdates() throws AmbariException, SQLException {
    //To change body of implemented methods use File | Settings | File Templates.
  }

  @Override
  protected void executePreDMLUpdates() throws AmbariException, SQLException {
    //To change body of implemented methods use File | Settings | File Templates.
  }

  @Override
  protected void executeDMLUpdates() throws AmbariException, SQLException {
    addNewConfigurationsFromXml();
    updateAlerts();
    updateStormConfigs();
    updateAMSConfigs();
  }

  protected void updateStormConfigs() throws  AmbariException {
    AmbariManagementController ambariManagementController = injector.getInstance(AmbariManagementController.class);
    Map<String, Cluster> clusterMap = getCheckedClusterMap(ambariManagementController.getClusters());

    for (final Cluster cluster : clusterMap.values()) {
      if (cluster.getDesiredConfigByType("storm-site") != null && cluster.getDesiredConfigByType("storm-site").getProperties().containsKey("storm.zookeeper.superACL")
              && cluster.getDesiredConfigByType("storm-site").getProperties().get("storm.zookeeper.superACL").equals("sasl:{{storm_base_jaas_principal}}")) {
        Map<String, String> newStormProps = new HashMap<String, String>();
        newStormProps.put("storm.zookeeper.superACL", "sasl:{{storm_bare_jaas_principal}}");
        updateConfigurationPropertiesForCluster(cluster, "storm-site", newStormProps, true, false);
      }
    }
  }

  protected void updateAlerts() {
    LOG.info("Updating alert definitions.");
    AmbariManagementController ambariManagementController = injector.getInstance(AmbariManagementController.class);
    AlertDefinitionDAO alertDefinitionDAO = injector.getInstance(AlertDefinitionDAO.class);
    Clusters clusters = ambariManagementController.getClusters();

    Map<String, Cluster> clusterMap = getCheckedClusterMap(clusters);
    for (final Cluster cluster : clusterMap.values()) {
      long clusterID = cluster.getClusterId();

      final AlertDefinitionEntity regionserverHealthSummaryDefinitionEntity = alertDefinitionDAO.findByName(
              clusterID, "regionservers_health_summary");

      if (regionserverHealthSummaryDefinitionEntity != null) {
        alertDefinitionDAO.remove(regionserverHealthSummaryDefinitionEntity);
      }

    }


  }

  protected void updateAMSConfigs() throws AmbariException {
    AmbariManagementController ambariManagementController = injector.getInstance(AmbariManagementController.class);
    Clusters clusters = ambariManagementController.getClusters();

    if (clusters != null) {
      Map<String, Cluster> clusterMap = clusters.getClusters();

      if (clusterMap != null && !clusterMap.isEmpty()) {
        for (final Cluster cluster : clusterMap.values()) {

          Config amsSite = cluster.getDesiredConfigByType(AMS_SITE);
          if (amsSite != null) {
            Map<String, String> amsSiteProperties = amsSite.getProperties();
            Map<String, String> newProperties = new HashMap<>();

            if (amsSiteProperties.containsKey(HOST_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER) &&
              amsSiteProperties.get(HOST_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER).equals("1")) {

              LOG.info("Setting value of " + HOST_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER + " : 2");
              newProperties.put(HOST_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER, String.valueOf(2));

            }

            if (amsSiteProperties.containsKey(CLUSTER_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER) &&
              amsSiteProperties.get(CLUSTER_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER).equals("1")) {

              LOG.info("Setting value of " + CLUSTER_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER + " : 2");
              newProperties.put(CLUSTER_AGGREGATOR_DAILY_CHECKPOINTCUTOFFMULTIPIER, String.valueOf(2));

            }

            if (!amsSiteProperties.containsKey(TIMELINE_METRICS_SERVICE_WATCHER_DISBALED)) {
              LOG.info("Add config  " + TIMELINE_METRICS_SERVICE_WATCHER_DISBALED + " = false");
              newProperties.put(TIMELINE_METRICS_SERVICE_WATCHER_DISBALED, String.valueOf(false));
            }

            boolean isDistributed = false;
            if ("distributed".equals(amsSite.getProperties().get(AMS_MODE))) {
              isDistributed = true;
            }

            if (amsSiteProperties.containsKey(PRECISION_TABLE_TTL)) {
              String oldTtl = amsSiteProperties.get(PRECISION_TABLE_TTL);
              String newTtl = convertToDaysIfInSeconds(oldTtl);
              if (isDistributed) {
                if ("86400".equals(oldTtl)) {
                  newTtl = "7.0"; // 7 days
                }
              }
              newProperties.put(PRECISION_TABLE_TTL, newTtl);
              LOG.info("Setting value of " + PRECISION_TABLE_TTL + " : " + newTtl);
            }

            if (amsSiteProperties.containsKey(HOST_MINUTE_TABLE_TTL)) {
              String oldTtl = amsSiteProperties.get(HOST_MINUTE_TABLE_TTL);
              String newTtl = convertToDaysIfInSeconds(oldTtl);
              newProperties.put(HOST_MINUTE_TABLE_TTL, newTtl);
              LOG.info("Setting value of " + HOST_MINUTE_TABLE_TTL + " : " + newTtl);
            }

            if (amsSiteProperties.containsKey(HOST_MINUTE_TABLE_TTL)) {
              String oldTtl = amsSiteProperties.get(HOST_MINUTE_TABLE_TTL);
              String newTtl = convertToDaysIfInSeconds(oldTtl);
              newProperties.put(HOST_MINUTE_TABLE_TTL, newTtl);
              LOG.info("Setting value of " + HOST_MINUTE_TABLE_TTL + " : " + newTtl);
            }

            if (amsSiteProperties.containsKey(HOST_HOUR_TABLE_TTL)) {
              String oldTtl = amsSiteProperties.get(HOST_HOUR_TABLE_TTL);
              String newTtl = convertToDaysIfInSeconds(oldTtl);
              newProperties.put(HOST_HOUR_TABLE_TTL, newTtl);
              LOG.info("Setting value of " + HOST_HOUR_TABLE_TTL + " : " + newTtl);
            }

            if (amsSiteProperties.containsKey(HOST_DAILY_TABLE_TTL)) {
              String oldTtl = amsSiteProperties.get(HOST_DAILY_TABLE_TTL);
              String newTtl = convertToDaysIfInSeconds(oldTtl);
              newProperties.put(HOST_DAILY_TABLE_TTL, newTtl);
              LOG.info("Setting value of " + HOST_DAILY_TABLE_TTL + " : " + newTtl);
            }

            if (amsSiteProperties.containsKey(CLUSTER_SECOND_TABLE_TTL)) {
              String oldTtl = amsSiteProperties.get(CLUSTER_SECOND_TABLE_TTL);
              String newTtl = convertToDaysIfInSeconds(oldTtl);

              if ("2592000".equals(oldTtl)) {
                newTtl = "7.0"; // 7 days
              }

              newProperties.put(CLUSTER_SECOND_TABLE_TTL, newTtl);
              LOG.info("Setting value of " + CLUSTER_SECOND_TABLE_TTL + " : " + newTtl);
            }

            if (amsSiteProperties.containsKey(CLUSTER_MINUTE_TABLE_TTL)) {
              String oldTtl = amsSiteProperties.get(CLUSTER_MINUTE_TABLE_TTL);
              String newTtl = convertToDaysIfInSeconds(oldTtl);

              if ("7776000".equals(oldTtl)) {
                newTtl = "30.0"; // 30 days
              }

              newProperties.put(CLUSTER_MINUTE_TABLE_TTL, newTtl);
              LOG.info("Setting value of " + CLUSTER_MINUTE_TABLE_TTL + " : " + newTtl);
            }

            if (amsSiteProperties.containsKey(CLUSTER_HOUR_TABLE_TTL)) {
              String oldTtl = amsSiteProperties.get(CLUSTER_HOUR_TABLE_TTL);
              String newTtl = convertToDaysIfInSeconds(oldTtl);
              newProperties.put(CLUSTER_HOUR_TABLE_TTL, newTtl);
              LOG.info("Setting value of " + CLUSTER_HOUR_TABLE_TTL + " : " + newTtl);
            }

            if (amsSiteProperties.containsKey(CLUSTER_DAILY_TABLE_TTL)) {
              String oldTtl = amsSiteProperties.get(CLUSTER_DAILY_TABLE_TTL);
              String newTtl = convertToDaysIfInSeconds(oldTtl);
              newProperties.put(CLUSTER_DAILY_TABLE_TTL, newTtl);
              LOG.info("Setting value of " + CLUSTER_DAILY_TABLE_TTL + " : " + newTtl);
            }

            updateConfigurationPropertiesForCluster(cluster, AMS_SITE, newProperties, true, true);
          }

        }
      }
    }
  }

  private String convertToDaysIfInSeconds(String secondsString) {

    int seconds = Integer.valueOf(secondsString);
    double days = 0.0;

    if (seconds >= 86400) {
      days += TimeUnit.SECONDS.toDays(seconds);
    }

    days += ((float)seconds % 86400.0) / 86400.0;
    days = Math.round(days * 100.0)/100.0;

    return String.valueOf(days);
  }

}
