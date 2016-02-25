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

var App = require('app');
require('mixins/wizard/assign_master_components');
var c;

describe('App.AssignMasterComponents', function () {
  var baseObject = Em.Object.extend(App.AssignMasterComponents);
  var data;

  beforeEach(function () {
    c = baseObject.create();
    c.set('content', {});

    var hosts = [];
    for(var i = 1; i <= 4; ++i) {
      hosts.push(App.Host.createRecord({
        'host_name': 'h' + i
      }));
    }
    c.set('hosts', hosts);

    data = {
      "resources": [
        {
          "recommendations": {
            "blueprint": {
              "host_groups": [
                {
                  "name": "host-group-1",
                  "components": [{"name": "c1"}, {"name": "c3"}, {"name": "c2"}]
                },
                {
                  "name": "host-group-2",
                  "components": [{"name": "c1"}, {"name": "c2"}]
                },
                {
                  "name": "host-group-3",
                  "components": [{"name": "c1"}]
                }
              ]
            },
            "blueprint_cluster_binding": {
              "host_groups": [
                {
                  "name": "host-group-1",
                  "hosts": [{"fqdn": "h1"}]
                },
                {
                  "name": "host-group-3",
                  "hosts": [{"fqdn": "h3"}]
                },
                {
                  "name": "host-group-2",
                  "hosts": [{"fqdn": "h2"}, {"fqdn": "h4"}]
                }
              ]
            }
          }
        }
      ]
    };
  });

  describe('#loadRecommendationsSuccessCallback', function () {

    it('should set recommendations', function() {
      c.loadRecommendationsSuccessCallback(data);
      expect(c.get('content.recommendations')).to.eq(data.resources[0].recommendations);
    });

    it('should set recommendedHostsForComponents', function() {
      c.loadRecommendationsSuccessCallback(data);
      var expected = {
        "c1": ["h1", "h2", "h4", "h3"],
        "c3": ["h1"],
        "c2": ["h1", "h2", "h4"]
      };

      expect(c.get('content.recommendedHostsForComponents')).to.deep.equal(expected);
    });
  });

  describe('#getHostForMaster', function () {

    var allMasters;

    beforeEach(function () {
      allMasters = [
        {
          "component_name": "c1",
          "selectedHost": "h1"
        },
        {
          "component_name": "c1",
          "selectedHost": "h2"
        },
        {
          "component_name": "c1",
          "selectedHost": "h3"
        },
        {
          "component_name": "c1",
          "selectedHost": "h4"
        },
        {
          "component_name": "c2",
          "selectedHost": "h1"
        },
        {
          "component_name": "c5",
          "selectedHost": "h1"
        }
      ];
    });

    it('should return the recommended host', function() {
      c.loadRecommendationsSuccessCallback(data);
      expect(c.getHostForMaster('c2', allMasters)).to.eq('h2');
    });

    it('should return the first available host from the list of existing hosts', function() {
      c.loadRecommendationsSuccessCallback(data);
      expect(c.getHostForMaster('c6', allMasters)).to.eq('h1');
    });

    it('should return the next available host from the list of existing hosts', function() {
      c.loadRecommendationsSuccessCallback(data);
      expect(c.getHostForMaster('c5', allMasters)).to.eq('h2');
    });

    it('should return false if the component is already on all hosts', function() {
      c.loadRecommendationsSuccessCallback(data);
      expect(c.getHostForMaster('c1', allMasters)).to.eq(false);
    });

  });
});