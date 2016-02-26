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

import Ember from 'ember';
import OperationModal from '../mixins/operation-modal';
import FileUploader from '../utils/file-uploader';

export default Ember.Component.extend(OperationModal, {
  modalEventBus: Ember.inject.service('modal-event-bus'),
  fileOperationService: Ember.inject.service('file-operation'),
  logger: Ember.inject.service('alert-messages'),
  tagName: "span",
  closeOnEscape: true,
  name: 'ctx-uploader',
  path: '',
  isUploading: false,
  uploadFileName: '',
  uploadPercent: '0%',
  uploadPercentStyle: Ember.computed('uploadPercent', function() {
    var style = 'width: ' + this.get('uploadPercent') + ';';
    return style.htmlSafe();
  }),
  didInitAttrs: function() {
    this.get('modalEventBus').registerModal("ctx-uploader");
  },
  willDestroyElement() {
    this.get('modalEventBus').resetModal("ctx-uploader");
  },
  setUploadPercent: function(percent) {
    var intValue = Math.round(percent);
    this.set('uploadPercent', `${intValue}%`);
  },

  setUploading: function(fileName) {
    this.set('uploadFileName', fileName);
    this.set('isUploading', true);
    this.set('closeOnEscape', false);
  },

  actions: {
    openModal : function() {
      this.get('modalEventBus').showModal('ctx-uploader');
    },
    didOpenModal: function() {
      this.set('isUploading', false);
      this.set('uploadFileName', '');
      this.set('closeOnEscape', true);
    },

    didCloseModal: function() {
      this.set('uploader');
    },

    fileLoaded: function(file) {
      var url = this.get('fileOperationService').getUploadUrl();
      var uploader = FileUploader.create({
        url: url
      });
      this.set('uploader', uploader);
      if(!Ember.isEmpty(file)) {
        uploader.upload(file, {path: this.get('path')});
        this.setUploading(file.name);
        uploader.on('progress', (e) => {
          this.setUploadPercent(e.percent);
        });
        uploader.on('didUpload', (e) => {
          this.send('close');
          this.sendAction('refreshAction');
        });
        uploader.on('didError', (jqXHR, textStatus, errorThrown) => {
          var error = Ember.$.parseJSON(jqXHR.responseText);
          this.get('logger').danger(`Failed to upload ${file.name} to ${this.get('path')}`, error);
          this.send('close');
          return false;
        });
      }

    },

    close: function() {
      if (!Ember.isNone(this.get('uploader'))) {
        console.log('cancelling the upload');
        this.get('uploader').abort();
      }
      this._super();
    }

  }
});

