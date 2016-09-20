/*jslint node: true, vars: true */

//
// Contains dispatchers for constructors and verifiers
//

const assert = require('assert');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const util = require('util');

var model = {};
model.utils = {};

//--------------------------------
// Constructors from YAML nodes
//--------------------------------

model.utils.YAML2Metadata = function YAML2Metadata(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));

  if (!yaml.type) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type missing from YAML format cannot dispatch:%j', yaml),
    });
  } else {
    switch (yaml.type) {
      case 'PrivacyAlgorithm':
        return require('./privacyAlgorithm').utils.YAML2PrivacyAlgorithm(yaml, props);
      default:
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format('ERROR unknown type missing from YAML format cannot dispatch:%j', yaml),
        });
    } // switch
  }
};

module.exports = {
  utils:        model.utils,
};
