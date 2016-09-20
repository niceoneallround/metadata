/*jslint node: true, vars: true */

//
// Contains constructors and verifiers for privacy algorithms, privacy steps
// and privacy actions.
//

const assert = require('assert');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

var model = {};
model.utils = {};

//--------------------------------
// Constructors from YAML nodes
//--------------------------------

/*
The Privacy Algorithm is part of the resources token it has the following
format. Note resoruce tag is not part of the PA, just shown for example

resources:
  - id: // the
    type: PrivacyAlgorithm  // needed as many types of resources
    privacy_step:
      - id:
        privacy_action:
        - id:
*/

//
// convert a YAML node into a Privacy Algorithm JSON-LD node. If a validation
// error returns an Error otherwise returns the PA node.
// *yaml - the JSON version of the yaml node
//
model.utils.YAML2PrivacyAlgorithm = function YAML2PrivacyAlgorithm(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  console.log(yaml);
  let node = {};

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML privacy algorithm format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyAlgorithmId(props.hostname, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.Resource, PN_T.PrivacyAlgorithm];

  if (yaml.privacy_step) {
    node[PN_P.privacyStep] = [];
    for (let i = 0; i < yaml.privacy_step.length; i++) {
      let ps = YAML2PrivacyStep(yaml.privacy_step[i], props);

      if (PNDataModel.errors.isError(ps)) {
        return ps; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyStep].push(ps);
      }
    }
  }

  return node;
};

// create a privacy step and any contained privacy actions from yaml
function YAML2PrivacyStep(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));

  let node = {};

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML privacy step format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyStepId(props.hostname, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.PrivacyStep];

  if (yaml.privacy_action) {
    node[PN_P.privacyAction] = [];
    for (let i = 0; i < yaml.privacy_action.length; i++) {
      let ps = YAML2PrivacyAction(yaml.privacy_action[i], props);

      if (PNDataModel.errors.isError(ps)) {
        return ps; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyAction].push(ps);
      }
    }
  }

  return node;
}

// create a privacy action from yaml
function YAML2PrivacyAction(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));

  let node = {};

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML privacy action format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyActionId(props.hostname, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.PrivacyAction];
  return node;
}

module.exports = {
  utils:        model.utils,
};
