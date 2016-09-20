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
    description: // optional
    privacy_step:
      - id:
        node_type: <connector> *** need to add more ***
        order_number: defaults to 1
        description: // optional
        privacy_action:
        - id:
          action: <obfuscate>
          order_number: Defaults to 1 - if more than one then set
          node_type: <external> ** need to add more **
          description: // optional
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

  if (yaml.description) {
    node[PN_P.description] = yaml.desccription;
  }

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

  if (yaml.description) {
    node[PN_P.description] = yaml.desccription;
  }

  // set order number
  if (!yaml.order_number) {
    node[PN_P.orderNumber] = 1;
  } else {
    node[PN_P.orderNumber] = yaml.order_number;
  }

  // set node type - for now just external, but add others
  if (!yaml.node_type) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR node_type missing from YAML privacy step format:%j', yaml),
    });
  } else {
    if (yaml.node_type.toLowerCase() === 'connector') {
      node[PN_P.nodeType] = PN_T.Connector;
    } else {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR node_type is not connector in YAML privacy step format:%j', yaml),
      });
    }
  }

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

  if (yaml.description) {
    node[PN_P.description] = yaml.desccription;
  }

  // check has action and is of valid type
  if (!yaml.action) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR action missing from YAML privacy action format:%j', yaml),
    });
  } else {
    if (yaml.action.toLowerCase() === 'obfuscate') {
      node[PN_P.action] = PN_T.Obfuscate;
    } else {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR action is not obfuscate in YAML privacy action format:%j', yaml),
      });
    }
  }

  // set order number
  if (!yaml.order_number) {
    node[PN_P.orderNumber] = 1;
  } else {
    node[PN_P.orderNumber] = yaml.order_number;
  }

  // set node type - for now just external, but add others
  if (!yaml.node_type) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR node_type missing from YAML privacy action format:%j', yaml),
    });
  } else {
    if (yaml.node_type.toLowerCase() === 'external') {
      node[PN_P.nodeType] = PN_T.External;
    } else {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR node_type is not external in YAML privacy action format:%j', yaml),
      });
    }
  }

  return node;
}

module.exports = {
  utils:        model.utils,
};
