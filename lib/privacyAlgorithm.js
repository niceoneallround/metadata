/*jslint node: true, vars: true */

//
// Contains constructors and verifiers for privacy algorithms, privacy steps
// and privacy actions.
//
// Implements
// * verify() - verifies a privacy algorithm JSON-LD node
// * YAML2Node() - converts a YAML node to a JSON-LD node
//

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
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

The Privacy Algorithm YAML node has the following format, note the issuer and
creation time are passed in props

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

The above is passed in a as JSON node
   { id: , type: , description: , priavcy_step:, etc}

*/

//
// convert a YAML node into a Privacy Algorithm JSON-LD node. If a validation
// error returns an Error otherwise returns the PA node.
//
// *yaml - the JSON version of the yaml node
//
// optional props are
// props.issuer: add as issuer to the PA as is not part of YAML
// props.creationTime - add as creation time to the PA as not part of YAML
//
model.utils.YAML2Node = function YAML2Node(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));
  let node = {};

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyAlgorithmId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.Resource, PN_T.PrivacyAlgorithm];

  if (yaml.description) {
    node[PN_P.description] = yaml.description;
  }

  // add optional props
  if ((props) && (props.issuer)) {
    node[PN_P.issuer] = props.issuer;
  }

  if ((props) && (props.creationTime)) {
    node[PN_P.creationTime] = props.creationTime;
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

  // check all ok
  let error = model.utils.verify(node, props.domainName);
  if (error) {
    return error;
  } else {
    return node;
  }
};

// create a privacy step and any contained privacy actions from yaml
//
// optional props are
// props.issuer: add as issuer to the PA as is not part of YAML
// props.creationTime - add as creation time to the PA as not part of YAML
function YAML2PrivacyStep(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  let node = {};

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML privacy step format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyStepId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.PrivacyStep];

  if (yaml.description) {
    node[PN_P.description] = yaml.description;
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
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  let node = {};

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML privacy action format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyActionId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.PrivacyAction];

  if (yaml.description) {
    node[PN_P.description] = yaml.description;
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

//--------------------------------------
// verifier a privacy algorithm JSON-LD node and all its sub-nodes
//--------------------------------------

model.utils.verify = function verify(node, hostname) {
  'use strict';

  var psteps, invalid;
  assert(node, 'node param missing');

  if (!node['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', node),
    });
  }

  if (!((jsonldUtils.isType(node, PN_T.PrivacyAlgorithm)) &&
        (jsonldUtils.isType(node, PN_T.Metadata)) &&
        (jsonldUtils.isType(node, PN_T.Resource))
      )) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s, %s, %s] missing in:%j', PN_T.PrivacyAlgorithm, PN_T.Metadata, PN_T.Resource, node),
    });
  }

  // should have an issuer - note this is populated from the JWT
  if (!node[PN_P.issuer]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.issuer, node),
    });
  }

  // should have a creation time - note this is populated from the JWT
  if (!node[PN_P.creationTime]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.creationTime, node),
    });
  }

  if (!node[PN_P.privacyStep]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyStep, node),
    });
  } else {
    psteps = jsonldUtils.getArray(node, PN_P.privacyStep);
    if (psteps.length !== 1) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s has can only have 1 entry:%j', PN_P.privacyStep, node),
      });
    }

    invalid = null;
    invalid = verifyPrivacyStep(psteps[0], hostname, node);
    if (invalid) {
      return invalid;
    }
  }

  // all ok :)
  return null;
};

function verifyPrivacyStep(privacyStep, hostname, pa) {
  'use strict';
  var invalid, pactions;

  if (!privacyStep['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', privacyStep),
    });
  }

  if (!(jsonldUtils.isType(privacyStep, PN_T.PrivacyStep))) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j in pa:%j', PN_T.PrivacyStep, privacyStep, pa),
    });
  }

  if (!privacyStep[PN_P.orderNumber]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR privacy step is missing:%s in:%j in pa:%j', PN_P.orderNumber, privacyStep, pa),
    });
  }

  if (!privacyStep[PN_P.nodeType]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR privacy step is missing:%s in:%j in pa:%j', PN_P.nodeType, privacyStep, pa),
    });
  }

  // privacy actions are optional
  if (privacyStep[PN_P.privacyAction]) {
    pactions = jsonldUtils.getArray(privacyStep, PN_P.privacyAction);
    if (pactions.length > 1) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s has can only have o or 1 privacy action:%j', PN_P.privacyAction, pa),
      });
    }

    if (pactions.length !== 0) {
      invalid = null;
      invalid = verifyPrivacyAction(pactions[0], hostname, pa);
      if (invalid) {
        return invalid;
      }
    }
  }

  return null;
}

function verifyPrivacyAction(privacyAction, hostname, pa) {
  'use strict';
  var invalid, pSchema;

  if (!privacyAction['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', privacyAction),
    });
  }

  if (!(jsonldUtils.isType(privacyAction, PN_T.PrivacyAction))) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j in pa:%j', PN_T.PrivacyAction, privacyAction, pa),
    });
  }

  if (!privacyAction[PN_P.action]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j in pa:%j', PN_P.action, privacyAction, pa),
    });
  }

  if (!privacyAction[PN_P.orderNumber]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j in pa:%j', PN_P.orderNumber, privacyAction, pa),
    });
  }

  if (!privacyAction[PN_P.nodeType]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j in pa:%j', PN_P.nodeType, privacyAction, pa),
    });
  }

  if (jsonldUtils.npUtils.getV(privacyAction, PN_P.nodeType) === PN_T.Internal) {
    //
    // If internal then must have a privacy schema
    //
    if (!privacyAction[PN_P.privacySchema]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from:%j in pa:%j', PN_P.privacySchema, privacyAction, pa),
      });
    } else {
      pSchema = jsonldUtils.getArray(privacyAction, PN_P.privacySchema);
      if (pSchema.length !== 1) {
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR %s can only have 1 entry:%j in pa:%j', PN_P.privacySchema, privacyAction, pa),
        });
      }

      invalid = null;
      invalid = verifyPrivacySchema(pSchema[0], hostname, pa);
      if (invalid) {
        return invalid;
      }
    }
  } // internal

  return null;
}

function verifyPrivacySchema(privacySchema, hostname, pa) {
  'use strict';

  if (!privacySchema['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', privacySchema),
    });
  }

  if (!(jsonldUtils.isType(privacySchema, PN_T.SchemaItem))) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j in pa:%j', PN_T.PrivacySchema, privacySchema, pa),
    });
  }
}

module.exports = {
  utils:        model.utils,
};
