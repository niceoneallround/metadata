/*jslint node: true, vars: true */

//
// Contains constructors and verifiers for Privacy Step
//
// Implements
// * verify() - verifies a JSON-LD node
// * YAML2Node() - converts a YAML node to a JSON-LD node
//

/*

A Privacy Step is meta-metadata that describes the obfuscation or de-obfuscation
execution that should occur within one process such as a PN Connector or Privacy Node.

It is used to instantiate Privacy Step Instances at Privacy Pipe creation time.
Its state is constant across all Privacy Step Instances created from it

It is created as part of the Privacy Algorithm meta-metadata JWT, it has the following properties
•	@id: a globally unique url
  	https://md.pn.id.webshield.io/privacy_step/(hostname reversed)#<id>
•	@type: [pn_t.PrivacyStep]
•	pn_p.client: The cname of the client, if set then is fixed for all uses. Example, {@type:[pn_t:X509CN] @value: <cname of the client >}
•	pn_p.next: the URL of the destination, if set then fixed for all uses. Example {@type:pn_t.URL @value: <URL where to post the processed graph>
•	pn_p.node_type: The fixed node type the step should execute in
   - pn_t.Connector: runs inside a connector
   - pn_p.PrivacyNode: runs inside a privacy node
•	pn_p.privacy_action: [< Privacy Actions>]. Currently limited to 1.


The Privacy Setp YAML node has the following format

  - id: // the #value - builds the rest
    type: PrivacyStep
    description:
    client
    next:
    node_type:
    privacy_action: []


The above is passed in a as JSON node
   { id: , type: , description:, etc}

*/

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PActionUtils = require('./privacyAction').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

var model = {};
model.utils = {};

//
// convert a YAML node into a Privacy Step JSON-LD node.
//
// *yaml - the JSON version of the yaml node
// *props - var props
//
model.utils.YAML2Node = function YAML2Node(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));
  assert(props.pa, util.format('props.pa missing - required to verify:%j', props));

  let node = {};

  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML privacy step format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyStepId(props.domainName, yaml.id);
  }

  if (yaml.description) {
    node[PN_P.description] = yaml.description;
  }

  if (yaml.client) {
    node[PN_P.client] = yaml.client;
  }

  if (yaml.next) {
    node[PN_P.next] = yaml.next;
  }

  if (yaml.node_type) {
    if (yaml.node_type.toLowerCase() === 'connector') {
      node[PN_P.nodeType] = PN_T.Connector;
    } else {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR node_type is not connector in YAML privacy step format:%j', yaml),
      });
    }
  }

  // create the privacy actions
  if (yaml.privacy_action) {
    node[PN_P.privacyAction] = [];

    props.privacyStep = node['@id'];
    for (let i = 0; i < yaml.privacy_action.length; i++) {
      let ps = PActionUtils.YAML2Node(yaml.privacy_action[i], props);

      if (PNDataModel.errors.isError(ps)) {
        return ps; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyAction].push(ps);
      }
    }
  }

  if (yaml.type) {
    if (yaml.type.toLowerCase() !== 'privacystep') {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR type is not PrivacyStep:%j', yaml),
      });
    }
  }

  node['@type'] = [PN_T.Metadata, PN_T.PrivacyStep];

  // verify the node is valid
  let error = model.utils.verify(node, props);
  if (error) {
    return error;
  } else {
    return node;
  }
};

model.utils.verify = function verify(privacyStep, props) {
  'use strict';

  assert(privacyStep, 'node param missing');
  assert(props, 'props param is missing');
  assert(props.pa, 'props.pa is missing');
  assert(props.hostname, 'props.hostname is missing');

  let pa = props.pa;
  let hostname = props.hostname;

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

  if (!privacyStep[PN_P.nodeType]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR privacy step is missing:%s in:%j in pa:%j', PN_P.nodeType, privacyStep, pa),
    });
  } else {
    if (privacyStep[PN_P.nodeType] !== PN_T.Connector) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR node_type is not connector privacy step:%j pa:%j', privacyStep, pa),
      });
    }
  }

  if (privacyStep[PN_P.privacyAction]) {
    let pactions = jsonldUtils.getArray(privacyStep, PN_P.privacyAction);
    if (pactions.length > 1) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s has can only have 0 or 1 privacy action:%j', PN_P.privacyAction, pa),
      });
    }

    if (pactions.length !== 0) {
      let invalid = null;
      invalid = PActionUtils.verify(pactions[0], props);
      if (invalid) {
        return invalid;
      }
    }
  }

  return null;
};

module.exports = {
  utils:        model.utils,
};
