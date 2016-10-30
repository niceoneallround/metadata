/*jslint node: true, vars: true */

//
// Contains constructors and verifiers for a Privacy Pipe - very basic for now!
//
// Implements
// * verify() - verifies a PP JSON-LD node
// * YAML2Node() - converts a YAML node to a JSON-LD node
//

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const pAlgInstanceUtils = require('./privacyAlgorithmInstance').utils;
const privacyActionInstanceUtils = require('./privacyActionInstance').utils;
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

var model = {};
model.utils = {};

/*
A Privacy Pipe is created by sending a Metadata JWT to the PN. This causes a Privacy Broker to instantiate a Privacy Pipe and returned the Privacy Pipe created response that contains the URL that the data should be Posted to.

The metadata JWT should contain
•	sub: https://pn.id.webshield.io/privacy_pipe/(hostname reversed)#<id>
•	iss: the cname of the issuer
•	iat: the creation time
•	pn_p.metadata: contains the following JSON object
•	@id: https://pn.id.webshield.io/privacy_pipe/(hostname reversed)#<id>
•	@type: [pn_t.PrivacyPipe]
•	pn_p.client: <the sender>
•	pn_p.destination: <the destination>
•	pn_p.obfuscation_context: An pn_t.ObfuscationContext node
•	pn_p.access_context: <TBD the context used to determine the access decision>


A PN_T.Ob onfuscation context describes the context needed to instantiate a Privacy Algorithm -
it does not have an @id as not used outside of this
•	@type: pn_t.ObfuscationContext
•	pn_p.privacy_algorithm: The @id of the privacy algorithm to use
•	pn_p.action: pn_t.Obfuscate or pn_t.Deobfuscate
•	pn_p.privacy_algorithm_instance_template:[ PrivacyAlgorithmInstance]
   Used in conjunction with the privacy algorithm to create the privacy algorithm instance

*/

//
// convert a YAML node into a Privacy Pipe JSON-LD node. Does not check
// for anything other tha id as ok to have fields missing as can be added from
// other sources, for example issuer, and creation time.
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

  if (!yaml.type) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type missing from YAML format cannot create:%j', yaml),
    });
  }

  if (yaml.type.toLowerCase() !== 'privacypipe') {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not PrivacyPipe:%j', yaml),
    });
  }

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyPipeId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.PrivacyPipe];

  node[PN_P.version] = '2';

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

  // client is a CNAME by default
  if (yaml.client) {
    if (yaml.client['@type']) {
      node[PN_P.client] = yaml.client;
    } else {
      node[PN_P.client] = PNDataModel.utils.createCNameValue(yaml.client);
    }
  }

  // destination is a URL by default
  if (yaml.destination) {
    if (yaml.destination['@type']) {
      node[PN_P.destination] = yaml.destination;
    } else {
      node[PN_P.destination] = PNDataModel.utils.createURLValue(yaml.destination);
    }
  }

  //
  // Copy the obfuscation context
  //
  if (yaml.obfuscation_context) {
    let oc = {};
    oc['@type'] = [PN_T.ObfuscationContext];

    if (yaml.obfuscation_context.action) {
      if (yaml.obfuscation_context.action.toLowerCase() === 'obfuscate') {
        oc[PN_P.action] = PN_T.Obfuscate;
      } else if (yaml.obfuscation_context.action.toLowerCase() === 'deobfuscate') {
        oc[PN_P.action] = PN_T.Deobfuscate;
      }
    }

    // if the YAML contains a privacy algorithm instance templates, copy across
    if (yaml.obfuscation_context.privacy_algorithm_instance_template) {
      let templates = yaml.obfuscation_context.privacy_algorithm_instance_template;
      oc[PN_P.privacyAlgorithmInstanceTemplate] = [];

      // for each privacy algorithm instance convert to a json-ld node
      for (let i = 0; i < templates.length; i++) {
        let palgI = pAlgInstanceUtils.YAML2Node(templates[i], props);

        if (PNDataModel.errors.isError(palgI)) {
          return palgI; // ERROR SO STOP AND RETURN;
        } else {
          oc[PN_P.privacyAlgorithmInstanceTemplate].push(palgI);
        }
      }
    }

    // if contains privacy actions instances to de-obfuscate then copy that across
    if (yaml.obfuscation_context.privacy_action_instance_2_deobfuscate) {
      let templates = yaml.obfuscation_context.privacy_action_instance_2_deobfuscate;
      oc[PN_P.privacyActionInstance2Deobfuscate] = [];

      for (let i = 0; i < templates.length; i++) {
        let pait = privacyActionInstanceUtils.YAML2Node(templates[i], props);

        if (PNDataModel.errors.isError(pait)) {
          return pait; // ERROR SO STOP AND RETURN;
        } else {
          oc[PN_P.privacyActionInstance2Deobfuscate].push(pait);
        }
      }
    }

    node[PN_P.obfuscationContext] = oc;
  }

  return node;
};

//--------------------------------------
// verifier a Privacy Pipe JSON-LD node and all its sub-nodes
//--------------------------------------

model.utils.verify = function verify(node, props) {
  'use strict';
  assert(node, 'node param missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname is missing:%j', props));

  let hostname = props.hostname;

  if (!node['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', node),
    });
  }

  if (!((jsonldUtils.isType(node, PN_T.PrivacyPipe)) &&
        (jsonldUtils.isType(node, PN_T.Metadata))
      )) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s, %s, %s] missing in:%j',
              PN_T.PrivacyPipe, PN_T.Metadata, node),
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

  //
  // Must have an obfuscation context
  //
  if (!node[PN_P.obfuscationContext]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.obfuscationContext, node),
    });
  }

  let oc = node[PN_P.obfuscationContext];

  if (!oc[PN_P.action]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from obfuscation context:%j', PN_P.action, node),
    });
  }

  if ((oc[PN_P.action] !== PN_T.Obfuscate) && (oc[PN_P.action] !== PN_T.Deobfuscate)) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s is not obfuscate or deobfuscate :%j', PN_P.action, node),
    });
  }

  // all ok :)
  return null;
};

module.exports = {
  utils:        model.utils,
};
