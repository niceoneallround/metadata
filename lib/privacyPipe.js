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

  //
  // Copy the obfuscation context
  //
  if (yaml.obfuscation_context) {
    let oc = {};
    oc['@type'] = [PN_T.ObfuscationContext];

    // just the id
    if (yaml.privacy_algorithm) {
      oc[PN_P.privacyAlgorithm] = yaml.privacyAlgorithm;
    }

    // if the YAML contains a privacy algorith instance, these are templates
    // and we just want t blindly copy them across as is. Later on we will
    // create the actual instances from these and the privacy algoriothm itself
    //
    // NOTE ASSUMES THAT THEY ARE IN EXPANDED FORMAT FOR NOW, LATER ADD ABILITY
    // TO PASS SIMPLIER TERMS. SO OK JUST TO COPY
    if (yaml.privacy_algorithm_instance) {
      oc[PN_P.PrivacyAlgorithmInstance] = yaml.privacy_algorithm_instance;
    }

    node[PN_P.ObfuscationContext] = oc;
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
  assert(props.hostname, 'props.hostname is missing');

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
  // DO NOT CHECK Ocontext yet, wait until converted
  //
  console.log('****** FIXME ENHANCE PRIVACY PIPE metadata verify to check obfuscation context when upgraded all to v2');

  // all ok :)
  return null;
};

module.exports = {
  utils:        model.utils,
};
