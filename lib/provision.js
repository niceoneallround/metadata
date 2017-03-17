/*jslint node: true, vars: true */

/*
 A provision contains an array of metadata that needs to be installed and executed by
 the reciever. Today this is just privacy algorithm instance information.

*/

const assert = require('assert');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const PSICanons = require('./privacyStepInstance').canons;
const util = require('util');

let model = {};
model.utils = {};

let canons = {};

//
// convert a YAML node into provision SON-LD node. Does not check
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

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createProvisionId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Provision];

  // Does not convert any metadata requires it to be passed in as JSONLD-node
  if (yaml.provisioned_metadata) {
    node[PN_P.provisionedMetadata] = yaml.provisioned_metadata;
  }

  // as convenience if not an array convert it
  if (!Array.isArray(node[PN_P.provisionedMetadata])) {
    node[PN_P.provisionedMetadata] = [node[PN_P.provisionedMetadata]];
  }

  if (yaml.privacy_pipe) {
    node[PN_P.privacyPipe] = yaml.privacy_pipe;
  }

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

  return node;

};

//--------------------------------------
// verifier - Does not verify the metadata
//--------------------------------------

model.utils.verify = function verify(node, hostname) {
  'use strict';

  assert(node, 'node param missing');
  assert(hostname, 'hostname param missing');

  if (!node['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', node),
    });
  }

  if (!JSONLDUtils.isType(node, PN_T.Provision)) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.Provision, node),
    });
  }

  if (!node[PN_P.provisionedMetadata]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.provisionedMetadatar, node),
    });
  }

  if (!Array.isArray(node[PN_P.provisionedMetadata])) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s must be an Array:%j', PN_P.provisionedMetadata, node),
    });
  }

  if (!node[PN_P.privacyPipe]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyPipe, node),
    });
  }

  // all ok :)
  return null;
};

//-------------------
// CANON DATA
//------------------

/*
  Create a canon V2 provision with de-obfuscate privacy step instance for the canon subjects in the syndicate query
*/
canons.createDebofuscateIngestPASubjectsProvision = function createDebofuscateIngestPASubjectsProvision(props) {
  'use strict';
  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));
  assert(props.privacyPipeId, util.format('props.privacyPipeId is missing:%j', props));

  let pstepI = PSICanons.createDeobfuscatePrivacyStepI(props);

  let provision = model.utils.YAML2Node(
    {
      id: 'canon-prov-1',
      type: 'provision',
      provisioned_metadata: [pstepI],
      privacy_pipe: props.privacyPipeId,
    },
    props);

  return provision;
};

/*
  Create a canon V2 provision with de-obfuscate privacy step instance for the canon subjects in the reference source query result canons
*/
canons.createDebofuscateReferenceSourceSubjectsProvision = function createDebofuscateReferenceSourceSubjectsProvision(props) {
  'use strict';
  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));
  assert(props.privacyPipeId, util.format('props.privacyPipeId is missing:%j', props));

  let pstepI = PSICanons.createDeobfuscateReferenceSourceSubjectsPrivacyStepI(props);

  let provision = model.utils.YAML2Node(
    {
      id: 'canon-prov-1',
      type: 'provision',
      provisioned_metadata: [pstepI],
      privacy_pipe: props.privacyPipeId,
    },
    props);

  return provision;
};

module.exports = {
  canons:   canons,
  utils:    model.utils,
};
