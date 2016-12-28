/*jslint node: true, vars: true */

/*

Describes an ingest privacy agent - it acts on a specific PN Data Model and is responsible for
first hop orchestrating of the obfuscation of data, and the publishing data to the Identity Syndicate
on behalf of the owning Organization

Has the following properties
•	@id: https://md.id.webshield.io/ingest_privacy_agent/<domain-reversed>#value
    Example : http://md.id.webshield.io/ingest_privacy_agent/com/aetna/enrollment_records”
•	@type: Resource, IngestPrivacyAgent
•	description
•	organization: the @id of the owning org
•	data_model: the @id of the data model it uses
•	pn_p.privacy_algorithm: the @id of the default privacy algorithm that should be used to obfuscate ingested data that
  is being sent to the identity syndicate. Note the algorithm is not associated with data model as a function of the connector,
  may use different ones depending on circumstances.
- pn_p.obfuscation_service: the @id of the default obfuscation service to be used with privacy algorithms. This is set at pipe
  creation time.
- pn_p.identity_syndication_algorithm: the @id of the default identity_syndication_algorithm, can be overrided on synd request

*/

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

var model = {};
model.utils = {};
model.canons = {}; // constructors for canonical versions that can be used for test

//
// convert a YAML node into a JSON-LD node. Does not check
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

  if (yaml.type.toLowerCase() !== 'ingestprivacyagent') {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not IngestPrivacyAgent:%j', yaml),
    });
  }

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createIngestPrivacyAgentId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.Resource, PN_T.IngestPrivacyAgent];

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

  if (yaml.pndatamodel) {
    node[PN_P.pnDataModel] = yaml.pndatamodel;
  }

  if (yaml.privacy_algorithm) {
    node[PN_P.privacyAlgorithm] = yaml.privacy_algorithm;
  }

  if (yaml.obfuscation_service) {
    node[PN_P.obfuscationService] = yaml.obfuscation_service;
  }

  if (yaml.identity_syndication_algorithm) {
    node[PN_P.identitySyndicationAlgorithm] = yaml.identity_syndication_algorithm;
  }

  return node;

};

//--------------------------------------
// verifier JSON-LD node and all its sub-nodes
//--------------------------------------

model.utils.verify = function verify(node, props) {
  'use strict';

  assert(node, 'node param missing');
  assert(props.hostname, util.format('props.hostname is missing:%j', props));

  let hostname = props.hostname;

  if (!node['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', node),
    });
  }

  if (!((jsonldUtils.isType(node, PN_T.Resource)) &&
        (jsonldUtils.isType(node, PN_T.Metadata)) &&
        (jsonldUtils.isType(node, PN_T.IngestPrivacyAgent))
      )) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s, %s, %s] missing in:%j',
              PN_T.IngestPrivacyAgent, PN_T.Metadata, PN_T.Resource, node),
    });
  }

  if (!node[PN_P.pnDataModel]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.pnDataModel, node),
    });
  }

  if (!node[PN_P.privacyAlgorithm]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyAlgorithm, node),
    });
  }

  if (!node[PN_P.obfuscationService]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.obfuscationService, node),
    });
  }

  // identitySyndicationAlgorithm is not required but for now make it required so can flush out issues
  if (!node[PN_P.identitySyndicationAlgorithm]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.identitySyndicationAlgorithm, node),
    });
  }

  // all ok :)
  return null;
};

//-------------------------
// Canonical Organization can be used for tests
//--------------------------

model.canons.createTestIngestPrivacyAgent = function createTestIngestPrivacyAgent(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'test-ingest-agent-1',
    type: 'ingestprivacyagent',
    description: 'Test Ingest Privacy Agent',
    pndatamodel: 'https://md.pn.id.webshield.io/pndatamodel/io/webshield/test/dc#enrollment-records', // used in testing so may aswell use
    privacy_algorithm: 'https://md.pn.id.webshield.io/privacy_algorithm/io/webshield/test/dc#dc-test-insecure-key-palg', // used in testing
    obfuscation_service: 'https://md.pn.id.webshield.io/obfuscation_service/io/webshield/test/dc/local#os-test-private-1', // used in testing
    identity_syndication_algorithm:
        'https://md.pn.id.webshield.io/identity_syndication_algorithm/io/webshield/test/dc/local#isa-1', // used in testing
  };

  // create a JSONLD node
  let md = model.utils.YAML2Node(yaml,
              { hostname: props.hostname,
                domainName: props.domainName,
                issuer: 'fake.setin.canon', creationTime: '282828', });

  if (PNDataModel.errors.isError(md)) {
    assert(false, util.format('failed to create test PNDataModel:%j', md));
  }

  return md;
};

module.exports = {
  canons:       model.canons,
  utils:        model.utils,
};
