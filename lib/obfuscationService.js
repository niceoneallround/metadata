/*

The Obfuscation Service PN Resource represents either a private or shared OS is is created using a metadata JWT with the following properties
•	sub –  a globally unique Id of the form
  - https://md.pn.id.webshield.io/obfuscation_service/(hostname reversed)#<id>
  - http://md.pn.id.webshield.io/obfuscation_service/com/experian/poc_os
•	iss: the issuer cname
•	iat: the creation time
•	pn_p.metadata: – the metadata claim containing a JSON-LD node with
  o	@id: from sub
  o	@type: [PN_T.ObfuscationService, PN_T.Metadata, PN_T.Resource]
  o	pn_p.description
  o	pn_p.content_obfuscation_algorithm: same as in Privacy Action
  o	pn_p.obfuscation_provider: same as in Privacy Action
  o	pn_p.protocol: defines the protocol, used by privacy agent when calling
    - PN_T.EncryptObfuscationServiceProtocolV1: see below for definition
    - PN_T.EncryptObfuscationServiceProtocolV2: see below for definition
    - PN_T.Token etc will be worked out as implement
  o	pn_p.obfuscate_endpoint: URL or in the future swagger
  o	pn_p.deobfuscate_endpoint:

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

  if (yaml.type.toLowerCase() !== 'obfuscationservice') {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not ObfuscationService:%j', yaml),
    });
  }

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createObfuscationServiceId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.Resource, PN_T.ObfuscationService];

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

  if (yaml.content_obfuscation_algorithm) {
    node[PN_P.contentObfuscationAlgorithm] = yaml.content_obfuscation_algorithm;
  }

  if (yaml.obfuscation_provider) {
    node[PN_P.obfuscationProvider] = yaml.obfuscation_provider;
  }

  switch (yaml.message_protocol.toLowerCase()) {

    case 'encryptv1': {
      node[PN_P.messageProtocol] = PN_T.EncryptObfuscationServiceProtocolV1;
      break;
    }

    case 'encryptv2': {
      node[PN_P.messageProtocol] = PN_T.EncryptObfuscationServiceProtocolV2;
      break;
    }

    default: {
      node[PN_P.messageProtocol] = PN_T.EncryptObfuscationServiceProtocolV2;
    }
  }

  if (yaml.obfuscate_endpoint) {
    node[PN_P.obfuscateEndpoint] = { '@type': PN_T.URL, '@value': yaml.obfuscate_endpoint, };
  }

  if (yaml.deobfuscate_endpoint) {
    node[PN_P.deobfuscateEndpoint] = { '@type': PN_T.URL, '@value': yaml.deobfuscate_endpoint, };
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
        (jsonldUtils.isType(node, PN_T.ObfuscationService))
      )) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s, %s, %s] missing in:%j',
              PN_T.ObfuscationService, PN_T.Metadata, PN_T.Resource, node),
    });
  }

  if (!node[PN_P.contentObfuscationAlgorithm]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.contentObfuscationAlgorithm, node),
    });
  }

  if (!node[PN_P.obfuscationProvider]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.obfuscationProvider, node),
    });
  }

  if (!node[PN_P.messageProtocol]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.messageProtocol, node),
    });
  }

  if (!node[PN_P.obfuscateEndpoint]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.obfuscateEndpoint, node),
    });
  }

  if (!node[PN_P.deobfuscateEndpoint]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.deobfuscateEndpoint, node),
    });
  }

  // all ok :)
  return null;
};

//-------------------------
// Canonical Organization can be used for tests
//--------------------------

model.canons.createTestObfuscationService = function createTestObfuscationService(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'test-os-1',
    type: 'obfuscationservice',
    description: 'Test Obfuscation Service',
    message_protocol: 'encryptv2',
    content_obfuscation_algorithm: 'https://ietf.org/rfc7518/A256GCM',
    obfuscation_provider: 'https://test.webshield.io/os/local',
    obfuscate_endpoint: 'http://test.webshield.io/os/obfuscate',
    deobfuscate_endpoint: 'http://test.webshield.io/os/deobfuscate',
  };

  // create a JSONLD node
  let md = model.utils.YAML2Node(yaml,
              { hostname: props.hostname,
                domainName: props.domainName,
                issuer: 'fake.setin.canon', creationTime: '282828', });

  if (PNDataModel.errors.isError(md)) {
    assert(false, util.format('failed to create test Obfuscation Service:%j', md));
  }

  return md;
};

module.exports = {
  canons:       model.canons,
  utils:        model.utils,
};
