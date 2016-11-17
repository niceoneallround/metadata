/*jslint node: true, vars: true */

/*

A KMS resource identifies a Key Managment Service that is being used by a Privacy Algorithm.

This is submitted as metadata claim JWT with the following properties:
  sub: the globally unique URL of the format used as @id
     - http://md.pn.id.webshield.io/kms/<domain name reversed>/<frags>
  iss: the domain name of issuer
  iat: when issued
  pn_p.metadata:
    - @type: [PN_T.KMS, PN_T.Metadata, PN_T.Resource]
    - pn_p.description: Some text about the service
    - pn_p.provider: the globally unique URI of the provider. This is used to interpret the PN Standard and Custom properties in the metadata. Provider examples are
       - http://ionic-security.com - lonic is being used – the opaque ionic key id is embedded in the encrypt key metadata.
       - http//kms.aws.amazon.com – AWS KMS is being used – the opaque AWS KMS key id is embedded in the encrypt key metadata
       - http://aetna.com/acceptto/kms - A KMS provided that is specific to Aetna and Acceptto is being used – An opaque acceptto token is embedded in the encrypt key metadata
       - http://kms.test.webshield.io/insecure/32bit - A KMS that is provided by webshield for testing and embeds a clear text 32-bit encryption key in the encrypt key metadata, so highly insecure. The key is provisioned locally within the connector.
    - pn_p.algorithm: holds an array of the types of cryptographic algorithms that the KMS can produce keys for. See https://www.rfc-editor.org/rfc/rfc7518.txt. To support JSON-LD this have been converted to URLS of the form
        - https://ietf.org/rfc7518/A256GCM - AES GSM using 256-bit key
        - etc
    - pn_p.custom_props: A json object holding PN Standard and custom properties: that are dependent on the key provider, but must be JSON-LD compliant. For example
      - @type: pn_t.CustomProperties
      - pn_p.provision_new_key_url: the url to call to provision a new key – this might hold the acceptto auth and get key
      - pn_p.dereference_key_url: the url to call to deference

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
model.CONSTANTS = {};

/*
  Setup the WebShield KMS Provider constants - all others are defined by edges
*/
model.CONSTANTS.provider = {
  //
  // The connector will generate a key of the size needed by the algorithm and
  // store it in clear text within the encrypt key metadata
  //
  WEBSHIELD_TEST: 'https://kms.webshield.io/test',
};

/*
  Setup the algorithm constants use for KMS as per https://www.rfc-editor.org/rfc/rfc7518.txt describes the cryptographic
  algorithm intended for use with the key.

  To support JSON-LD this have been converted to URLS of the form
  https://ietf.org/rfc7518/A256GCM - AES GSM using 256-bit key

*/
model.CONSTANTS.algorithm = {
  A256GCM: 'https://ietf.org/rfc7518/A256GCM',
};

//
// convert a YAML node into KMS JSON-LD node. Does not check
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

  if (yaml.type.toLowerCase() !== 'kms') {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not KMS:%j', yaml),
    });
  }

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createKMSId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.Resource, PN_T.KMS];

  // check has provider
  if (!yaml.provider) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR provider missing from YAML format:%j', yaml),
    });
  } else {
    node[PN_P.provider] = yaml.provider;
  }

  // check has an algorithm
  if (!yaml.algorithm) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR algorithm missing from YAML format:%j', yaml),
    });
  } else {
    node[PN_P.algorithm] = yaml.algorithm;
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

  // if custom properties copy across
  if (yaml.custom_props) {
    node[PN_P.customProps] = yaml.custom_props;
  }

  return node;

};

//--------------------------------------
// verifier - Does not verify the metadata
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

  if (!((jsonldUtils.isType(node, PN_T.KMS)) &&
        (jsonldUtils.isType(node, PN_T.Metadata)) &&
        (jsonldUtils.isType(node, PN_T.Resource))
      )) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s, %s, %s] missing in:%j', PN_T.KMS, PN_T.Metadata, PN_T.Resource, node),
    });
  }

  if (!node[PN_P.provider]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.provider, node),
    });
  }

  // check a valid provider
  switch (node[PN_P.provider]) {
    case model.CONSTANTS.provider.WEBSHIELD_TEST: {
      break;
    }

    default: {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR unknown provider:%j', node),
      });
    }
  }

  if (!node[PN_P.algorithm]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.algorithm, node),
    });
  }

  // all ok :)
  return null;
};

//-------------------------
// Canonical KMS  can be used for tests
//--------------------------

model.canons.createTestKMS = function createTestKMS(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'kms-1',
    type: 'kms',
    description: 'A valid KMS that is linked into the canon PA - provides test KMS with insecure key',
    provider: model.CONSTANTS.provider.WEBSHIELD_TEST,
    algorithm: [model.CONSTANTS.algorithm.A256GCM],
  };

  // create a JSONLD node
  let md = model.utils.YAML2Node(yaml,
              { hostname: props.hostname,
                domainName: props.domainName,
                issuer: 'fake.setin.canon', creationTime: '282828', });

  if (PNDataModel.errors.isError(md)) {
    assert(false, util.format('failed to create test KMS:%j', md));
  }

  return md;
};

module.exports = {
  canons:       model.canons,
  CONSTANTS:    model.CONSTANTS,
  utils:        model.utils,
};
