/*jslint node: true, vars: true */

/*

Encrypt Key Metadata is used to track the information needed to identify the key that was used to encrypt the data.
So that it is available for decryption. To support any kind of information, the actual raw data is wrapped in a JWT
that is stored within the Encrypt Key Metadata.

The PN Encrypt Key Metadata is PN Metadata conforming to the PN Metadata JWT and JSONLD patterns.  An example in JSON-LD format is

{ @id: id http://md.pn.id.webshield.io/encrypt_key/com/acme#23,
   @type: [ pn_t.EncryptKeyMetadata, pn_t.Metadata],
   pn_p.description:
   pn_p.raw_encrypt_key_metadata: base64 encoded
 }

 When submitted as a JWT using the metadata claim

   sub: the globally unique URL of the format used as @id
   iss: the domain name of issuer
   iat: when issued
   pn_p.metadata:
     - @type: [PN_T.EncryptKeyMetadata, PN_T.Metadata]
     - pn_p.description: Some text about the service
     - pn_p.raw_encrypt_key_metadata_type: JSONWebKey - https://tools.ietf.org/html/rfc7517
     - pn_p.raw_encrypt_key_metadata: base64 encoding


When submitted as yaml
  id: idValue
  type: EncryptKeyMetadata - case insenstive
  description:
  raw_encrypt_key_metadata: can be a base64 string of a json object, the latter is converted to a string and then base64

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
// convert a YAML node into JSON-LD node. Does not check
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

  if (yaml.type.toLowerCase() !== 'encryptkeymetadata') {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not encryptkeymetadata:%j', yaml),
    });
  }

  // check has id
  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createEncryptKeyMetadataId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.Metadata, PN_T.EncryptKeyMetadata];

  // check type, if not specified default to JSONWebKey
  if (!yaml.raw_encrypt_key_metadata_type) {
    node[PN_P.rawEncryptKeyMetadataType] = 'jsonwebkey';
  } else {
    node[PN_P.rawEncryptKeyMetadataType] = yaml.raw_encrypt_key_metadata_type.toLowerCase();
  }

  // check has raw data
  if (!yaml.raw_encrypt_key_metadata) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR raw_encrypt_key_metadata missing from YAML format:%j', yaml),
    });
  } else {
    if ((typeof yaml.raw_encrypt_key_metadata === 'string') || (yaml.raw_encrypt_key_metadata instanceof String)) {
      node[PN_P.rawEncryptKeyMetadata] = yaml.raw_encrypt_key_metadata;
    } else {
      // assume a json object so convert to a base64
      let s = JSON.stringify(yaml.raw_encrypt_key_metadata);
      let b64 = Buffer.from(s).toString('base64');
      node[PN_P.rawEncryptKeyMetadata]  = b64;
    }
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
// verifier
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

  if (!((jsonldUtils.isType(node, PN_T.EncryptKeyMetadata)) &&
        (jsonldUtils.isType(node, PN_T.Metadata))
      )) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s, %s] missing in:%j', PN_T.EncryptKeyMetadata, PN_T.Metadata, node),
    });
  }

  if (!node[PN_P.rawEncryptKeyMetadataType]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.rawEncryptKeyMetadataType, node),
    });
  }

  if (!node[PN_P.rawEncryptKeyMetadata]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.rawEncryptKeyMetadata, node),
    });
  }

  // all ok :)
  return null;
};

//-------------------------
// Canonical Encrypt Key  can be used for tests
//--------------------------

model.canons.createTestKey = function createTestKey(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'ekm-1',
    type: 'encryptkeymetadata',
    description: 'raw data is an object in JSON Web Key Format holding a base64 clear text key. If an object code will auto convert to bas64',
    raw_encrypt_key_metadata_type: 'jsonwebkey',
    raw_encrypt_key_metadata: {
      kty: 'oct',
      alg: 'AES_256',
      k: '2kW2pzVjo1n+hpDuNnZTRy4CjXqAkgMQ1MtpWZFd4FI=',
    },
  };

  // create a JSONLD node
  let md = model.utils.YAML2Node(yaml,
              { hostname: props.hostname,
                domainName: props.domainName,
                issuer: 'fake.setin.canon', creationTime: '282828', });

  if (PNDataModel.errors.isError(md)) {
    assert(false, util.format('failed to create canon Encrypt Key Metadata:%j', md));
  }

  return md;
};

model.canons.createPoC2Key = function createPoC2Key(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'ekm-1',
    type: 'encryptkeymetadata',
    description: 'raw data is an object in JSON Web Key Format holding a base64 clear text key. If an object code will auto convert to bas64',
    raw_encrypt_key_metadata_type: 'json',
    raw_encrypt_key_metadata: {
      inbound_job_id: 'in-1',
      outbound_job_id: 'out-1',
      process_id: '222-222',
    },
  };

  // create a JSONLD node
  let md = model.utils.YAML2Node(yaml,
              { hostname: props.hostname,
                domainName: props.domainName,
                issuer: 'fake.setin.canon', creationTime: '282828', });

  if (PNDataModel.errors.isError(md)) {
    assert(false, util.format('failed to create canon Encrypt Key Metadata:%j', md));
  }

  return md;
};

module.exports = {
  canons:       model.canons,
  utils:        model.utils,
};
