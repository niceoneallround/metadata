/*jslint node: true */

/*


The Privacy Broker is responsible for creating and provisioning Privacy Pipes.

A party creates a privacy pipe by partially creating a Privacy Pipe metadata with
the relevant properties, see below, wrapping in a metadata JWT and then posting to
a Privacy Broker, typically via an API Gateway.

A Privacy Pipe can be used to either obfuscate or deobfuscate data as it is sent
to the destination.

DEOBFUSCATE PIPE Metadata JWT

The partially formed Deobfuscate privacy pipe contains the following information
- sub: https://pn.id.webshield.io/privacy_pipe/(hostname reversed)#<id>
- iss: the cname of the issuer
- iat: the creation time
- METADATA claim: contains the following JSON object
  - @id
  - @type PN_T.PrivacyPipe
  - pn_p.client
  - pn_p.destination
  - pn_p.version
  - pn_p.obfuscation_context - contains the set of PAI than need to be de-obfuscated
  - pn_p.access_context - TBD see document - the fields that want to be sent
- signature - signed by requestor

The created DE-OBFUSCATE PIPE has the following
- sub: https://pn.id.webshield.io/privacy_pipe/(hostname reversed)#<id>
- iss: the cname of the PB
- iat: the creation time
- METADATA claim: contains the following JSON object
  - pn_p.client
  - pn_p.destination
  - pn_p.version
  - pn_p.post_data_url: populated by the privacy broker and is URL client should post thier data
  - pn_p.obfuscation_context - contains the set of PAI than need to be de-obfuscated
  - pn_p.access_context - TBD see document - the fields that want to be sent
- signature - signed by the PB

The OBFUSCATION_CONTEXT for deobfuscate is as follows
- pn_p.action: deobfuscate - set by client
- pn_p.destination_provision_pipe_url: set by client
- pn_p.destination_provision_basic_auth_token: set by client
- pn_p.privacy_action_instance_2_deobfuscate: array of
  - @id: new id
    @type: pai
    pn_p.action: deobfuscate
    pn_p.privacy_action_instance_2_deobfuscate: paction-i-ob-1
    pn_p.privacy_pipe_2_deobfuscate: pipe-ob-1


OBFUSCATE PIPE
A Privacy Pipe is created by sending a Metadata JWT containing a partially formed Privay Pipe to the Privacy Broker.

This causes a Privacy Broker to instantiate a Privacy Pipe and returned the Privacy Pipe created response that contains the URL that the data should be Posted to.

The metadata JWT should contain
•	sub: https://pn.id.webshield.io/privacy_pipe/(hostname reversed)#<id>
•	iss: the cname of the issuer
•	iat: the creation time
•	pn_p.metadata: contains the following JSON object
  •	@type: [pn_t.PrivacyPipe]
  •	pn_p.client: <the sender>
  •	pn_p.destination: <the destination>
  •	pn_p.post_data_url: populated by the privacy broker and is URL client should post thier data
  •	pn_p.version: the version, either 1 or 2. If not supplied assumed to be 1.
  •	pn_p.obfuscation_context: An pn_t.ObfuscationContext node
  •	pn_p.access_context: <TBD the context used to determine the access decision>


A PN_T.Ob onfuscation context describes the context needed to instantiate a Privacy Algorithm -
it does not have an @id as not used outside of this
•	@type: pn_t.ObfuscationContext
•	pn_p.privacy_algorithm: The @id of the privacy algorithm to use
•	pn_p.action: pn_t.Obfuscate or pn_t.Deobfuscate
•	pn_p.privacy_algorithm_instance_template:[ PrivacyAlgorithmInstance]
   Used in conjunction with the privacy algorithm to create the privacy algorithm instance
 •	pn_p.destination_provision_pipe_url: [optional] used when the IS is creating a deobfuscation pipe and needs to tell t
    he PB where to provision. FIXME this will be replaced by the PB accessing the destination resource that would contain this
 •	pn_p.destination_povision_basic_auth_token:[optional] used when the IS is creating a deobfuscaiton pipe.
    It passes the credentials to access the reference source. FIXME this will be replaced by encrypted credentials
    inside the reference source resource.


*/

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
model.canons = {}; // constructors for canonical versions that can be used for test

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

  if ((props) && (props.post_data_url)) {
    node[PN_P.postDataUrl] = props.post_data_url;
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

  node[PN_P.version] = '1';
  if (yaml.version) {
    node[PN_P.version] = yaml.version;
  } else {
    if (yaml.obfuscation_context) {
      node[PN_P.version] = '2';
    } else {
      node[PN_P.version] = '1';
    }
  }

  //
  // create the obfuscation context
  //
  if (yaml.obfuscation_context) {
    let oc = {};
    oc['@type'] = [PN_T.ObfuscationContext];

    // handle properties common to obfuscate and deobfuscate

    if (yaml.obfuscation_context.action) {
      if (yaml.obfuscation_context.action.toLowerCase() === 'obfuscate') {
        oc[PN_P.action] = PN_T.Obfuscate;
      } else if (yaml.obfuscation_context.action.toLowerCase() === 'deobfuscate') {
        oc[PN_P.action] = PN_T.Deobfuscate;
      }
    }

    if (yaml.obfuscation_context.destination_provision_pipe_url) {
      if (yaml.obfuscation_context.destination_provision_pipe_url['@type']) {
        oc[PN_P.destinationProvisionPipeURL] = yaml.obfuscation_context.destination_provision_pipe_url;
      } else {
        oc[PN_P.destinationProvisionPipeURL] = PNDataModel.utils.createURLValue(yaml.obfuscation_context.destination_provision_pipe_url);
      }
    }

    if (yaml.obfuscation_context.destination_provision_basic_auth_token) {
      oc[PN_P.destinationProvisionBasicAuthToken] = yaml.obfuscation_context.destination_provision_basic_auth_token;
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
// NOTE THIS CANNOT VERIFY THE YAML NODE AS BEEN CREATED YET
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

  if (node[PN_P.version] === '2') {
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

    switch (oc[PN_P.action]) {

      case PN_T.Deobfuscate: {

        if (!oc[PN_P.privacyActionInstance2Deobfuscate]) {
          return PNDataModel.errors.createTypeError({
            id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
            errMsg: util.format('ERROR %s missing from obfuscation context:%j', PN_P.privacyActionInstance2Deobfuscate, node),
          });
        }

        break;
      }

      case PN_T.Obfuscate: {

        if (!oc[PN_P.privacyAlgorithmInstanceTemplate]) {
          return PNDataModel.errors.createTypeError({
            id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
            errMsg: util.format('ERROR %s missing from obfuscation context:%j', PN_P.privacyAlgorithmInstanceTemplate, node),
          });
        }

        break;
      }

      default: {
        assert(false, util.format('Unknown action should not get here as check above:%j', oc));
      }
    }
  }

  // all ok :)
  return null;
};

//-------------------------
// Canonical Privacy Pipe can be used for tests -
//--------------------------

model.canons.createPrivacyPipe = function createPrivacyPipe(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'canon-fake-pipe',
    type: 'privacyPipe',
    client: props.domainName,
    destination: 'http//idenity.syndicate',
    description: 'a canon fake privacy pipe',
    obfuscation_context: {
      action: 'obfuscate',
      privacy_algorithm_instance_template: [{
        id: 'canon-fake-palgi',
        privacy_algorithm: 'canon-fake-privacy-alg-id',
        privacy_step_instance: [{
          id: 'canon-fake-pstepi',
          privacy_step: 'canon-fake-privacy-step-id',
          client: props.domainName,
          next: 'http//idenity.syndicate',
          privacy_action_instance: [{
            id: 'canon-fake-pactioni',
            action: 'obfuscate',
            skip_orchestration: false,
            privacy_action: 'canon-fake-privacy-action-id',
            obfuscation_service: 'need to add os',
            encrypt_key_md_jwt: 'canon-fake-ekmd-jwt',
          },
          ],
        },
        ],
      },
      ],
    },
  };

  // create a JSONLD node
  let md = model.utils.YAML2Node(yaml,
              { hostname: props.hostname,
                domainName: props.domainName,
                issuer: 'fake.setin.canon', creationTime: '282828', });

  if (PNDataModel.errors.isError(md)) {
    assert(false, util.format('failed to create privacy pipe:%j', md));
  }

  return md;
};

module.exports = {
  canons: model.canons,
  utils:        model.utils,
};
